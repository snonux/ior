package parquet

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gateWriter blocks every WriteRows until release is closed, then counts the
// rows (and fails with err when set). Unlike blockingWriter it can make the
// writer die, which is how a blocked producer's wake-up on failure is tested.
type gateWriter struct {
	started chan struct{}
	release chan struct{}
	err     error

	startOnce sync.Once
	written   atomic.Uint64
}

func newGateWriter(err error) *gateWriter {
	return &gateWriter{started: make(chan struct{}), release: make(chan struct{}), err: err}
}

func (w *gateWriter) WriteRows(rows []Record) error {
	w.startOnce.Do(func() { close(w.started) })
	<-w.release
	if w.err != nil {
		return w.err
	}
	w.written.Add(uint64(len(rows)))
	return nil
}
func (w *gateWriter) Close() error      { return nil }
func (w *gateWriter) Abort() error      { return nil }
func (w *gateWriter) FinalPath() string { return "ignored.parquet" }
func (w *gateWriter) TempPath() string  { return "ignored.parquet.tmp" }

// newGatedRecorder starts a recording on w with a one-slot queue and batch
// size 1, then fills the pipeline: row 1 is taken by the session goroutine,
// which blocks in WriteRows, and row 2 occupies the single queue slot. The
// next Record call therefore meets a full queue.
func newGatedRecorder(t *testing.T, w *gateWriter, block bool) *Recorder {
	t.Helper()
	r := NewRecorder(RecorderConfig{
		QueueCapacity: 1,
		BatchSize:     1,
		FlushInterval: time.Hour,
		BlockWhenFull: block,
		newWriter:     func(string, WriterConfig, FileMetadata) (rowWriter, error) { return w, nil },
	})
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record(1) error = %v", err)
	}
	<-w.started
	if err := r.Record(testStreamRow(2, "read", false), 0); err != nil {
		t.Fatalf("Record(2) error = %v", err)
	}
	return r
}

// recordAsync runs one Record call in the background and returns its result.
func recordAsync(r *Recorder, seq uint64) <-chan error {
	done := make(chan error, 1)
	go func() { done <- r.Record(testStreamRow(seq, "read", false), 0) }()
	return done
}

// TestRecorderBlockWhenFullWaitsInsteadOfShedding is the core of task 4s2: on
// a full queue a backpressured recorder holds the producer until the writer
// makes room, and then every row - including the one that waited - is written.
func TestRecorderBlockWhenFullWaitsInsteadOfShedding(t *testing.T) {
	w := newGateWriter(nil)
	r := newGatedRecorder(t, w, true)

	done := recordAsync(r, 3)
	select {
	case err := <-done:
		t.Fatalf("Record on a full queue returned %v, want it to wait for room", err)
	case <-time.After(150 * time.Millisecond):
	}
	if dropped := r.Status().RowsDropped; dropped != 0 {
		t.Fatalf("RowsDropped = %d while a producer waits, want 0", dropped)
	}

	close(w.release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Record after room freed error = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting Record did not resume after the writer freed room")
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	status := r.Status()
	if status.RowsWritten != 3 || w.written.Load() != 3 || status.RowsDropped != 0 {
		t.Fatalf("written %d (writer %d), dropped %d; want 3 written, 0 dropped",
			status.RowsWritten, w.written.Load(), status.RowsDropped)
	}
}

// TestRecorderShedModeStillDoesNotBlock is the negative twin: without
// BlockWhenFull (the TUI) the same full queue sheds at once and never stalls.
func TestRecorderShedModeStillDoesNotBlock(t *testing.T) {
	w := newGateWriter(nil)
	r := newGatedRecorder(t, w, false)

	select {
	case err := <-recordAsync(r, 3):
		if !errors.Is(err, ErrRecorderStartedDropping) {
			t.Fatalf("Record on a full queue error = %v, want %v", err, ErrRecorderStartedDropping)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shed-mode Record blocked on a full queue")
	}
	close(w.release)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if status := r.Status(); status.RowsDropped != 1 || status.RowsWritten != 2 {
		t.Fatalf("dropped %d, written %d; want 1 dropped, 2 written", status.RowsDropped, status.RowsWritten)
	}
}

// TestRecorderBlockedProducerWakesWhenWriterDies pins that a dead writer can
// never wedge a backpressured caller: the waiting Record returns the writer's
// error instead of blocking forever on a queue nobody drains any more.
func TestRecorderBlockedProducerWakesWhenWriterDies(t *testing.T) {
	writeErr := errors.New("disk full")
	w := newGateWriter(writeErr)
	r := newGatedRecorder(t, w, true)

	done := recordAsync(r, 3)
	time.Sleep(50 * time.Millisecond) // let it reach the wait
	close(w.release)                  // the write now fails and kills the session

	select {
	case err := <-done:
		// The row may also have slipped into the queue before the failure; it
		// is then lost with the aborted recording, which Stop/Status report.
		if err != nil && !errors.Is(err, writeErr) {
			t.Fatalf("Record error = %v, want nil or %v", err, writeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a producer stayed blocked after the writer died")
	}
	waitSessionDead(t, r)
	if err := r.Record(testStreamRow(4, "read", false), 0); !errors.Is(err, writeErr) {
		t.Fatalf("Record on the dead recording error = %v, want %v", err, writeErr)
	}
}

// TestRecorderStopWithBlockedProducerLosesNoAcceptedRow exercises the race the
// senders barrier exists for: Stop while producers wait for room. Every Record
// that returned nil must be in the file, every other one must have been
// rejected, and Stop must neither hang nor abort the recording.
func TestRecorderStopWithBlockedProducerLosesNoAcceptedRow(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		w := newGateWriter(nil)
		r := newGatedRecorder(t, w, true)

		const producers = 4
		results := make(chan error, producers)
		for p := 0; p < producers; p++ {
			go func(p int) { results <- r.Record(testStreamRow(uint64(10+p), "read", false), 0) }(p)
		}
		time.Sleep(time.Duration(trial%5) * time.Millisecond)

		stopped := make(chan error, 1)
		go func() { stopped <- r.Stop() }()
		time.Sleep(time.Millisecond)
		close(w.release)

		accepted := uint64(2) // the two rows of newGatedRecorder
		for p := 0; p < producers; p++ {
			select {
			case err := <-results:
				switch {
				case err == nil:
					accepted++
				case errors.Is(err, ErrRecorderNotActive):
				default:
					t.Fatalf("trial %d: Record error = %v, want nil or %v", trial, err, ErrRecorderNotActive)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("trial %d: a producer is stuck after Stop", trial)
			}
		}
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatalf("trial %d: Stop() error = %v", trial, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("trial %d: Stop hung with blocked producers", trial)
		}
		if got := w.written.Load(); got != accepted {
			t.Fatalf("trial %d: writer got %d rows, %d were accepted", trial, got, accepted)
		}
	}
}

// TestRecorderBackpressureIsLosslessThroughRealWriter records far more rows
// than the tiny queue holds through the real parquet writer from several
// producers and reads the file back: nothing is dropped and every row is
// there exactly once.
func TestRecorderBackpressureIsLosslessThroughRealWriter(t *testing.T) {
	r := NewRecorder(RecorderConfig{
		QueueCapacity: 8,
		BatchSize:     64,
		FlushInterval: time.Hour,
		BlockWhenFull: true,
		Writer:        WriterConfig{MaxRowsPerRowGroup: 512},
	})
	path := filepath.Join(t.TempDir(), "bp.parquet")
	if err := r.Start(path, StartOptions{Metadata: FileMetadata{Mode: "headless"}}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	const producers, perProducer = 4, 5000
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				seq := uint64(p*perProducer + i + 1)
				if err := r.Record(testStreamRow(seq, "read", false), 0); err != nil {
					t.Errorf("Record(%d) error = %v", seq, err)
					return
				}
			}
		}(p)
	}
	wg.Wait()
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	status := r.Status()
	if status.RowsDropped != 0 || status.RowsWritten != producers*perProducer {
		t.Fatalf("written %d, dropped %d; want %d, 0", status.RowsWritten, status.RowsDropped, producers*perProducer)
	}
	seen := make(map[uint64]bool, producers*perProducer)
	for _, rec := range readAllRecords(t, status.Path) {
		if seen[rec.Seq] {
			t.Fatalf("row %d is in the file twice", rec.Seq)
		}
		seen[rec.Seq] = true
	}
	if len(seen) != producers*perProducer {
		t.Fatalf("file holds %d distinct rows, want %d", len(seen), producers*perProducer)
	}
}

// TestDefaultQueueCapacities pins the memory bounds: the zero config keeps a
// modest shed-mode queue and the headless size stays a fixed, bounded figure
// (slots are ~224 bytes each and allocated up front).
func TestDefaultQueueCapacities(t *testing.T) {
	if got := normalizeRecorderConfig(RecorderConfig{}).QueueCapacity; got != defaultRecorderQueueCapacity {
		t.Fatalf("default QueueCapacity = %d, want %d", got, defaultRecorderQueueCapacity)
	}
	if defaultRecorderQueueCapacity <= 4096 {
		t.Fatalf("default queue %d does not cover a row-group flush at high rates", defaultRecorderQueueCapacity)
	}
	if HeadlessQueueCapacity < defaultRecorderQueueCapacity || HeadlessQueueCapacity > 1<<18 {
		t.Fatalf("HeadlessQueueCapacity = %d, want between the default and 262144 (~56 MiB)", HeadlessQueueCapacity)
	}
}

// TestRecorderStopWaitsForRegisteredWaiter pins the senders barrier
// deterministically. A producer has registered as a waiter but has not yet
// started waiting when Stop runs and the writer frees the queue; the producer
// then sees both "room" and "stopped" and may enqueue. Stop must not finish
// until that producer is done, so a row Record accepted is never stranded in
// a queue that nobody drains any more. Without awaitSenders about half of the
// trials lose the accepted row.
func TestRecorderStopWaitsForRegisteredWaiter(t *testing.T) {
	for trial := 0; trial < 40; trial++ {
		registered, proceed := make(chan struct{}), make(chan struct{})
		waiterRegisteredHook = func() {
			close(registered)
			<-proceed
		}
		w := newGateWriter(nil)
		r := newGatedRecorder(t, w, true)

		result := recordAsync(r, 3)
		<-registered
		stopped := make(chan error, 1)
		go func() { stopped <- r.Stop() }()
		time.Sleep(2 * time.Millisecond) // Stop has closed stopC by now
		close(w.release)                 // the writer drains: room appears
		time.Sleep(5 * time.Millisecond) // a barrier-less Stop would finish here
		waiterRegisteredHook = nil
		close(proceed)

		accepted := uint64(2)
		if err := <-result; err == nil {
			accepted++
		} else if !errors.Is(err, ErrRecorderNotActive) {
			t.Fatalf("trial %d: Record error = %v, want nil or %v", trial, err, ErrRecorderNotActive)
		}
		if err := <-stopped; err != nil {
			t.Fatalf("trial %d: Stop() error = %v", trial, err)
		}
		if got := w.written.Load(); got != accepted {
			t.Fatalf("trial %d: writer got %d rows but %d were accepted: an accepted row was lost", trial, got, accepted)
		}
	}
}
