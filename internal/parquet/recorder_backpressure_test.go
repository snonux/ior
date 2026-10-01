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
	// openOnce makes open idempotent, so a failing test's cleanup can release
	// a writer that the test body may already have released.
	openOnce sync.Once
	written  atomic.Uint64
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

// open releases every blocked and future WriteRows call; safe to call twice.
func (w *gateWriter) open() { w.openOnce.Do(func() { close(w.release) }) }

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
	registered := make(chan struct{}, 1)
	waiterRegisteredHook = func() { registered <- struct{}{} }
	t.Cleanup(func() { waiterRegisteredHook = nil })
	w := newGateWriter(writeErr)
	r := newGatedRecorder(t, w, true)

	done := recordAsync(r, 3)
	<-registered     // the producer is registered as a waiter on the full queue
	close(w.release) // the write now fails and kills the session

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

// fillStalledQueue stalls the writer on row 1 (batch size 1, so the session
// goroutine holds it inside WriteRows) and then offers exactly capacity more
// rows, every one of which must be accepted into the queue. The next Record
// call meets a full queue.
func fillStalledQueue(t *testing.T, r *Recorder, w *gateWriter, capacity int) {
	t.Helper()
	mustStart(t, r)
	if err := r.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record(1) error = %v", err)
	}
	<-w.started
	for i := 0; i < capacity; i++ {
		if err := r.Record(testStreamRow(uint64(2+i), "read", false), 0); err != nil {
			t.Fatalf("Record of queued row %d/%d error = %v, want it accepted", i+1, capacity, err)
		}
	}
}

func gatedRecorderConfig(w *gateWriter, cfg RecorderConfig) RecorderConfig {
	cfg.BatchSize = 1
	cfg.FlushInterval = time.Hour
	cfg.newWriter = func(string, WriterConfig, FileMetadata) (rowWriter, error) { return w, nil }
	return cfg
}

// TestDefaultRecorderQueueHoldsItsCapacityThenSheds pins the shed-mode (TUI)
// queue size behaviourally: with the writer stalled, a default-config recorder
// accepts exactly defaultRecorderQueueCapacity rows, sheds the next one at once
// (counted, never blocking), and writes everything it accepted.
func TestDefaultRecorderQueueHoldsItsCapacityThenSheds(t *testing.T) {
	w := newGateWriter(nil)
	r := NewRecorder(gatedRecorderConfig(w, RecorderConfig{}))
	fillStalledQueue(t, r, w, defaultRecorderQueueCapacity)

	select {
	case err := <-recordAsync(r, 1<<20):
		if !errors.Is(err, ErrRecorderStartedDropping) {
			t.Fatalf("Record beyond the default queue error = %v, want %v", err, ErrRecorderStartedDropping)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a default (shed-mode) recorder blocked on a full queue")
	}
	if dropped := r.Status().RowsDropped; dropped != 1 {
		t.Fatalf("RowsDropped = %d, want 1", dropped)
	}
	close(w.release)
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if want := uint64(1 + defaultRecorderQueueCapacity); w.written.Load() != want {
		t.Fatalf("writer got %d rows, want %d", w.written.Load(), want)
	}
}

// TestHeadlessRecorderQueueHoldsItsCapacityThenBlocks is the headless twin: a
// backpressured recorder of HeadlessQueueCapacity slots accepts exactly that
// many rows with the writer stalled, then makes the next Record wait (it sheds
// nothing) until the writer frees room; every row ends up written.
func TestHeadlessRecorderQueueHoldsItsCapacityThenBlocks(t *testing.T) {
	registered := make(chan struct{}, 1)
	waiterRegisteredHook = func() { registered <- struct{}{} }
	t.Cleanup(func() { waiterRegisteredHook = nil })

	w := newGateWriter(nil)
	r := NewRecorder(gatedRecorderConfig(w, RecorderConfig{
		QueueCapacity: HeadlessQueueCapacity,
		BlockWhenFull: true,
	}))
	fillStalledQueue(t, r, w, HeadlessQueueCapacity)

	done := recordAsync(r, 1<<20)
	<-registered // the producer met the full queue and waits for room
	select {
	case err := <-done:
		t.Fatalf("Record beyond the headless queue returned %v, want it to wait", err)
	default:
	}
	if dropped := r.Status().RowsDropped; dropped != 0 {
		t.Fatalf("RowsDropped = %d, want 0 in backpressure mode", dropped)
	}
	close(w.release)
	if err := <-done; err != nil {
		t.Fatalf("Record after room freed error = %v, want nil", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if want := uint64(2 + HeadlessQueueCapacity); w.written.Load() != want {
		t.Fatalf("writer got %d rows, want %d", w.written.Load(), want)
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
	t.Cleanup(func() { waiterRegisteredHook = nil })
	for trial := 0; trial < 40; trial++ {
		runWaiterBarrierTrial(t, trial)
	}
}

// runWaiterBarrierTrial is one trial of the test above. Its cleanup runs even
// after a Fatalf: it lets the parked producer proceed, opens the writer and
// stops the recorder, so a failure cannot leak a goroutine that races the
// next test through the shared waiterRegisteredHook.
func runWaiterBarrierTrial(t *testing.T, trial int) {
	registered, proceed := make(chan struct{}), make(chan struct{})
	var proceedOnce sync.Once
	letProceed := func() { proceedOnce.Do(func() { close(proceed) }) }
	waiterRegisteredHook = func() {
		close(registered)
		<-proceed
	}
	w := newGateWriter(nil)
	r := newGatedRecorder(t, w, true)
	t.Cleanup(func() {
		waiterRegisteredHook = nil
		letProceed()
		w.open()
		_ = r.Stop()
	})

	result := recordAsync(r, 3)
	<-registered
	stopped := make(chan error, 1)
	go func() { stopped <- r.Stop() }()
	time.Sleep(2 * time.Millisecond) // Stop has closed stopC by now
	w.open()                         // the writer drains: room appears
	time.Sleep(5 * time.Millisecond) // a barrier-less Stop would finish here
	waiterRegisteredHook = nil
	letProceed()

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

// raceOrder names one way the writer's death and Stop can interleave. The test
// below forces each of them with explicit waits; letting the scheduler pick
// (goroutine start order) exercised the Stop-first orders in only a few
// percent of the trials.
type raceOrder int

const (
	// deathBeforeStop: the session is dead and published before Stop is
	// called, so Stop meets no active session.
	deathBeforeStop raceOrder = iota
	// stopBeforeDeath: Stop has closed stopC and waits for the session, which
	// is still stuck in the stalled write, when that write fails.
	stopBeforeDeath
	// deathInStopWindow: the writer dies and the session finishes after Stop
	// has marked its request and released r.mu but before it stops the session
	// (stopUnlockedHook), so Stop must still report the failure, once.
	deathInStopWindow
)

func (o raceOrder) String() string {
	return [...]string{"death-before-stop", "stop-before-death", "death-in-stop-window"}[o]
}

// stopRequested reports whether the active session's stopC is closed, i.e.
// Stop (or a dead writer) has asked it to end.
func stopRequested(r *Recorder) bool {
	r.mu.RLock()
	session := r.active
	r.mu.RUnlock()
	if session == nil {
		return false
	}
	select {
	case <-session.stopC:
		return true
	default:
		return false
	}
}

// sessionDead reports whether the session has published its failure.
func sessionDead(r *Recorder) bool {
	st := r.Status()
	return !st.Active && st.LastError != nil
}

// awaitCondition polls cond for up to five seconds and reports whether it held.
func awaitCondition(cond func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Microsecond)
	}
	return true
}

// stopWithWriterFailure ends the recording through Stop while the stalled
// write fails in the given order, and returns Stop's result.
func stopWithWriterFailure(t *testing.T, r *Recorder, w *gateWriter, order raceOrder) <-chan error {
	t.Helper()
	stopped := make(chan error, 1)
	stop := func() { stopped <- r.Stop() }
	switch order {
	case deathBeforeStop:
		w.open()
		if !awaitCondition(func() bool { return sessionDead(r) }) {
			t.Fatalf("%v: the writer failure was never published", order)
		}
		go stop()
	case stopBeforeDeath:
		go stop()
		if !awaitCondition(func() bool { return stopRequested(r) }) {
			t.Fatalf("%v: Stop never closed stopC", order)
		}
		w.open()
	case deathInStopWindow:
		// Runs on Stop's goroutine, after it released r.mu: Status is safe.
		stopUnlockedHook = func() {
			w.open()
			awaitCondition(func() bool { return sessionDead(r) })
		}
		go stop()
	}
	return stopped
}

// TestRecorderWriterDeathRacingStopWithBlockedProducers kills the writer and
// calls Stop while several producers wait for room, in each of the orders of
// raceOrder, every one forced deterministically. Nothing may deadlock or close
// a channel twice (both paths close stopC and finish the session); every
// producer is released with nil or a rejection; and the failure is reported
// exactly once, by Stop, never again by TakeFailure or a second Stop. The
// producers are registered as waiters before the race starts
// (waiterRegisteredHook), so no sleep decides whether they are blocked.
func TestRecorderWriterDeathRacingStopWithBlockedProducers(t *testing.T) {
	const producers = 4
	registered := make(chan struct{}, producers)
	waiterRegisteredHook = func() { registered <- struct{}{} }
	t.Cleanup(func() { waiterRegisteredHook = nil; stopUnlockedHook = nil })

	for trial := 0; trial < 30; trial++ {
		order := raceOrder(trial % 3)
		runDeathRaceTrial(t, trial, order, producers, registered)
	}
}

func runDeathRaceTrial(t *testing.T, trial int, order raceOrder, producers int, registered <-chan struct{}) {
	writeErr := errors.New("disk full")
	w := newGateWriter(writeErr)
	r := newGatedRecorder(t, w, true)
	// A failing trial must not leave producers or the session goroutine behind.
	t.Cleanup(func() { w.open(); stopUnlockedHook = nil; _ = r.Stop() })

	results := make(chan error, producers)
	for p := 0; p < producers; p++ {
		go func(p int) { results <- r.Record(testStreamRow(uint64(10+p), "read", false), 0) }(p)
	}
	for p := 0; p < producers; p++ {
		<-registered
	}

	stopped := stopWithWriterFailure(t, r, w, order)
	for p := 0; p < producers; p++ {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, writeErr) && !errors.Is(err, ErrRecorderNotActive) {
				t.Fatalf("trial %d (%v): Record error = %v, want nil, %v or %v", trial, order, err, writeErr, ErrRecorderNotActive)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("trial %d (%v): a producer is stuck after the writer died and Stop ran", trial, order)
		}
	}
	assertFailureReportedOnce(t, trial, order, r, stopped, writeErr)
	stopUnlockedHook = nil // do not leak this trial's hook into the next one
}

// assertFailureReportedOnce checks that Stop returned the writer failure and
// that neither TakeFailure nor a second Stop reports it again.
func assertFailureReportedOnce(t *testing.T, trial int, order raceOrder, r *Recorder, stopped <-chan error, writeErr error) {
	t.Helper()
	select {
	case err := <-stopped:
		if !errors.Is(err, writeErr) {
			t.Fatalf("trial %d (%v): Stop() error = %v, want the writer failure %v", trial, order, err, writeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("trial %d (%v): Stop hung after the writer died", trial, order)
	}
	if err := r.TakeFailure(); err != nil {
		t.Fatalf("trial %d (%v): TakeFailure() = %v after Stop reported it, want nil", trial, order, err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("trial %d (%v): second Stop() = %v, want nil", trial, order, err)
	}
	if st := r.Status(); st.Active || !errors.Is(st.LastError, writeErr) {
		t.Fatalf("trial %d (%v): status = %+v, want an inactive recording that failed with %v", trial, order, st, writeErr)
	}
}
