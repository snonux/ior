package parquet

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/parkwait"
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
//
// The wait is proven, not assumed from a quiet time window (task oz2):
// waiterRegisteredHook fires only once the producer has met the full queue and
// registered as a waiter, i.e. committed to waitForRoom. With the writer still
// gated nothing can free room or stop the session, so from that point on
// Record cannot return until w is opened. A recorder that shed the row instead
// returns ErrRecorderStartedDropping without ever reaching the hook, which the
// select below reports at once rather than after a timeout.
func TestRecorderBlockWhenFullWaitsInsteadOfShedding(t *testing.T) {
	registered := make(chan struct{}, 1)
	waiterRegisteredHook = func() { registered <- struct{}{} }
	t.Cleanup(func() { waiterRegisteredHook = nil })
	w := newGateWriter(nil)
	r := newGatedRecorder(t, w, true)
	// Unwedge the producer and the session if a check below fails first.
	t.Cleanup(func() { w.open(); _ = r.Stop() })

	done := recordAsync(r, 3)
	select {
	case <-registered:
	case err := <-done:
		t.Fatalf("Record on a full queue returned %v, want it to wait for room", err)
	case <-time.After(stuckTimeout):
		t.Fatal("Record on a full queue neither returned nor registered as a waiter")
	}
	assertProducerStillWaiting(t, r, done)

	w.open() // the session's write completes and frees queue room
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Record after room freed error = %v, want nil", err)
		}
	case <-time.After(stuckTimeout):
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

// assertProducerStillWaiting checks, right after the producer behind done
// registered as a waiter, that it has not returned and that no row was shed.
// Both are deterministic: the writer is still gated, so the producer cannot
// have been released yet.
func assertProducerStillWaiting(t *testing.T, r *Recorder, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("a registered waiter returned %v before the writer freed room", err)
	default:
	}
	if dropped := r.Status().RowsDropped; dropped != 0 {
		t.Fatalf("RowsDropped = %d while a producer waits, want 0", dropped)
	}
}

// TestRecorderShedModeStillDoesNotBlock is the negative twin: without
// BlockWhenFull (the TUI) the same full queue sheds at once and never stalls.
// The producer must also never register as a waiter, so the shed path is not
// a backpressure wait that merely happened to end quickly.
func TestRecorderShedModeStillDoesNotBlock(t *testing.T) {
	var waiters atomic.Int32
	waiterRegisteredHook = func() { waiters.Add(1) }
	t.Cleanup(func() { waiterRegisteredHook = nil })
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
	if n := waiters.Load(); n != 0 {
		t.Fatalf("shed-mode Record registered %d waiter(s), want it to shed without waiting", n)
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
// a queue that nobody drains any more. Without awaitSenders every trial fails
// (Stop returns before the session parks in the barrier); the trials repeat
// so the producer's later choice between room and stop varies.
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
	stopped := stopPastRegisteredWaiter(t, trial, r, w)
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

// stopPastRegisteredWaiter starts Stop while a producer is parked in
// waiterRegisteredHook, frees queue room once Stop has closed stopC, and then
// proves the senders barrier holds: the session goroutine parks in
// awaitSenders instead of Stop returning. It returns Stop's pending result.
// Both waits observe state instead of sleeping, so a slow host cannot weaken
// the trial: without the barrier it fails on the first trial.
func stopPastRegisteredWaiter(t *testing.T, trial int, r *Recorder, w *gateWriter) <-chan error {
	t.Helper()
	stopped, stopDone := stopAsync(r)
	// The session goroutine is still stuck in the stalled write, so the
	// session stays active until Stop has closed stopC.
	if !awaitCondition(func() bool { return stopRequested(r) }) {
		t.Fatalf("trial %d: Stop never closed stopC", trial)
	}
	w.open() // the writer drains: room appears
	// With the barrier the session goroutine now parks in awaitSenders until
	// the registered producer is done; a barrier-less Stop instead drains,
	// closes the file and returns, which closes stopDone and fails here.
	parkwait.Await{
		Frame:   "(*recordingSession).awaitSenders",
		Reasons: []string{parkwait.RWMutexLock, parkwait.Semacquire},
		// Every earlier trial's session finished (or the test failed), so no
		// goroutine of this test is parked there yet.
		Baseline: 0,
		Done:     stopDone,
		DoneMsg:  fmt.Sprintf("trial %d: Stop finished while a registered producer was still pending (no senders barrier)", trial),
	}.Run(t)
	return stopped
}

// stopAsync runs Stop in the background. stopped delivers its result; done
// closes right after, so a select or parkwait.Await can notice that Stop
// returned without consuming the result.
func stopAsync(r *Recorder) (stopped <-chan error, done <-chan struct{}) {
	result, finished := make(chan error, 1), make(chan struct{})
	go func() {
		result <- r.Stop()
		close(finished)
	}()
	return result, finished
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

// stuckTimeout is how long the death-race tests wait for a producer or Stop
// before calling it stuck, and awaitCondition's default deadline.
const stuckTimeout = 5 * time.Second

// windowPublishTimeout bounds the deathInStopWindow hook's wait for the writer
// failure. It must stay well below stuckTimeout: in a broken recorder that
// publishes the failure only after Stop's own stop(nil), the producers stay
// blocked for as long as the hook waits, and with equal deadlines the
// producers' "stuck" timer raced the hook and usually reported the less
// specific failure. Two seconds is still generous for the happy path, where
// the failure is published within microseconds of the gate opening.
const windowPublishTimeout = 2 * time.Second

// awaitCondition polls cond for up to stuckTimeout and reports whether it held.
func awaitCondition(cond func() bool) bool {
	return awaitConditionWithin(stuckTimeout, cond)
}

// awaitConditionWithin polls cond for up to timeout and reports whether it held.
func awaitConditionWithin(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Microsecond)
	}
	return true
}

// stopWithWriterFailure ends the recording through Stop while the stalled
// write fails in the given order. It returns Stop's result and forced, which
// reports whether the order really happened; read it only after Stop's result
// arrived. The first two orders are checked here on the test goroutine, so
// forced is always true for them. deathInStopWindow waits inside the hook on
// Stop's goroutine, where t.Fatal must not be called: a failure that is never
// published there would let Stop go on and silently test a different order,
// so the hook records the outcome and the caller fails on it instead. The
// hook gives up after windowPublishTimeout, before the caller's stuckTimeout
// timers fire, so Stop and the producers move on in time for the caller to
// report the unforced order rather than a stuck producer.
func stopWithWriterFailure(t *testing.T, r *Recorder, w *gateWriter, order raceOrder) (stopped <-chan error, forced func() bool) {
	t.Helper()
	result := make(chan error, 1)
	stop := func() { result <- r.Stop() }
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
		var published atomic.Bool
		// Runs on Stop's goroutine, after it released r.mu: Status is safe.
		stopUnlockedHook = func() {
			w.open()
			published.Store(awaitConditionWithin(windowPublishTimeout, func() bool { return sessionDead(r) }))
		}
		go stop()
		return result, published.Load
	}
	return result, func() bool { return true }
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

	stopped, forced := stopWithWriterFailure(t, r, w, order)
	for p := 0; p < producers; p++ {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, writeErr) && !errors.Is(err, ErrRecorderNotActive) {
				t.Fatalf("trial %d (%v): Record error = %v, want nil, %v or %v", trial, order, err, writeErr, ErrRecorderNotActive)
			}
		case <-time.After(stuckTimeout):
			t.Fatalf("trial %d (%v): a producer is stuck after the writer died and Stop ran", trial, order)
		}
	}
	// Receiving Stop's result means the hook (which runs inside Stop) has
	// finished, so forced can be read. It is checked before Stop's error: if
	// the order was not forced, whatever Stop returned belongs to another
	// order, and the unforced order is the failure worth reporting.
	stopErr := awaitStop(t, trial, order, stopped)
	if !forced() {
		t.Fatalf("trial %d (%v): the writer failure was not published inside Stop's window, so this order was never tested", trial, order)
	}
	assertFailureReportedOnce(t, trial, order, r, stopErr, writeErr)
	stopUnlockedHook = nil // do not leak this trial's hook into the next one
}

// awaitStop returns Stop's result, failing the test if Stop does not return
// within stuckTimeout.
func awaitStop(t *testing.T, trial int, order raceOrder, stopped <-chan error) error {
	t.Helper()
	select {
	case err := <-stopped:
		return err
	case <-time.After(stuckTimeout):
		t.Fatalf("trial %d (%v): Stop hung after the writer died", trial, order)
		return nil
	}
}

// assertFailureReportedOnce checks that Stop returned the writer failure and
// that neither TakeFailure nor a second Stop reports it again.
func assertFailureReportedOnce(t *testing.T, trial int, order raceOrder, r *Recorder, stopErr, writeErr error) {
	t.Helper()
	if !errors.Is(stopErr, writeErr) {
		t.Fatalf("trial %d (%v): Stop() error = %v, want the writer failure %v", trial, order, stopErr, writeErr)
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
