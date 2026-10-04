package tui

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/parkwait"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/streamrow"
)

// emitRows is the call sequence of the trace core's print callback: one
// EmitRow per event row.
func emitRows(e runtime.RowEmitter, seqs ...uint64) {
	for _, seq := range seqs {
		e.EmitRow(streamrow.Row{Seq: seq, Syscall: "read"})
	}
}

// streamSyscalls lists the syscall names of the stream's rows in order, so a
// test can see where warning rows sit between event rows.
func streamSyscalls(r *runtimeBindings) []string {
	var names []string
	for _, row := range r.streamBuffer.Snapshot() {
		names = append(names, row.Syscall)
	}
	return names
}

// TestSessionEmitRowDeliversToStreamAndRecorderWhileCurrent is the positive
// case: the row lands in the stream and in the recorder, stamped with the
// filter epoch current at emit time.
func TestSessionEmitRowDeliversToStreamAndRecorderWhileCurrent(t *testing.T) {
	r := newRuntimeBindings()
	recorder := &countingRecorder{RecordingController: parquet.NewRecorder(parquet.RecorderConfig{})}
	r.recorder = recorder
	r.advanceFilterEpoch()
	r.advanceFilterEpoch()
	emitter := r.beginSession().RowEmitter()

	emitRows(emitter, 7)

	rows := r.streamBuffer.Snapshot()
	if len(rows) != 1 || rows[0].Seq != 7 {
		t.Fatalf("stream rows = %+v, want the one emitted row (Seq 7)", rows)
	}
	if recorder.rows != 1 || recorder.epochs[0] != 2 {
		t.Fatalf("recorder got %d rows at epochs %v, want 1 row at epoch 2", recorder.rows, recorder.epochs)
	}
}

// TestSessionEmitRowDropsRetiredSessionOutput is the negative case that the
// single gate must keep: after the lifecycle stops a session or a newer one
// begins, the old session's rows reach neither the stream nor the recorder,
// and it neither claims nor reports a recorder failure.
func TestSessionEmitRowDropsRetiredSessionOutput(t *testing.T) {
	retire := map[string]func(*runtimeBindings, traceSessionBindings){
		"stopped":    func(_ *runtimeBindings, view traceSessionBindings) { view.end() },
		"superseded": func(r *runtimeBindings, _ traceSessionBindings) { r.beginSession() },
	}
	for name, retireSession := range retire {
		t.Run(name, func(t *testing.T) {
			r, recorder := newFailedRecorderBindings(errors.New("disk full"))
			counter := &countingRecorder{RecordingController: recorder}
			r.recorder = counter
			view := r.beginSession()
			emitter := view.RowEmitter()
			retireSession(r, view)

			emitRows(emitter, 1, 2)

			if got := streamSyscalls(r); len(got) != 0 {
				t.Fatalf("retired session pushed %q to the stream, want nothing", got)
			}
			if counter.rows != 0 {
				t.Fatalf("retired session recorded %d rows, want 0", counter.rows)
			}
			if recorder.takes != 0 {
				t.Fatalf("retired session claimed the failure (%d takes)", recorder.takes)
			}
		})
	}
}

// TestSessionEmitRowWarnsOnceInRowOrder checks the warning path of the single
// gate: a failure is reported exactly once, and its warning row sits right
// after the event row whose record claimed it (push, record, warn).
func TestSessionEmitRowWarnsOnceInRowOrder(t *testing.T) {
	r, recorder := newFailedRecorderBindings(errors.New("disk full"))
	emitter := r.beginSession().RowEmitter()

	emitRows(emitter, 1, 2, 3)

	want := []string{"read", "warning", "read", "read"}
	if got := streamSyscalls(r); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("stream = %q, want %q", got, want)
	}
	if got := warningRows(r); len(got) != 1 || !strings.Contains(got[0], "disk full") {
		t.Fatalf("warnings = %q, want one naming the failure", got)
	}
	// The fake clears its failure when it is claimed, so only the first Record
	// reports one and the claim is made exactly once.
	if recorder.takes != 1 {
		t.Fatalf("TakeFailure calls = %d, want 1", recorder.takes)
	}
}

// TestSessionEmitRowIdleRecorderIsSilent: with no recording running every
// Record returns ErrRecorderNotActive, which is not news.
func TestSessionEmitRowIdleRecorderIsSilent(t *testing.T) {
	r := newRuntimeBindings()
	emitRows(r.beginSession().RowEmitter(), 1, 2)
	if got := streamSyscalls(r); strings.Join(got, ",") != "read,read" {
		t.Fatalf("stream = %q, want the two event rows and no warning", got)
	}
}

// TestSessionEmitRowToleratesMissingOutputs: a bindings set without a stream
// buffer still records, one without a recorder still streams, and neither
// panics (the old Push and Record paths had the same nil guards).
func TestSessionEmitRowToleratesMissingOutputs(t *testing.T) {
	r := newRuntimeBindings()
	counter := &countingRecorder{RecordingController: parquet.NewRecorder(parquet.RecorderConfig{})}
	r.recorder = counter
	r.streamBuffer = nil
	emitRows(r.beginSession().RowEmitter(), 1)
	if counter.rows != 1 {
		t.Fatalf("recorded %d rows without a stream buffer, want 1", counter.rows)
	}

	r = newRuntimeBindings()
	r.recorder = nil
	emitRows(r.beginSession().RowEmitter(), 1)
	if got := streamSyscalls(r); len(got) != 1 {
		t.Fatalf("stream = %q without a recorder, want the one event row", got)
	}
}

// TestSessionEmitRowKeepsWarningUndeliveredWithoutASink mirrors the
// RecordWarning rule for the single gate: with no warning sink the failure
// must stay unclaimed for the record modal and the quit path.
func TestSessionEmitRowKeepsWarningUndeliveredWithoutASink(t *testing.T) {
	r, recorder := newFailedRecorderBindings(errors.New("disk full"))
	r.streamSeq = nil
	emitRows(r.beginSession().RowEmitter(), 1)
	if recorder.takes != 0 {
		t.Fatalf("failure claimed %d times with no sequencer to number the warning", recorder.takes)
	}
}

// blockingRecorder parks every Record until released, so a test can hold an
// emit in flight inside the session gate.
type blockingRecorder struct {
	runtime.RecordingController
	entered chan struct{}
	release chan struct{}
}

func (b *blockingRecorder) Record(streamrow.Row, uint64) error {
	b.entered <- struct{}{}
	<-b.release
	return parquet.ErrRecorderNotActive
}

// TestEndSessionWaitsForAnInFlightEmit pins the stale-session barrier of task
// 5o2 for the single gate: a stop that lands while a row is between its push
// and its record must wait, so the caller that resets the stream afterwards
// can be sure no row of the retired session is still in flight. Rows emitted
// after the stop are dropped.
func TestEndSessionWaitsForAnInFlightEmit(t *testing.T) {
	r := newRuntimeBindings()
	blocker := &blockingRecorder{
		RecordingController: parquet.NewRecorder(parquet.RecorderConfig{}),
		entered:             make(chan struct{}, 8), release: make(chan struct{}),
	}
	r.recorder = blocker
	view := r.beginSession()
	emitter := view.RowEmitter()

	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		emitRows(emitter, 1)
	}()
	<-blocker.entered // the row is pushed and is now inside Record

	ended := make(chan struct{})
	go func() {
		view.end()
		close(ended)
	}()
	select {
	case <-ended:
		t.Fatal("endSession returned while a row was still being emitted")
	case <-time.After(50 * time.Millisecond):
	}
	close(blocker.release)
	<-emitted
	<-ended

	if got := streamSyscalls(r); len(got) != 1 {
		t.Fatalf("stream = %q, want the in-flight row to have landed before the barrier released", got)
	}
	emitRows(emitter, 2)
	if n := r.streamBuffer.Len(); n != 1 {
		t.Fatalf("stream holds %d rows after the stop, want the late row dropped (1)", n)
	}
}

// TestSessionEmitRowStampsTheEpochReadInsideTheGate pins where EmitRow reads
// the filter epoch: inside the gate, after the lock is acquired, so the stamp
// is as fresh as the delivery itself. The emit is parked on the gate (the
// test holds the write lock), the epoch advances while it waits, and the
// recorded row must carry the advanced epoch. An implementation that read the
// epoch before taking the read lock would stamp the older value. (The older
// stamp would not be wrong, merely staler; this test guards the freshness.)
//
// The epoch advances only once the emitting goroutine is proven parked in
// RLock inside EmitRow (parkwait reads the runtime's goroutine dump). A fixed
// sleep there let a starved host advance the epoch before the goroutine even
// ran, so an early-reading mutant read the advanced value too and passed.
// Parked in RLock means any read before the gate has already happened.
func TestSessionEmitRowStampsTheEpochReadInsideTheGate(t *testing.T) {
	r := newRuntimeBindings()
	recorder := &countingRecorder{RecordingController: parquet.NewRecorder(parquet.RecorderConfig{})}
	r.recorder = recorder
	emitter := r.beginSession().RowEmitter()

	r.mu.Lock() // park the emit on the gate
	unlock := sync.OnceFunc(r.mu.Unlock)
	baseline := parkwait.Count(emitRowFrame, gateReadReasons...)
	emitted := make(chan struct{})
	// A failing wait must not leave the emitter parked, nor let it run on
	// after the test ended: release the gate, then wait (bounded, in case the
	// emit is wedged elsewhere) for the emitting goroutine to finish.
	t.Cleanup(func() {
		unlock()
		select {
		case <-emitted:
		case <-time.After(10 * time.Second):
			t.Error("emitting goroutine still running 10s after the gate was released")
		}
	})
	go func() {
		defer close(emitted)
		emitRows(emitter, 1)
	}()
	parkwait.Await{
		Frame:      emitRowFrame,
		Reasons:    gateReadReasons,
		Baseline:   baseline,
		Done:       emitted,
		DoneMsg:    "EmitRow returned while the gate was write-locked",
		TimeoutMsg: "EmitRow never parked on the gate's read lock",
	}.Run(t)
	r.advanceFilterEpoch()
	unlock()
	<-emitted

	if recorder.rows != 1 || recorder.epochs[0] != 1 {
		t.Fatalf("recorder got %d rows at epochs %v, want 1 row at epoch 1 (the epoch current inside the gate)", recorder.rows, recorder.epochs)
	}
}

// emitRowFrame and gateReadReasons identify a goroutine parked on the
// session gate's read lock inside sessionRowEmitter.EmitRow in the goroutine
// dump: "sync.RWMutex.RLock" in the header on current toolchains,
// "semacquire" on older ones.
const emitRowFrame = "tui.sessionRowEmitter.EmitRow"

var gateReadReasons = []string{parkwait.RWMutexRLock, parkwait.Semacquire}

// TestSessionEmitRowRacesWithRetirement hammers the gate from several
// emitters while the session is retired and restarted: whatever interleaving
// the scheduler picks, once end returns the stream no longer grows (run it
// with -race for the data-race side).
func TestSessionEmitRowRacesWithRetirement(t *testing.T) {
	for round := 0; round < 50; round++ {
		r := newRuntimeBindings()
		view := r.beginSession()
		emitter := view.RowEmitter()

		var wg sync.WaitGroup
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 200; i++ {
					emitter.EmitRow(streamrow.Row{Seq: uint64(i), Syscall: "read"})
				}
			}()
		}
		view.end()
		afterEnd := r.streamBuffer.Len()
		wg.Wait()
		if got := r.streamBuffer.Len(); got != afterEnd {
			t.Fatalf("round %d: stream grew from %d to %d rows after endSession returned", round, afterEnd, got)
		}
	}
}

// TestTraceRequestBindingsOfferTheSessionEmitter checks the wiring from the
// outside: the bindings a trace session receives in its TraceRequest are the
// session view, expose the emitter, and that emitter follows the session's
// lifecycle (live while it runs, dropped once the lifecycle stops it).
func TestTraceRequestBindingsOfferTheSessionEmitter(t *testing.T) {
	requests := make(chan TraceRequest, 1)
	lifecycle := newTraceLifecycle(func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(lifecycle.stop)
	r := newRuntimeBindings()

	lifecycle.beginCmd(r, globalfilter.Filter{})()
	source, ok := (<-requests).Bindings.(runtime.RowEmitterSource)
	if !ok {
		t.Fatal("the TraceRequest bindings do not offer a runtime.RowEmitterSource")
	}
	emitter := source.RowEmitter()

	emitRows(emitter, 1)
	lifecycle.stop()
	emitRows(emitter, 2)
	if n := r.streamBuffer.Len(); n != 1 {
		t.Fatalf("stream holds %d rows, want only the one emitted while the session ran", n)
	}
}
