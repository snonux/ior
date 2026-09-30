package internal

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/streamrow"
)

// scriptedRowRecorder is a runtime.RowRecorder fake. Record returns the
// scripted errs in order and nil once they are exhausted; TakeFailure returns
// the scripted failures in order (nil entries model "not claimable yet" or
// "already taken by Stop") and nil once they are exhausted. The real
// report-once semantics are tested against parquet.Recorder in its package.
type scriptedRowRecorder struct {
	errs     []error
	calls    int
	failures []error
	takes    int
}

func (r *scriptedRowRecorder) TakeFailure() error {
	defer func() { r.takes++ }()
	if r.takes < len(r.failures) {
		return r.failures[r.takes]
	}
	return nil
}

func (r *scriptedRowRecorder) Record(streamrow.Row, uint64) error {
	defer func() { r.calls++ }()
	if r.calls < len(r.errs) {
		return r.errs[r.calls]
	}
	return nil
}

// tuiTestSession is one TUI trace session wired through
// makeTUIEventLoopConfigurer, driven by calling feed.
type tuiTestSession struct {
	rt *tuiRuntime
	el *eventLoop
}

// newTUITestSession builds a TUI runtime (optionally swapping in recorder)
// and wires a fresh event loop through makeTUIEventLoopConfigurer, like one
// trace start of the TUI does.
func newTUITestSession(t *testing.T, bindings runtime.TraceRuntimeBindings, recorder runtime.RowRecorder) *tuiTestSession {
	t.Helper()
	rt, err := buildTUIRuntime(flags.NewFlags(), bindings)
	if err != nil {
		t.Fatalf("buildTUIRuntime() error = %v", err)
	}
	if recorder != nil {
		rt.recorder = recorder
	}
	configure, unregister := makeTUIEventLoopConfigurer(flags.NewFlags(), rt, nil)
	t.Cleanup(unregister)
	el := &eventLoop{}
	configure(el)
	return &tuiTestSession{rt: rt, el: el}
}

// feed pushes n trace pairs through the session's print callback.
func (s *tuiTestSession) feed(n int) {
	for i := 0; i < n; i++ {
		s.el.printCb(testTracePair(uint64(i+1), "keep"))
	}
}

// warnings returns the warning messages pushed to the session's stream.
func (s *tuiTestSession) warnings() []string {
	return warningMessages(s.rt.streamSrc.Snapshot())
}

// runTUIPairs feeds n pairs through a fresh session and returns its stream.
func runTUIPairs(t *testing.T, bindings runtime.TraceRuntimeBindings, recorder runtime.RowRecorder, n int) []streamrow.Row {
	t.Helper()
	s := newTUITestSession(t, bindings, recorder)
	s.feed(n)
	return s.rt.streamSrc.Snapshot()
}

// warningMessages returns the messages of the synthetic warning rows.
func warningMessages(rows []streamrow.Row) []string {
	var msgs []string
	for _, row := range rows {
		if row.Syscall == "warning" {
			msgs = append(msgs, row.FileName)
		}
	}
	return msgs
}

// TestTUIIdleRecorderEmitsNoWarning is the regression test for task 4o2: the
// TUI bindings always carry a recorder, and with no recording running every
// Record call returns ErrRecorderNotActive. That idle state must not push a
// "Parquet recorder failed" warning into the stream.
func TestTUIIdleRecorderEmitsNoWarning(t *testing.T) {
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
		recorder:     parquet.NewRecorder(parquet.RecorderConfig{}), // never started
	}
	rows := runTUIPairs(t, bindings, nil, 3)
	if msgs := warningMessages(rows); len(msgs) != 0 {
		t.Fatalf("idle recorder produced warnings %q, want none", msgs)
	}
	if len(rows) != 3 {
		t.Fatalf("stream rows = %d, want 3 event rows", len(rows))
	}
}

// TestTUIRecorderFailureReportedOnce checks that a dead recording's error,
// which Record repeats on every call, is reported once - the one time the
// recorder hands it out via TakeFailure - and not before, while the session
// is still being torn down (TakeFailure nil).
func TestTUIRecorderFailureReportedOnce(t *testing.T) {
	diskFull := errors.New("disk full")
	recorder := &scriptedRowRecorder{
		errs:     []error{nil, diskFull, diskFull, diskFull, diskFull},
		failures: []error{nil, diskFull},
	}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 5))
	assertWarnings(t, msgs, []string{"Parquet recorder failed: disk full"})
	if recorder.takes != 4 {
		t.Fatalf("TakeFailure calls = %d, want one per failed Record (4)", recorder.takes)
	}
}

// TestTUIRecorderFailureBetweenSessionsReportedByNextSession covers a
// recording that spans a trace restart and fails after the first session's
// last event: the next session's first event reports it, once.
func TestTUIRecorderFailureBetweenSessionsReportedByNextSession(t *testing.T) {
	diskFull := errors.New("disk full")
	recorder := &scriptedRowRecorder{
		errs:     []error{nil, nil, diskFull, diskFull},
		failures: []error{diskFull},
	}
	first := newTUITestSession(t, nil, recorder)
	first.feed(2)
	assertWarnings(t, first.warnings(), nil)

	second := newTUITestSession(t, nil, recorder)
	second.feed(2)
	assertWarnings(t, second.warnings(), []string{"disk full"})
}

// TestTUIRecorderOverflowWarnedOncePerRecording checks that only the first
// shed row of each recording (ErrRecorderStartedDropping) warns, including a
// second recording started right after a Stop with no events in between.
func TestTUIRecorderOverflowWarnedOncePerRecording(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		nil, parquet.ErrRecorderStartedDropping, parquet.ErrRecorderQueueFull, nil, parquet.ErrRecorderQueueFull,
		// Stop -> Start: the new recording's first drop is announced again.
		parquet.ErrRecorderStartedDropping, parquet.ErrRecorderQueueFull,
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 8))
	assertWarnings(t, msgs, []string{"queue full", "queue full"})
	if recorder.takes != 0 {
		t.Fatalf("TakeFailure calls = %d, want 0 for overflow results", recorder.takes)
	}
}

// TestTUIRecordConcurrentWithStopIsSilent races the event loop against a
// real recorder's Stop: rows recorded while Stop drains the session
// (accepting == false) or after it return ErrRecorderNotActive, which must
// not produce a warning.
func TestTUIRecordConcurrentWithStopIsSilent(t *testing.T) {
	for round := 0; round < 20; round++ {
		recorder := parquet.NewRecorder(parquet.RecorderConfig{FlushInterval: time.Hour})
		if err := recorder.Start(filepath.Join(t.TempDir(), "rec"), parquet.StartOptions{}); err != nil {
			t.Fatalf("recorder.Start() error = %v", err)
		}
		s := newTUITestSession(t, nil, recorder)
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.feed(2000)
		}()
		if err := recorder.Stop(); err != nil {
			t.Fatalf("round %d: recorder.Stop() error = %v", round, err)
		}
		<-done
		if msgs := s.warnings(); len(msgs) != 0 {
			t.Fatalf("round %d: warnings = %q, want none around a clean stop", round, msgs)
		}
	}
}

// TestWarnRecorderResultCounts checks exact warning counts for a mixed
// result sequence, and that a loop without a warning sink tolerates it.
func TestWarnRecorderResultCounts(t *testing.T) {
	boom := errors.New("boom")
	results := []error{
		nil, parquet.ErrRecorderStartedDropping, parquet.ErrRecorderQueueFull,
		parquet.ErrRecorderNotActive, fmt.Errorf("wrapped: %w", parquet.ErrRecorderNotActive),
		boom, boom,
	}
	newRecorder := func() *scriptedRowRecorder { return &scriptedRowRecorder{failures: []error{boom}} }

	silent := newRecorder()
	for _, err := range results {
		warnRecorderResult(&eventLoop{}, silent, err) // no sink: must not panic
	}

	var got []string
	el := &eventLoop{}
	el.SetWarningCallback(func(msg string) { got = append(got, msg) })
	rec := newRecorder()
	for _, err := range results {
		warnRecorderResult(el, rec, err)
	}
	assertWarnings(t, got, []string{"queue full", "Parquet recorder failed: boom"})
}

// assertWarnings checks that got has one message per want entry, each
// containing the corresponding substring.
func assertWarnings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("warnings = %q, want %d matching %q", got, len(want), want)
	}
	for i := range want {
		if !strings.Contains(got[i], want[i]) {
			t.Fatalf("warning[%d] = %q, want it to contain %q (all: %q)", i, got[i], want[i], got)
		}
	}
}

// gatedRowRecorder is a runtime.WarningRecorder fake that, like the TUI's
// session view, runs the record call, the failure claim and the warning push
// as one step: retired makes it ignore everything (the session is over), and
// the warning lands in pushed only from inside RecordWarning.
type gatedRowRecorder struct {
	scriptedRowRecorder
	retired     bool
	pushed      []string
	plainRecord int
}

func (g *gatedRowRecorder) Record(row streamrow.Row, epoch uint64) error {
	g.plainRecord++
	return g.scriptedRowRecorder.Record(row, epoch)
}

func (g *gatedRowRecorder) RecordWarning(row streamrow.Row, epoch uint64, describe func(runtime.RowRecorder, error) string) {
	if g.retired {
		return
	}
	if message := describe(&g.scriptedRowRecorder, g.scriptedRowRecorder.Record(row, epoch)); message != "" {
		g.pushed = append(g.pushed, message)
	}
}

// TestRecordRowUsesTheGatedRecorderAtomically checks the dispatch task xp2
// added: a recorder that can publish its own warning is asked to (so the
// claim and the push cannot be split by a retiring session), its plain
// Record/TakeFailure/notifyWarning steps are not used, and a retired session
// neither claims the failure nor warns.
func TestRecordRowUsesTheGatedRecorderAtomically(t *testing.T) {
	diskFull := errors.New("disk full")
	rec := &gatedRowRecorder{scriptedRowRecorder: scriptedRowRecorder{
		errs: []error{nil, diskFull, diskFull}, failures: []error{diskFull},
	}}
	var viaLoop []string
	el := &eventLoop{}
	el.SetWarningCallback(func(msg string) { viaLoop = append(viaLoop, msg) })

	for i := 0; i < 3; i++ {
		recordRow(el, rec, streamrow.Row{}, 0)
	}
	assertWarnings(t, rec.pushed, []string{"Parquet recorder failed: disk full"})
	if rec.plainRecord != 0 || len(viaLoop) != 0 {
		t.Fatalf("plain Record calls = %d, event-loop warnings = %q, want the gated path only", rec.plainRecord, viaLoop)
	}

	retired := &gatedRowRecorder{retired: true, scriptedRowRecorder: scriptedRowRecorder{
		errs: []error{diskFull}, failures: []error{diskFull},
	}}
	recordRow(el, retired, streamrow.Row{}, 0)
	if retired.takes != 0 || len(retired.pushed) != 0 {
		t.Fatalf("retired session took %d failures and pushed %q, want neither", retired.takes, retired.pushed)
	}
}

// TestRecordRowFallsBackForPlainRecorders keeps the ungated form working for
// recorders that are not session views.
func TestRecordRowFallsBackForPlainRecorders(t *testing.T) {
	rec := &scriptedRowRecorder{errs: []error{parquet.ErrRecorderStartedDropping}}
	var got []string
	el := &eventLoop{}
	el.SetWarningCallback(func(msg string) { got = append(got, msg) })
	recordRow(el, rec, streamrow.Row{}, 0)
	assertWarnings(t, got, []string{"queue full"})
}
