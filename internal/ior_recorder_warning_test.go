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

// scriptedRowRecorder is a runtime.RowRecorder fake that returns the scripted
// errors in order, one per Record call, and nil once the script is exhausted.
type scriptedRowRecorder struct {
	errs  []error
	calls int
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

// TestTUIRealRecorderFailureSurvivesIdleEvents checks that idle
// ErrRecorderNotActive results do not disarm the failure warning: a real
// failure of a recording started later in the session is reported, once.
func TestTUIRealRecorderFailureSurvivesIdleEvents(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		parquet.ErrRecorderNotActive,
		fmt.Errorf("wrapped: %w", parquet.ErrRecorderNotActive),
		nil, // recording started
		errors.New("disk full"),
		errors.New("disk full"), // dead recording's LastError repeats
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 6))
	if len(msgs) != 1 {
		t.Fatalf("warnings = %q, want exactly one failure warning", msgs)
	}
	if !strings.Contains(msgs[0], "Parquet recorder failed: disk full") {
		t.Fatalf("warning = %q, want the first real failure (disk full)", msgs[0])
	}
}

// TestTUIRecorderOverflowAndFailureWarnIndependently checks that queue-full
// and genuine failures each get their own single warning per recording.
func TestTUIRecorderOverflowAndFailureWarnIndependently(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		nil,
		parquet.ErrRecorderQueueFull,
		nil, // capacity freed within the same recording: no re-warn
		parquet.ErrRecorderQueueFull,
		parquet.ErrRecorderQueueFull,
		errors.New("writer boom"),
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 6))
	if len(msgs) != 2 {
		t.Fatalf("warnings = %q, want one overflow and one failure warning", msgs)
	}
	if !strings.Contains(msgs[0], "queue full") || !strings.Contains(msgs[1], "writer boom") {
		t.Fatalf("warnings = %q, want [queue full, writer boom]", msgs)
	}
}

// TestTUIRecorderWarningsRearmPerRecording checks that the guards are per
// recording, not per trace session: a second recording in the same session
// gets its own overflow and failure warnings.
func TestTUIRecorderWarningsRearmPerRecording(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		nil, parquet.ErrRecorderQueueFull, errors.New("rec1 disk full"),
		errors.New("rec1 disk full"), // LastError until the next Start
		nil, parquet.ErrRecorderQueueFull, errors.New("rec2 boom"),
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 8))
	want := []string{"queue full", "rec1 disk full", "queue full", "rec2 boom"}
	assertWarnings(t, msgs, want)
}

// TestTUIStaleRecorderErrorIsSilent checks that a trace session starting
// after an earlier recording failed does not re-announce the stale LastError
// that Record keeps returning until the next Start.
func TestTUIStaleRecorderErrorIsSilent(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		errors.New("old disk full"), errors.New("old disk full"),
	}}
	if msgs := warningMessages(runTUIPairs(t, nil, recorder, 3)); len(msgs) != 0 {
		t.Fatalf("warnings = %q, want none for a stale failure", msgs)
	}
}

// TestTUIRealRecorderFailuresAcrossRecordingsAndSessions drives a real
// parquet.Recorder whose writes fail: two failing recordings in one trace
// session are each reported once, and a later trace session on the same
// (TUI-lifetime) recorder stays silent about the stale error.
func TestTUIRealRecorderFailuresAcrossRecordingsAndSessions(t *testing.T) {
	writeErr := errors.New("disk full")
	recorder := parquet.NewRecorder(parquet.RecorderConfig{
		BatchSize: 1, FlushInterval: time.Hour,
	}.WithFailingWriter(writeErr))
	bindings := &traceRuntimeBindingsStub{
		streamBuffer: streamrow.NewRingBuffer(),
		streamSeq:    streamrow.NewSequencer(0),
		recorder:     recorder,
	}
	dir := t.TempDir()

	first := newTUITestSession(t, bindings, nil)
	for i := range 2 {
		startRecorder(t, recorder, filepath.Join(dir, fmt.Sprintf("rec%d", i)))
		first.feed(1) // accepted, then the batch write fails
		waitRecorderFailed(t, recorder)
		first.feed(2) // LastError: reported once, then silent
	}
	assertWarnings(t, first.warnings(), []string{"disk full", "disk full"})

	bindings.streamBuffer.Reset()
	second := newTUITestSession(t, bindings, nil)
	second.feed(3)
	if msgs := second.warnings(); len(msgs) != 0 {
		t.Fatalf("new session warnings = %q, want none for the stale failure", msgs)
	}
}

// TestTUIRecorderStopRaceIsSilent checks that Record calls hitting a stopped
// recording (ErrRecorderNotActive, as when Stop races the event loop) stay
// silent, with a real recorder that stops cleanly.
func TestTUIRecorderStopRaceIsSilent(t *testing.T) {
	recorder := parquet.NewRecorder(parquet.RecorderConfig{BatchSize: 1, FlushInterval: time.Hour})
	startRecorder(t, recorder, filepath.Join(t.TempDir(), "rec"))
	s := newTUITestSession(t, nil, recorder)
	s.feed(2)
	if err := recorder.Stop(); err != nil {
		t.Fatalf("recorder.Stop() error = %v", err)
	}
	s.feed(2)
	if msgs := s.warnings(); len(msgs) != 0 {
		t.Fatalf("warnings = %q, want none after a clean stop", msgs)
	}
}

// TestRecorderWarnerWithoutWarningCallback checks that a loop without a
// warning sink tolerates every result category, and that the same sequence
// with a sink wired yields exactly the expected warnings.
func TestRecorderWarnerWithoutWarningCallback(t *testing.T) {
	results := []error{nil, parquet.ErrRecorderQueueFull, parquet.ErrRecorderNotActive, nil, errors.New("boom")}
	silent := &recorderWarner{}
	for _, err := range results {
		silent.warn(&eventLoop{}, err) // no sink: must not panic
	}

	var got []string
	el := &eventLoop{}
	el.SetWarningCallback(func(msg string) { got = append(got, msg) })
	w := &recorderWarner{}
	for _, err := range results {
		w.warn(el, err)
	}
	assertWarnings(t, got, []string{"queue full", "boom"})
}

// startRecorder starts a recording at path or fails the test.
func startRecorder(t *testing.T, recorder *parquet.Recorder, path string) {
	t.Helper()
	if err := recorder.Start(path, parquet.StartOptions{}); err != nil {
		t.Fatalf("recorder.Start() error = %v", err)
	}
}

// waitRecorderFailed waits until the recorder's session has died with an
// error (the writer goroutine fails asynchronously).
func waitRecorderFailed(t *testing.T, recorder *parquet.Recorder) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st := recorder.Status(); !st.Active && st.LastError != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorder did not fail in time: %+v", recorder.Status())
		}
		time.Sleep(time.Millisecond)
	}
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
