package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"

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

// runTUIPairs builds a TUI runtime (optionally swapping in recorder), wires an
// event loop through makeTUIEventLoopConfigurer, feeds n trace pairs through
// the print callback and returns the stream rows that were pushed.
func runTUIPairs(t *testing.T, bindings runtime.TraceRuntimeBindings, recorder runtime.RowRecorder, n int) []streamrow.Row {
	t.Helper()
	rt, err := buildTUIRuntime(flags.NewFlags(), bindings)
	if err != nil {
		t.Fatalf("buildTUIRuntime() error = %v", err)
	}
	if recorder != nil {
		rt.recorder = recorder
	}
	configure, unregister := makeTUIEventLoopConfigurer(flags.NewFlags(), rt, nil)
	defer unregister()
	el := &eventLoop{}
	configure(el)
	for i := 1; i <= n; i++ {
		el.printCb(testTracePair(uint64(i), "keep"))
	}
	return rt.streamSrc.Snapshot()
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
// ErrRecorderNotActive results do not consume the failure once-guard: a real
// failure later in the same session is still reported, exactly once.
func TestTUIRealRecorderFailureSurvivesIdleEvents(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		parquet.ErrRecorderNotActive,
		fmt.Errorf("wrapped: %w", parquet.ErrRecorderNotActive),
		errors.New("disk full"),
		errors.New("second failure"),
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 5))
	if len(msgs) != 1 {
		t.Fatalf("warnings = %q, want exactly one failure warning", msgs)
	}
	if !strings.Contains(msgs[0], "Parquet recorder failed: disk full") {
		t.Fatalf("warning = %q, want the first real failure (disk full)", msgs[0])
	}
}

// TestTUIRecorderOverflowAndFailureWarnIndependently checks that queue-full
// and genuine failures each get their own single warning.
func TestTUIRecorderOverflowAndFailureWarnIndependently(t *testing.T) {
	recorder := &scriptedRowRecorder{errs: []error{
		parquet.ErrRecorderQueueFull,
		parquet.ErrRecorderQueueFull,
		errors.New("writer boom"),
	}}
	msgs := warningMessages(runTUIPairs(t, nil, recorder, 4))
	if len(msgs) != 2 {
		t.Fatalf("warnings = %q, want one overflow and one failure warning", msgs)
	}
	if !strings.Contains(msgs[0], "queue full") || !strings.Contains(msgs[1], "writer boom") {
		t.Fatalf("warnings = %q, want [queue full, writer boom]", msgs)
	}
}

// TestRecorderWarnerWithoutWarningCallback checks that a loop without a
// warning sink (headless wiring, tests) tolerates every error category.
func TestRecorderWarnerWithoutWarningCallback(t *testing.T) {
	w := &recorderWarner{}
	el := &eventLoop{}
	for _, err := range []error{nil, parquet.ErrRecorderNotActive, parquet.ErrRecorderQueueFull, errors.New("boom")} {
		w.warn(el, err) // must not panic
	}
}
