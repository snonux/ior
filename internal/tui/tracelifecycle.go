package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/parquet"

	tea "charm.land/bubbletea/v2"
)

// traceLifecycle manages trace start/stop, recording start/stop, and the
// auto-reset interval cycle. It owns the context.CancelFunc for the running
// trace so the Model can stop tracing without understanding the context
// machinery.
type traceLifecycle struct {
	startTrace TraceStarter
	traceStop  context.CancelFunc
}

// newTraceLifecycle creates a traceLifecycle bound to the given starter.
// If starter is nil, a no-op default is used so the model can operate
// in tests without a real BPF trace.
func newTraceLifecycle(starter TraceStarter) traceLifecycle {
	if starter == nil {
		starter = defaultTraceStarter
	}
	return traceLifecycle{startTrace: starter}
}

// beginCmd creates a tea.Cmd that runs the trace starter in a goroutine and
// returns a TracingStartedMsg or TracingErrorMsg. It also cancels any
// previously running trace and stores the new cancel function.
func (t *traceLifecycle) beginCmd(runtime *runtimeBindings, filter globalfilter.Filter) tea.Cmd {
	ctx, cancel := context.WithCancel(context.Background())
	t.traceStop = cancel
	ctx = ContextWithRuntimeBindings(ctx, runtime)
	ctx = ContextWithTraceFilters(ctx, filter)
	return startTraceCmd(t.startTrace, ctx)
}

// stop cancels the running trace and clears the cancel function. Safe to call
// multiple times or when no trace is running.
func (t *traceLifecycle) stop() {
	if t.traceStop != nil {
		t.traceStop()
		t.traceStop = nil
	}
}

// startTraceCmd wraps a TraceStarter in a tea.Cmd that handles context
// cancellation gracefully (returns nil so the caller does not treat a
// user-initiated stop as an error).
func startTraceCmd(starter TraceStarter, ctx context.Context) tea.Cmd {
	return func() tea.Msg {
		if err := starter(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return TracingErrorMsg{Err: err}
		}
		return TracingStartedMsg{}
	}
}

func defaultTraceStarter(context.Context) error {
	return nil
}

// recorderStart opens the parquet recorder at the given path.
// It calls syncFn (typically syncDashboardFilterState) after the attempt
// (success or failure) so the status bar stays in sync.
func recorderStart(recorder *parquet.Recorder, path string, syncFn func()) error {
	if recorder == nil {
		return errors.New("recording runtime is unavailable")
	}
	err := recorder.Start(path, parquet.StartOptions{Metadata: tuiParquetMetadata()})
	syncFn()
	return err
}

// recorderStop closes the active parquet recorder.
// Returns nil without error when no recording is active.
// Calls syncFn after the attempt so the status bar stays in sync.
func recorderStop(recorder *parquet.Recorder, syncFn func()) error {
	if recorder == nil {
		return nil
	}
	if !recorder.Status().Active {
		syncFn()
		return nil
	}
	err := recorder.Stop()
	syncFn()
	return err
}

// recorderActive returns true when the recorder is currently recording.
func recorderActive(recorder *parquet.Recorder) bool {
	if recorder == nil {
		return false
	}
	return recorder.Status().Active
}

// recorderStatus returns the human-readable recording status string shown
// in the status bar.
func recorderStatus(recorder *parquet.Recorder) string {
	if recorder == nil {
		return "rec: unavailable"
	}
	status := recorder.Status()
	if status.Active {
		return "rec: " + shortenRecordingPath(status.Path)
	}
	if status.LastError != nil {
		return "rec err: " + status.LastError.Error()
	}
	return "rec: off"
}

func defaultParquetRecordingFilename() string {
	return fmt.Sprintf("ior-recording-%s.parquet", time.Now().Format("20060102-150405"))
}

// tuiParquetMetadata delegates to the canonical parquet.NewFileMetadata.
func tuiParquetMetadata() parquet.FileMetadata {
	return parquet.NewFileMetadata("tui")
}

func shortenRecordingPath(path string) string {
	const maxLen = 36
	if len(path) <= maxLen {
		return path
	}
	return "..." + path[len(path)-maxLen+3:]
}

// autoResetCycle is the ordered set of cadences exposed via the `I` hotkey.
// The first entry (0) disables the timer; the rest are progressively longer
// to give users a quick way to slow auto-resets down on long traces or turn
// them off entirely. The cycle wraps so pressing `I` past the last preset
// returns to off.
var autoResetCycle = []time.Duration{
	0,
	10 * time.Second,
	30 * time.Second,
	60 * time.Second,
	2 * time.Minute,
	5 * time.Minute,
}

// nextAutoResetInterval returns the next entry in autoResetCycle after
// current. If current is not in the cycle (e.g. a custom -resetTimer like
// 47s), the next entry is the first cycle value strictly greater than current;
// if there is none, we wrap to 0 (off).
func nextAutoResetInterval(current time.Duration) time.Duration {
	for i, d := range autoResetCycle {
		if d == current {
			return autoResetCycle[(i+1)%len(autoResetCycle)]
		}
	}
	for _, d := range autoResetCycle {
		if d > current {
			return d
		}
	}
	return autoResetCycle[0]
}
