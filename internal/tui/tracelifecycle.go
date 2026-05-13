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

// defaultStartupTimeout is the maximum time allowed for BPF probe attachment.
// If the trace starter does not return within this window the TUI surfaces
// a TracingErrorMsg instead of spinning in the "Attaching tracepoints..."
// state indefinitely. The stuck goroutine is left running until the caller
// cancels the trace context (e.g. via traceLifecycle.stop on the next
// user action) so no goroutine is leaked permanently.
const defaultStartupTimeout = 30 * time.Second

// startTraceCmd wraps a TraceStarter in a tea.Cmd that handles context
// cancellation gracefully (returns nil so the caller does not treat a
// user-initiated stop as an error). It uses defaultStartupTimeout to
// prevent the TUI from hanging indefinitely when BPF probe attachment stalls.
func startTraceCmd(starter TraceStarter, ctx context.Context) tea.Cmd {
	return startTraceCmdWithTimeout(starter, ctx, defaultStartupTimeout)
}

// startTraceCmdWithTimeout is the testable core of startTraceCmd. It races
// the starter goroutine against a caller-supplied timeout so that tests can
// use a short deadline without waiting 30 seconds.
func startTraceCmdWithTimeout(starter TraceStarter, ctx context.Context, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		type starterResult struct{ err error }
		ch := make(chan starterResult, 1)
		go func() {
			err := starter(ctx)
			ch <- starterResult{err: err}
		}()
		select {
		case res := <-ch:
			if res.err != nil {
				if errors.Is(res.err, context.Canceled) {
					return nil
				}
				return TracingErrorMsg{Err: res.err}
			}
			return TracingStartedMsg{}
		case <-time.After(timeout):
			// BPF probe attachment did not complete in time. The stuck
			// goroutine will be cleaned up when the caller cancels ctx
			// (e.g. on the next traceLifecycle.stop call).
			return TracingErrorMsg{Err: fmt.Errorf(
				"trace startup timed out after %s: BPF probe attachment did not complete",
				timeout,
			)}
		}
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
