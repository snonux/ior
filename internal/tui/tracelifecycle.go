package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"

	tea "charm.land/bubbletea/v2"
)

// traceLifecycle manages trace start/stop, recording start/stop, and the
// auto-reset interval cycle. It owns the context.CancelFunc for the running
// trace so the Model can stop tracing without understanding the context
// machinery.
type traceLifecycle struct {
	startTrace       TraceStarter
	traceStop        context.CancelFunc
	shutdownReporter *runtime.TraceShutdownReporter
}

// tracingShutdownProgressMsg carries one progress update from the active
// trace session back onto Bubble Tea's Update goroutine.
type tracingShutdownProgressMsg struct {
	progress runtime.TraceShutdownProgress
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
// returns a TracingStartedMsg or TracingErrorMsg. It cancels any previously
// running trace before storing the new cancel function, so at most one trace
// session (BPF module plus eventloop) is ever live per lifecycle: overwriting
// traceStop without cancelling it would orphan the old session, leaving its
// probes attached and feeding the same stream buffer as the new one. Callers
// that already called stop() pay nothing extra, because stop() is idempotent.
func (t *traceLifecycle) beginCmd(bindings *runtimeBindings, filter globalfilter.Filter) tea.Cmd {
	t.stop()
	ctx, cancel := context.WithCancel(context.Background())
	t.traceStop = cancel
	t.shutdownReporter = runtime.NewTraceShutdownReporter()
	ctx = ContextWithRuntimeBindings(ctx, bindings)
	ctx = ContextWithTraceFilters(ctx, filter)
	ctx = runtime.ContextWithTraceShutdownReporter(ctx, t.shutdownReporter)
	return startTraceCmd(ctx, t.startTrace)
}

// stop cancels the running trace and clears the cancel function. Safe to call
// multiple times or when no trace is running.
func (t *traceLifecycle) stop() {
	if t.traceStop != nil {
		t.traceStop()
		t.traceStop = nil
	}
}

// stopAndWaitCmd cancels the active trace and returns a command that waits for
// this exact session's next shutdown update. A nil reporter means no trace was
// ever started (for example, quitting directly from the initial PID picker),
// so there is no cleanup to wait for.
func (t *traceLifecycle) stopAndWaitCmd() tea.Cmd {
	t.stop()
	return t.waitForShutdownCmd()
}

func (t *traceLifecycle) waitForShutdownCmd() tea.Cmd {
	reporter := t.shutdownReporter
	if reporter == nil {
		return tea.Quit
	}
	return waitForTraceShutdownCmd(reporter.Updates())
}

func waitForTraceShutdownCmd(updates <-chan runtime.TraceShutdownProgress) tea.Cmd {
	return func() tea.Msg {
		return tracingShutdownProgressMsg{progress: <-updates}
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
// ctx is first per Go convention (context.Context always leads the parameter list).
func startTraceCmd(ctx context.Context, starter TraceStarter) tea.Cmd {
	return startTraceCmdWithTimeout(ctx, starter, defaultStartupTimeout)
}

// startTraceCmdWithTimeout is the testable core of startTraceCmd. It races
// the starter goroutine against a caller-supplied timeout so that tests can
// use a short deadline without waiting 30 seconds.
// ctx is first per Go convention (context.Context always leads the parameter list).
func startTraceCmdWithTimeout(ctx context.Context, starter TraceStarter, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		if reporter, ok := runtime.TraceShutdownReporterFromContext(ctx); ok {
			defer reporter.CompleteUnlessClaimed()
		}
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
func recorderStart(recorder runtime.RecordingController, path string, syncFn func()) error {
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
func recorderStop(recorder runtime.RecordingController, syncFn func()) error {
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
func recorderActive(recorder runtime.RecordingController) bool {
	if recorder == nil {
		return false
	}
	return recorder.Status().Active
}

// recorderStatus returns the human-readable recording status string shown
// in the status bar.
func recorderStatus(recorder runtime.RecordingController) string {
	if recorder == nil {
		return "rec: unavailable"
	}
	return formatRecorderStatus(recorder.Status())
}

// formatRecorderStatus renders a recorder status snapshot for the status
// bar, surfacing queue-overflow drops next to the recording state so partial
// recordings are visible without opening the file.
func formatRecorderStatus(status parquet.Status) string {
	dropped := ""
	if status.RowsDropped > 0 {
		dropped = fmt.Sprintf(" (dropped %d)", status.RowsDropped)
	}
	if status.Active {
		return "rec: " + shortenRecordingPath(status.Path) + dropped
	}
	if status.LastError != nil {
		return "rec err: " + status.LastError.Error()
	}
	return "rec: off" + dropped
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
