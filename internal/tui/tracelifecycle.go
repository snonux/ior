package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
)

// traceLifecycle manages trace start/stop, recording start/stop, and the
// auto-reset interval cycle. It owns the context.CancelFunc for the running
// trace so the Model can stop tracing without understanding the context
// machinery.
type traceLifecycle struct {
	startTrace TraceStarter
	// traceCtx is the running session's context and traceStop cancels it;
	// both are nil while no session runs. Work bound to the session, such as
	// a family batch on its probe manager, shares traceCtx (sessionContext).
	traceCtx         context.Context
	traceStop        context.CancelFunc
	shutdownReporter *runtime.TraceShutdownReporter
	// session numbers the sessions begun by this lifecycle; the running one
	// (if any) is session. It tags each session's start result so a result
	// of a session that has since been stopped or replaced can be ignored.
	session uint64
	// endSession retires the running session's bindings view (nil without
	// bindings or when no session runs), see traceSessionBindings.
	endSession func()
	// attachSyscalls is the probe set every following session attaches (see
	// runtime.TraceRequest.AttachSyscalls): nil until the user changes the
	// attached probes at runtime, so the startup -trace-* selection applies
	// until then. It outlives sessions, which is what carries a runtime
	// probe change across a restart.
	attachSyscalls []string
}

// tracingShutdownProgressMsg carries one progress update from the active
// trace session back onto Bubble Tea's Update goroutine.
type tracingShutdownProgressMsg struct {
	progress runtime.TraceShutdownProgress
}

// traceSessionResultMsg is the start result (TracingStartedMsg or
// TracingErrorMsg) of one session, tagged with that session's number. The
// model applies result only while traceLifecycle.isCurrent(session): a restart
// does not wait for the old session, whose result can still arrive after the
// new session has begun.
type traceSessionResultMsg struct {
	session uint64
	result  tea.Msg
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
//
// The session's bindings, filter, shutdown reporter and runtime probe
// selection (setAttachSyscalls) reach the starter explicitly in a
// TraceRequest; the context only carries cancellation.
//
// The cancelled session is not waited for, so it may still be loading,
// attaching or detaching while the new one starts. That is why each session
// gets its own bindings view (runtimeBindings.beginSession), retired again by
// stop: the view drops whatever the stopped session publishes, clears or emits
// from then on, so its late setup, events or teardown cannot replace or erase
// the new session's probe manager, live-filter setter, dashboard sources or
// stream. For the same reason its start result is tagged with the session
// number (traceSessionResultMsg) and ignored once the session is not current.
func (t *traceLifecycle) beginCmd(bindings *runtimeBindings, filter globalfilter.Filter) tea.Cmd {
	t.stop()
	ctx, cancel := context.WithCancel(context.Background())
	t.traceCtx, t.traceStop = ctx, cancel
	t.shutdownReporter = runtime.NewTraceShutdownReporter()
	t.session++
	var sessionBindings runtime.TraceRuntimeBindings
	if bindings != nil {
		view := bindings.beginSession()
		t.endSession = view.end
		sessionBindings = view
	}
	req := newTraceRequest(sessionBindings, filter, t.shutdownReporter)
	req.AttachSyscalls = t.attachSyscalls
	return tagSessionResult(t.session, startTraceCmd(ctx, t.startTrace, req))
}

// setAttachSyscalls records the probe set the next sessions attach. The slice
// is owned by the lifecycle from here on; callers pass a fresh one.
func (t *traceLifecycle) setAttachSyscalls(syscalls []string) {
	t.attachSyscalls = syscalls
}

// newTraceRequest assembles the explicit inputs of one trace session. The
// filter is cloned so the starter never aliases the model's filter state,
// which the user keeps editing while the session runs. A nil bindings stays a
// nil interface, which a starter's "no TUI attached" check (Bindings == nil)
// sees as absent.
func newTraceRequest(bindings runtime.TraceRuntimeBindings, filter globalfilter.Filter, reporter *runtime.TraceShutdownReporter) TraceRequest {
	cloned := filter.Clone()
	return TraceRequest{Bindings: bindings, Filter: &cloned, ShutdownReporter: reporter}
}

// tagSessionResult wraps cmd so that its non-nil result arrives as a
// traceSessionResultMsg of session.
func tagSessionResult(session uint64, cmd tea.Cmd) tea.Cmd {
	return func() tea.Msg {
		result := cmd()
		if result == nil {
			return nil
		}
		return traceSessionResultMsg{session: session, result: result}
	}
}

// isCurrent reports whether session is the running session, i.e. the newest
// one begun and not stopped since.
func (t *traceLifecycle) isCurrent(session uint64) bool {
	return t.running() && session == t.session
}

// sessionContext returns the running session's context, which stop cancels.
// Without a running session it returns an already cancelled context: work
// started then has no session to belong to (and no probe manager is
// published without one, see runtimeBindings.endSessionLocked), so it must
// not run at all.
func (t *traceLifecycle) sessionContext() context.Context {
	if t.traceCtx != nil {
		return t.traceCtx
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// running reports whether a trace session is live, i.e. started and not yet
// stopped.
func (t *traceLifecycle) running() bool {
	return t.traceStop != nil
}

// stop cancels the running trace and clears the cancel function. Safe to call
// multiple times or when no trace is running.
func (t *traceLifecycle) stop() {
	if t.traceStop != nil {
		t.traceStop()
		t.traceCtx, t.traceStop = nil, nil
	}
	// Retire the session's bindings view synchronously, here on the Update
	// goroutine: once stop returns, none of the stopped session's rows can
	// still reach the stream or the recorder, which is what lets callers reset
	// the stream (selectProcess) or advance the filter epoch right after.
	if t.endSession != nil {
		t.endSession()
		t.endSession = nil
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
func startTraceCmd(ctx context.Context, starter TraceStarter, req TraceRequest) tea.Cmd {
	return startTraceCmdWithTimeout(ctx, starter, req, defaultStartupTimeout)
}

// startTraceCmdWithTimeout is the testable core of startTraceCmd. It races
// the starter goroutine against a caller-supplied timeout so that tests can
// use a short deadline without waiting 30 seconds.
// ctx is first per Go convention (context.Context always leads the parameter list).
func startTraceCmdWithTimeout(ctx context.Context, starter TraceStarter, req TraceRequest, timeout time.Duration) tea.Cmd {
	return func() tea.Msg {
		// Nil-safe: a request without a reporter has no waiter to release.
		defer req.ShutdownReporter.CompleteUnlessClaimed()
		type starterResult struct{ err error }
		ch := make(chan starterResult, 1)
		go func() {
			err := starter(ctx, req)
			ch <- starterResult{err: err}
		}()
		select {
		case res := <-ch:
			// A stopped session reports nothing, whatever the starter
			// returned: a success that raced the stop is not a running
			// trace, and its failure is not the user's concern any more.
			if ctx.Err() != nil || errors.Is(res.err, context.Canceled) {
				return nil
			}
			if res.err != nil {
				return TracingErrorMsg{Err: res.err}
			}
			return TracingStartedMsg{}
		case <-time.After(timeout):
			// A session stopped while its starter hung (for example stuck
			// in BPFLoadObject) must not report a fatal timeout against
			// whatever runs now.
			if ctx.Err() != nil {
				return nil
			}
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

func defaultTraceStarter(context.Context, TraceRequest) error {
	return nil
}

// recorderStart opens the parquet recorder at the given path.
// It calls syncFn (typically syncDashboardFilterState) after the attempt
// (success or failure) so the status bar stays in sync.
func recorderStart(recorder runtime.RecordingController, path string, syncFn func()) error {
	if recorder == nil {
		return errors.New("recording runtime is unavailable")
	}
	err := recorder.Start(path, parquet.StartOptions{
		Metadata: tuiParquetMetadata(),
		// The R modal offers a generated default; only that name is ior's to
		// protect. Anything the user typed is theirs and is replaced.
		AutoNamed: isDefaultParquetRecordingName(path),
	})
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
	if status.Path != "" && status.RequestedPath != "" && status.Path != status.RequestedPath {
		// An auto-named recording found its name taken and was published
		// under a "-N" name; say so, since the modal showed the other one.
		return "rec: saved as " + shortenRecordingPath(status.Path) + dropped
	}
	return "rec: off" + dropped
}

// defaultParquetRecordingLayout is the time.Format layout of the generated
// recording name; isDefaultParquetRecordingName parses with the same layout,
// so the two cannot drift apart.
const defaultParquetRecordingLayout = "ior-recording-20060102-150405.parquet"

func defaultParquetRecordingFilename() string {
	return time.Now().Format(defaultParquetRecordingLayout)
}

// isDefaultParquetRecordingName reports whether path's file name is a
// generated default recording name (as opposed to one the user typed). Such a
// name is only accurate to the second, so it is published without replacing an
// existing file.
func isDefaultParquetRecordingName(path string) bool {
	_, err := time.Parse(defaultParquetRecordingLayout, filepath.Base(path))
	return err == nil
}

// tuiParquetMetadata delegates to the canonical parquet.NewFileMetadata.
func tuiParquetMetadata() parquet.FileMetadata {
	return parquet.NewFileMetadata("tui")
}

// shortenRecordingPath keeps the status-line recording path within 36 display
// cells, preserving its end (the file name) behind a "..." prefix. The cut is
// grapheme-aware (common.TruncateLeft) so non-ASCII paths stay valid UTF-8.
func shortenRecordingPath(path string) string {
	const maxWidth = 36
	return common.TruncateLeft(path, maxWidth, common.ASCIIEllipsis)
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
