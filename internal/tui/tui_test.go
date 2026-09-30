package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"

	"ior/internal/flags"
	"ior/internal/tui/probes"
	"ior/internal/types"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type fakeProbeManager struct {
	states []probemanager.ProbeState
}

func (f fakeProbeManager) States() []probemanager.ProbeState { return f.states }
func (f fakeProbeManager) Toggle(string) error               { return nil }
func (f fakeProbeManager) Attach(string) error               { return nil }
func (f fakeProbeManager) Detach(string) error               { return nil }
func (f fakeProbeManager) ActiveCount() (int, int)           { return len(f.states), len(f.states) }
func (f fakeProbeManager) AttachFamily(context.Context, types.SyscallFamily, func(int, int)) (probemanager.BatchResult, error) {
	return probemanager.BatchResult{}, nil
}
func (f fakeProbeManager) DetachFamily(context.Context, types.SyscallFamily, func(int, int)) (probemanager.BatchResult, error) {
	return probemanager.BatchResult{}, nil
}

type testStreamSink interface {
	eventstream.Source
	Push(eventstream.StreamEvent)
}

func requireTestStreamSink(t *testing.T, source eventstream.Source) testStreamSink {
	t.Helper()
	sink, ok := source.(testStreamSink)
	if !ok {
		t.Fatalf("expected stream source to support Push, got %T", source)
	}
	return sink
}

// TestBeginCmdHandsStarterItsInputsExplicitly pins that one trace session's
// bindings, filter and shutdown reporter reach the starter in its
// TraceRequest - the context only carries cancellation now, so a dropped
// field here would silently start the trace without the TUI attached.
func TestBeginCmdHandsStarterItsInputsExplicitly(t *testing.T) {
	requests := make(chan TraceRequest, 1)
	lifecycle := newTraceLifecycle(func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(lifecycle.stop)
	bindings := newRuntimeBindings()
	filter := globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "nginx"},
		File: &globalfilter.StringFilter{Pattern: "/var/log"},
		PID:  &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42},
	}

	cmd := lifecycle.beginCmd(bindings, filter)
	// The model keeps editing its filter while the session runs; the request
	// must not alias it.
	filter.Comm.Pattern = "mutated"
	filter.PID.Value = 7
	msg := cmd()
	if msg != (traceSessionResultMsg{session: lifecycle.session, result: TracingStartedMsg{}}) {
		t.Fatalf("begin command = %#v, want this session's TracingStartedMsg", msg)
	}
	req := <-requests

	if view, ok := req.Bindings.(traceSessionBindings); !ok || view.bindings != bindings {
		t.Fatalf("request bindings = %v, want a session view of the model's runtime bindings", req.Bindings)
	}
	if req.Filter == nil {
		t.Fatal("request carries no filter; the starter would keep the startup filter on every restart")
	}
	if req.Filter.Comm == nil || req.Filter.Comm.Pattern != "nginx" {
		t.Fatalf("request comm filter = %+v, want the cloned pattern nginx", req.Filter.Comm)
	}
	if req.Filter.PID == nil || req.Filter.PID.Value != 42 {
		t.Fatalf("request pid filter = %+v, want the cloned value 42", req.Filter.PID)
	}
	if req.ShutdownReporter == nil || req.ShutdownReporter != lifecycle.shutdownReporter {
		t.Fatal("request shutdown reporter is not this session's reporter")
	}
}

// TestNewTraceRequestTreatsNilBindingsAsAbsent is the negative case: absent
// bindings must stay a nil interface, which the starter's "no TUI attached"
// check relies on.
func TestNewTraceRequestTreatsNilBindingsAsAbsent(t *testing.T) {
	req := newTraceRequest(nil, globalfilter.Filter{}, nil)
	if req.Bindings != nil {
		t.Fatalf("request bindings = %#v, want a nil interface", req.Bindings)
	}
	if req.Filter == nil {
		t.Fatal("an empty filter must still be sent: it clears the PID/TID scope, unlike an absent one")
	}
	if req.ShutdownReporter != nil {
		t.Fatal("request invented a shutdown reporter")
	}
}

func TestPidSelectedTransitionsToDashboardAndSetsPIDFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	next, cmd := m.Update(PidSelectedMsg{Pid: 42})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}

	updated := next.(*Model)
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.router.current())
	}
	if !updated.attaching {
		t.Fatalf("expected attaching state to be true")
	}
	if updated.proc.pid != 42 {
		t.Fatalf("expected pid filter 42, got %d", updated.proc.pid)
	}
	if updated.proc.tid != -1 {
		t.Fatalf("expected tid filter reset to -1, got %d", updated.proc.tid)
	}
}

func TestInitialPIDSkipsPickerAndStartsTracing(t *testing.T) {
	m := NewModel(7, func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected initial screen dashboard, got %v", m.router.current())
	}

	if !cmdEmits[initialTraceStartMsg](m.Init()) {
		t.Fatal("Init with an initial pid must request the startup trace")
	}
}

func TestPidSelectedAllSetsNoFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	next, _ := m.Update(PidSelectedMsg{Pid: 0})
	updated := next.(*Model)

	if updated.proc.pid != -1 {
		t.Fatalf("expected pid filter -1 for all pids, got %d", updated.proc.pid)
	}
}

func TestTracingErrorMessageClearsAttachingState(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.attaching = true

	next, _ := m.Update(TracingErrorMsg{Err: errors.New("boom")})
	updated := next.(*Model)
	if updated.attaching {
		t.Fatalf("expected attaching to be false after tracing error")
	}
	if updated.lastErr == nil || updated.lastErr.Error() != "boom" {
		t.Fatalf("expected tracing error to be stored")
	}
	if updated.errorKind != errorScreenFatal {
		t.Fatalf("tracing error kind = %v, want fatal", updated.errorKind)
	}
}

func TestViewShowsAttachingAndErrorStates(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.attaching = true
	attachingView := m.View().Content
	if !strings.Contains(attachingView, "Attaching tracepoints...") {
		t.Fatalf("expected attaching view, got %q", attachingView)
	}

	m.attaching = false
	m.setError(errors.New("failed"), errorScreenFatal)
	errorView := m.View().Content
	if !strings.Contains(errorView, "failed") {
		t.Fatalf("expected error view, got %q", errorView)
	}
}

func TestQuitKeySetsQuittingState(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	if msg := cmd(); !isQuitMsg(msg) {
		t.Fatalf("expected tea.QuitMsg")
	}

	updated := next.(*Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestQuitDispatchWaitsForTheActiveTraceCleanup(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 100
	m.height = 30
	reporter := runtime.NewTraceShutdownReporter()
	m.tracer.shutdownReporter = reporter
	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := next.(*Model)
	if !stopped || !updated.quitting {
		t.Fatalf("quit dispatched stopped=%t quitting=%t, want both true", stopped, updated.quitting)
	}
	if got := updated.View().Content; !strings.Contains(got, "Stopping trace and releasing BPF resources") {
		t.Fatalf("initial shutdown view = %q", got)
	}

	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("quit command = %T with %d entries, want two-command batch", batch, len(batch))
	}
	// The spinner remains live while shutdown is indeterminate.
	if tickMsg := batch[0](); tickMsg == nil {
		t.Fatal("shutdown spinner tick returned nil")
	} else if _, tickCmd := updated.Update(tickMsg); tickCmd == nil {
		t.Fatal("shutdown spinner did not schedule its next tick")
	}

	reporter.Publish(runtime.TraceShutdownProgress{
		Phase:     runtime.TraceShutdownDetaching,
		Completed: 2,
		Total:     5,
	})
	progressMsg := batch[1]()
	progressNext, waitCmd := updated.Update(progressMsg)
	updated = progressNext.(*Model)
	if waitCmd == nil {
		t.Fatal("detach progress did not dispatch the next completion wait")
	}
	if got := updated.View().Content; !strings.Contains(got, "2/5") || !strings.Contains(got, "Detaching BPF probe pairs") {
		t.Fatalf("determinate shutdown view = %q, want detach count", got)
	}

	reporter.Publish(runtime.TraceShutdownProgress{Phase: runtime.TraceShutdownReleasing})
	releasingNext, completeWaitCmd := updated.Update(waitCmd())
	updated = releasingNext.(*Model)
	if completeWaitCmd == nil {
		t.Fatal("release progress did not dispatch the completion wait")
	}
	if got := updated.View().Content; !strings.Contains(got, "Releasing remaining BPF resources") {
		t.Fatalf("release shutdown view = %q", got)
	}

	reporter.Complete()
	completeNext, quitCmd := updated.Update(completeWaitCmd())
	updated = completeNext.(*Model)
	if quitCmd == nil {
		t.Fatal("shutdown completion did not dispatch tea.Quit")
	}
	if _, ok := quitCmd().(tea.QuitMsg); !ok {
		t.Fatalf("completion command = %T, want tea.QuitMsg", quitCmd())
	}
	if !updated.quitting {
		t.Fatal("completed shutdown lost the quitting state")
	}
}

func TestQuitWhileDashboardIsAttachingWaitsForBlockedStarterCleanup(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	releaseCleanup := make(chan struct{})
	claimed := make(chan bool, 1)
	starter := func(ctx context.Context, req TraceRequest) error {
		reporter := req.ShutdownReporter
		claimed <- reporter != nil && reporter.Claim()
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-releaseCleanup
		reporter.Complete()
		return ctx.Err()
	}

	m := NewModel(-1, starter)
	m.router.showDashboard()
	m.attaching = true
	startResult := make(chan tea.Msg, 1)
	go func() { startResult <- m.beginTraceCmd()() }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("starter did not begin")
	}
	if !<-claimed {
		t.Fatal("blocked starter did not claim shutdown completion")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := next.(*Model)
	if !updated.quitting {
		t.Fatal("quit while attaching did not enter shutdown view")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("attaching quit command = %T, want spinner + shutdown wait", batch)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("quit while attaching did not cancel the blocked starter")
	}

	shutdownMsg := make(chan tea.Msg, 1)
	go func() { shutdownMsg <- batch[1]() }()
	select {
	case msg := <-shutdownMsg:
		t.Fatalf("shutdown wait returned before starter cleanup: %T", msg)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseCleanup)

	var progressMsg tea.Msg
	select {
	case progressMsg = <-shutdownMsg:
	case <-time.After(time.Second):
		t.Fatal("shutdown wait did not receive starter completion")
	}
	completeNext, quitCmd := updated.Update(progressMsg)
	if _, ok := completeNext.(*Model); !ok {
		t.Fatalf("completion model = %T, want *Model", completeNext)
	}
	if quitCmd == nil {
		t.Fatal("starter cleanup completion did not dispatch tea.Quit")
	}
	if _, ok := quitCmd().(tea.QuitMsg); !ok {
		t.Fatalf("cleanup completion command = %T, want tea.QuitMsg", quitCmd())
	}
	select {
	case msg := <-startResult:
		if msg != nil {
			t.Fatalf("cancelled starter result = %T, want nil", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled starter command did not return")
	}
}

func TestTraceShutdownReporterIsIsolatedAcrossRestarts(t *testing.T) {
	lifecycle := newTraceLifecycle(func(context.Context, TraceRequest) error { return nil })
	bindings := newRuntimeBindings()
	_ = lifecycle.beginCmd(bindings, globalfilter.Filter{})
	oldReporter := lifecycle.shutdownReporter
	lifecycle.stop()
	_ = lifecycle.beginCmd(bindings, globalfilter.Filter{})
	newReporter := lifecycle.shutdownReporter
	if oldReporter == newReporter {
		t.Fatal("trace restart reused the previous session's shutdown reporter")
	}

	oldReporter.Complete()
	select {
	case got := <-newReporter.Updates():
		t.Fatalf("old trace completion reached the new session: %+v", got)
	default:
	}
	lifecycle.stop()
}

func TestQuitKeyMatchesSingleBindingWithoutPanic(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.keys.Quit = key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "quit"))
	m.router.showDashboard()
	m.attaching = false

	_, _ = m.Update(tea.KeyPressMsg{Code: []rune{'z'}[0], Text: string([]rune{'z'})})

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'x'}[0], Text: string([]rune{'x'})})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	updated := next.(*Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestStartTraceCmdLaunchesBeforeStarterReturns(t *testing.T) {
	cmd := startTraceCmd(context.Background(), func(context.Context, TraceRequest) error { return nil }, TraceRequest{})
	msg := cmd()
	if _, ok := msg.(TracingStartedMsg); !ok {
		t.Fatalf("expected TracingStartedMsg, got %T", msg)
	}
}

func TestStartTraceCmdEmitsErrorMsg(t *testing.T) {
	cmd := startTraceCmd(context.Background(), func(context.Context, TraceRequest) error { return errors.New("trace failed") }, TraceRequest{})
	msg := cmd()
	traceErr, ok := msg.(TracingErrorMsg)
	if !ok {
		t.Fatalf("expected TracingErrorMsg, got %T", msg)
	}
	if traceErr.Err == nil || traceErr.Err.Error() != "trace failed" {
		t.Fatalf("unexpected trace error message: %+v", traceErr)
	}
}

// TestStartTraceCmdCompletesTheRequestReporterOfANonClaimingStarter pins
// that the command releases a shutdown waiter through the reporter it got in
// the request, not one looked up elsewhere: a synchronous starter that never
// claims the reporter would otherwise leave quit waiting forever.
func TestStartTraceCmdCompletesTheRequestReporterOfANonClaimingStarter(t *testing.T) {
	reporter := runtime.NewTraceShutdownReporter()
	cmd := startTraceCmd(context.Background(), func(context.Context, TraceRequest) error { return nil },
		TraceRequest{ShutdownReporter: reporter})
	if _, ok := cmd().(TracingStartedMsg); !ok {
		t.Fatal("non-claiming starter did not report a started trace")
	}
	select {
	case got := <-reporter.Updates():
		if got.Phase != runtime.TraceShutdownComplete {
			t.Fatalf("reporter update = %+v, want complete", got)
		}
	default:
		t.Fatal("the request's reporter was not completed for a starter that never claimed it")
	}
}

// TestStartTraceCmdTimeoutEmitsErrorMsg verifies that a starter that never
// returns causes startTraceCmdWithTimeout to surface a TracingErrorMsg once
// the deadline expires, rather than blocking the TUI indefinitely.
func TestStartTraceCmdTimeoutEmitsErrorMsg(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Starter that blocks until ctx is cancelled, simulating a hung BPF attach.
	blocker := func(ctx context.Context, _ TraceRequest) error {
		<-ctx.Done()
		return ctx.Err()
	}

	// Use a short timeout so the test finishes quickly.
	cmd := startTraceCmdWithTimeout(ctx, blocker, TraceRequest{}, 50*time.Millisecond)
	msg := cmd()

	traceErr, ok := msg.(TracingErrorMsg)
	if !ok {
		t.Fatalf("expected TracingErrorMsg on timeout, got %T", msg)
	}
	if traceErr.Err == nil {
		t.Fatal("expected non-nil error in TracingErrorMsg")
	}
	if !strings.Contains(traceErr.Err.Error(), "timed out") {
		t.Fatalf("expected timeout message, got: %v", traceErr.Err)
	}
}

// TestStartTraceCmdContextCancelledBeforeTimeoutReturnsNil verifies that
// cancelling ctx before the timeout fires is treated as a user-initiated stop
// (returns nil, not an error).
func TestStartTraceCmdContextCancelledBeforeTimeoutReturnsNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Starter that blocks until ctx is cancelled.
	blocker := func(ctx context.Context, _ TraceRequest) error {
		<-ctx.Done()
		return ctx.Err()
	}

	// Cancel ctx immediately so the starter exits before the timeout.
	cancel()

	cmd := startTraceCmdWithTimeout(ctx, blocker, TraceRequest{}, 5*time.Second)
	msg := cmd()

	if msg != nil {
		t.Fatalf("expected nil msg on context cancel, got %T: %v", msg, msg)
	}
}

func TestQuitInvokesTraceStop(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	done := make(chan struct{})
	m.tracer.traceStop = func() {
		close(done)
	}

	_, quitCmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	if quitCmd == nil {
		t.Fatalf("expected quit command")
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected stopTrace to be invoked on quit")
	}
}

func TestStartupPIDPickerQuitsOnQuitKeys(t *testing.T) {
	tests := []struct {
		name  string
		press tea.KeyPressMsg
	}{
		{name: "q", press: tea.KeyPressMsg{Code: 'q', Text: "q"}},
		{name: "ctrl+c", press: tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			if m.router.current() != ScreenPIDPicker || hasReturn(m) {
				t.Fatalf("expected startup PID picker with no pending return")
			}
			// The filter input starts focused and would take a typed q as
			// text (see textinput_keys_test.go); Down moves the selection
			// off it, which is when q is a command again.
			next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
			m = next.(*Model)
			stopCalls := 0
			m.tracer.traceStop = func() { stopCalls++ }

			next, cmd := m.Update(tt.press)
			updated := assertQuits(t, next, cmd)
			if stopCalls != 1 {
				t.Fatalf("expected startup quit to stop tracing once, got %d calls", stopCalls)
			}
			if updated.tracer.traceStop != nil {
				t.Fatalf("expected startup quit to clear the trace stop function")
			}
		})
	}
}

func TestQuitKeysOnReselectPIDPickerReturnToDashboardLikeEsc(t *testing.T) {
	tests := []struct {
		name  string
		press tea.KeyPressMsg
	}{
		{name: "q", press: tea.KeyPressMsg{Code: 'q', Text: "q"}},
		{name: "ctrl+c", press: tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			m.router.showDashboard()
			m.attaching = false
			m.width = 120
			m.height = 30
			m.proc.pid = 1111
			m.proc.tid = 2222
			m.dashboard.SetPidFilter(1111)

			next, _ := m.Update(tea.KeyPressMsg{Code: '2', Text: "2"})
			m = next.(*Model)
			next, _ = m.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
			m = next.(*Model)
			if m.router.current() != ScreenPIDPicker || !hasReturn(m) {
				t.Fatalf("expected reselect PID picker with a pending return")
			}
			// Down blurs the filter input, which would otherwise take a
			// typed q as text (see textinput_keys_test.go).
			next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
			m = next.(*Model)

			next, cmd := m.Update(tt.press)
			updated := next.(*Model)
			if cmd == nil {
				t.Fatalf("expected %s in reselect picker to restart tracing", tt.name)
			}
			if isQuitMsg(cmd()) {
				t.Fatalf("expected %s in reselect picker to return, not quit", tt.name)
			}
			if updated.router.current() != ScreenDashboard {
				t.Fatalf("expected dashboard screen after %s cancel, got %v", tt.name, updated.router.current())
			}
			if !updated.attaching {
				t.Fatalf("expected attaching=true after %s cancel", tt.name)
			}
			if updated.quitting {
				t.Fatalf("expected %s in reselect picker to behave like esc, not quit", tt.name)
			}
			if hasReturn(updated) {
				t.Fatalf("expected picker return context to clear after %s cancel", tt.name)
			}
			if updated.proc.pid != 1111 || updated.proc.tid != 2222 {
				t.Fatalf("expected previous pid/tid filters restored, got pid=%d tid=%d", updated.proc.pid, updated.proc.tid)
			}
		})
	}
}

func TestEscOnReselectPIDPickerReturnsToDashboard(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	m.proc.pid = 3333
	m.proc.tid = 4444
	m.dashboard.SetPidFilter(3333)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(*Model)

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: string([]rune{'p'})})
	m = next.(*Model)
	if m.router.current() != ScreenPIDPicker {
		t.Fatalf("expected pid picker screen after reselect, got %v", m.router.current())
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	updated := next.(*Model)
	if cmd == nil {
		t.Fatalf("expected esc in reselect picker to return to dashboard and restart tracing")
	}
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen after esc cancel, got %v", updated.router.current())
	}
	if !updated.attaching {
		t.Fatalf("expected attaching=true after esc cancel")
	}
	if updated.quitting {
		t.Fatalf("expected esc in reselect picker not to quit app")
	}
	if hasReturn(updated) {
		t.Fatalf("expected picker return context to clear after cancel")
	}
	if updated.proc.pid != 3333 || updated.proc.tid != 4444 {
		t.Fatalf("expected previous pid/tid filters restored, got pid=%d tid=%d", updated.proc.pid, updated.proc.tid)
	}
}

func TestQuitKeyClosesProbeModalLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.probeModal = probes.NewModel(fakeProbeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}).Open()

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(*Model)
	if cmd != nil {
		_ = cmd()
	}
	if updated.probeModal.Visible() {
		t.Fatalf("expected q to close probe modal like esc")
	}
	if updated.quitting {
		t.Fatalf("expected q in probe modal not to quit app")
	}
}

func TestQuitKeyClosesExportModalLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.exporter = m.exporter.Open()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(*Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected q to close export modal like esc")
	}
	if updated.quitting {
		t.Fatalf("expected q in export modal not to quit app")
	}
}

// While the flame search input is open a q is typed text (see
// textinput_keys_test.go), so it is Esc - not q - that closes the search.
func TestEscClosesFlameSearch(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: string([]rune{'/'})})
	m = next.(*Model)
	if !strings.Contains(m.View().Content, "0/0 matches") {
		t.Fatalf("expected flame search footer to open on /")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)
	if cmd != nil {
		t.Fatalf("expected esc in flame search to close search, not quit")
	}
	if m.quitting {
		t.Fatalf("expected esc in flame search not to set quitting state")
	}
	if strings.Contains(m.View().Content, "0/0 matches") {
		t.Fatalf("expected esc to close flame search")
	}
}

// fakeDashboardSource is a runtime.ResettableSnapshotSource test double. Reset
// counts calls and swaps in an empty snapshot, mimicking a stats engine that
// restarts its baseline.
type fakeDashboardSource struct {
	snap       *statsengine.Snapshot
	resetCalls int
	// err, when set, makes Snapshot fail.
	err error
}

func (f *fakeDashboardSource) Snapshot() (*statsengine.Snapshot, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.snap, nil
}

func (f *fakeDashboardSource) Reset() {
	f.resetCalls++
	f.snap = &statsengine.Snapshot{TotalSyscalls: 0}
}

func TestDashboardRefreshPicksLateBoundSource(t *testing.T) {
	runtime := newRuntimeBindings()
	source := lateBoundDashboardSource{runtime: runtime}

	want := &statsengine.Snapshot{TotalSyscalls: 77}
	runtime.setDashboardSnapshotSource(&fakeDashboardSource{snap: want})

	got, err := source.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if got != want {
		t.Fatalf("expected late-bound source to use latest runtime source")
	}
}

func TestLateBoundDashboardSourceResetForwardsToWiredSource(t *testing.T) {
	runtime := newRuntimeBindings()
	source := lateBoundDashboardSource{runtime: runtime}
	wired := &fakeDashboardSource{snap: &statsengine.Snapshot{TotalSyscalls: 42}}
	runtime.setDashboardSnapshotSource(wired)

	source.Reset()

	if wired.resetCalls != 1 {
		t.Fatalf("expected Reset to reach the wired source once, got %d", wired.resetCalls)
	}
	got, err := source.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if got == nil || got.TotalSyscalls != 0 {
		t.Fatalf("expected post-reset snapshot from wired source, got %+v", got)
	}
}

// TestLateBoundDashboardSourceWithoutSourceIsInert covers the window before
// the trace starter wires a stats engine (and a zero-value wrapper): Reset
// and Snapshot must neither panic nor fabricate data.
func TestLateBoundDashboardSourceWithoutSourceIsInert(t *testing.T) {
	for name, source := range map[string]lateBoundDashboardSource{
		"nil runtime":     {},
		"no wired source": {runtime: newRuntimeBindings()},
	} {
		t.Run(name, func(t *testing.T) {
			source.Reset()
			got, err := source.Snapshot()
			if err != nil || got != nil {
				t.Fatalf("expected (nil, nil) without a source, got (%+v, %v)", got, err)
			}
		})
	}
}

func TestRuntimeBindingsStoreAndExposeLiveTrie(t *testing.T) {
	runtime := newRuntimeBindings()
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	runtime.setLiveTrie(trie)
	if got := runtime.liveTrie(); got != trie {
		t.Fatalf("expected live trie to be stored and returned")
	}

	runtime.setLiveTrie(nil)
	if got := runtime.liveTrie(); got != nil {
		t.Fatalf("expected live trie to clear on nil assignment")
	}
}

func TestRuntimeBindingsProvidePersistentStreamBuffer(t *testing.T) {
	runtime := newRuntimeBindings()
	buffer := requireTestStreamSink(t, runtime.StreamBuffer())
	if buffer == nil {
		t.Fatalf("expected persistent stream buffer")
	}
	if got := runtime.eventStreamSource(); got != buffer {
		t.Fatalf("expected runtime stream source to default to persistent buffer")
	}

	buffer.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read"})
	if buffer.Len() != 1 {
		t.Fatalf("expected pushed event in persistent buffer")
	}

	runtime.resetStreamBuffer()
	if buffer.Len() != 0 {
		t.Fatalf("expected resetStreamBuffer to clear existing buffer contents")
	}
	if got := runtime.eventStreamSource(); got != buffer {
		t.Fatalf("expected resetStreamBuffer to preserve the same buffer source")
	}
}

func TestRuntimeBindingsProvidePersistentRecorderAndSequencer(t *testing.T) {
	runtime := newRuntimeBindings()

	recorder := runtime.Recorder()
	if recorder == nil {
		t.Fatalf("expected persistent recorder")
	}
	if got := runtime.Recorder(); got != recorder {
		t.Fatalf("expected recorder pointer to remain stable")
	}

	seq := runtime.StreamSequencer()
	if seq == nil {
		t.Fatalf("expected persistent stream sequencer")
	}
	if got := seq.Next(); got != 1 {
		t.Fatalf("first persistent sequence = %d, want 1", got)
	}
	if got := runtime.StreamSequencer().Next(); got != 2 {
		t.Fatalf("second persistent sequence = %d, want 2", got)
	}
}

func TestProbeToggledMsgResetsDashboardStatsSource(t *testing.T) {
	src := &fakeDashboardSource{snap: &statsengine.Snapshot{TotalSyscalls: 99}}

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.runtime.setDashboardSnapshotSource(src)
	m.router.showDashboard()
	m.attaching = false
	m.probeModal = probes.NewModel(fakeProbeManager{states: []probemanager.ProbeState{{Syscall: "read", Active: true}}}).Open()

	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read"})
	updated := next.(*Model)

	if src.resetCalls != 1 {
		t.Fatalf("expected one reset call, got %d", src.resetCalls)
	}
	snap := updated.dashboard.LatestSnapshot()
	if snap == nil || snap.TotalSyscalls != 0 {
		t.Fatalf("expected dashboard snapshot refreshed from reset source, got %+v", snap)
	}
}

// TestProbeToggledMsgKeepsLastGoodSnapshotOnFailure mirrors the dashboard's
// refresh/reset behaviour for the probe-toggle path: the source is reset, but
// a failing post-reset Snapshot must not replace the last good snapshot.
func TestProbeToggledMsgKeepsLastGoodSnapshotOnFailure(t *testing.T) {
	good := &statsengine.Snapshot{TotalSyscalls: 99}
	src := &fakeDashboardSource{snap: good, err: errors.New("snapshot build failed")}

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.runtime.setDashboardSnapshotSource(src)
	m.router.showDashboard()
	m.attaching = false
	m.probeModal = probes.NewModel(fakeProbeManager{states: []probemanager.ProbeState{{Syscall: "read", Active: true}}}).Open()
	next, _ := m.Update(messages.StatsTickMsg{Snap: good})
	m = next.(*Model)
	if got := m.dashboard.LatestSnapshot(); got != good {
		t.Fatalf("precondition: expected seeded snapshot, got %+v", got)
	}

	next, _ = m.Update(probes.ProbeToggledMsg{Syscall: "read"})
	updated := next.(*Model)

	if src.resetCalls != 1 {
		t.Fatalf("expected one reset call, got %d", src.resetCalls)
	}
	if got := updated.dashboard.LatestSnapshot(); got != good {
		t.Fatalf("expected last good snapshot to survive a failed post-toggle snapshot, got %+v", got)
	}
}

func TestTracingStartedRebindsEventStreamSource(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "proc", PID: 1, TID: 1})

	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	m.runtime.setEventStreamSource(rb)
	m.router.showDashboard()
	m.attaching = true

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(*Model)

	next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(*Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(*Model)

	if !strings.Contains(m.View().Content, "read") {
		t.Fatalf("expected stream tab to render rebound stream event")
	}
}

func TestGlobalFilterApplyPreservesBufferedStreamRowsAcrossRestart(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	buffer := requireTestStreamSink(t, m.runtime.StreamBuffer())
	buffer.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "proc", PID: 1, TID: 1, FileName: "/tmp/read"})
	buffer.Push(eventstream.StreamEvent{Seq: 2, Syscall: "write", Comm: "proc", PID: 1, TID: 2, FileName: "/tmp/write"})
	m.dashboard.SetStreamSource(buffer)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(*Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(*Model)
	initial := m.View().Content
	if !strings.Contains(initial, "read") || !strings.Contains(initial, "write") {
		t.Fatalf("expected initial stream view to show buffered rows, got %q", initial)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if buffer.Len() != 2 {
		t.Fatalf("expected filter apply not to clear persistent stream buffer")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}

	next, _ = m.Update(TracingStartedMsg{})
	m = next.(*Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(*Model)

	view := m.View().Content
	if !strings.Contains(view, "read") {
		t.Fatalf("expected matching historical row to remain visible, got %q", view)
	}
	if strings.Contains(view, "write") {
		t.Fatalf("expected non-matching historical row to be hidden after refilter, got %q", view)
	}
}

func TestGlobalFilterApplyAdvancesRuntimeFilterEpochAndKeepsRecorder(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	initialRecorder := m.runtime.Recorder()
	if initialRecorder == nil {
		t.Fatalf("expected runtime recorder")
	}
	if got := m.runtime.FilterEpoch(); got != 0 {
		t.Fatalf("initial filter epoch = %d, want 0", got)
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if got := m.runtime.FilterEpoch(); got != 1 {
		t.Fatalf("filter epoch after apply = %d, want 1", got)
	}
	if got := m.runtime.Recorder(); got != initialRecorder {
		t.Fatalf("expected runtime recorder to survive filter restart")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}
}

func TestTracingStartedUsesCurrentViewportForFlameNavigationWithoutResize(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = true
	m.width = 120
	m.height = 30
	m.runtime.setLiveTrie(trie)

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(*Model)

	if strings.Contains(m.View().Content, "sel:none") {
		t.Fatalf("expected flamegraph selection to be available immediately after tracing start")
	}

	selectedLabel := func(view string) string {
		re := regexp.MustCompile(`sel:[0-9]+/[0-9]+ ([^|]+) \|`)
		match := re.FindStringSubmatch(view)
		if len(match) != 2 {
			return ""
		}
		return strings.TrimSpace(match[1])
	}

	moved := false
	before := selectedLabel(m.View().Content)
	for i := 0; i < 12 && !moved; i++ {
		next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
		m = next.(*Model)
		after := selectedLabel(m.View().Content)
		if after != "" && after != before {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatalf("expected arrow navigation to move selection without requiring resize, view=%q", m.View().Content)
	}
}

func TestTracingStartedAppliesViewportWhenModelSizeIsUnset(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = true
	m.runtime.setLiveTrie(trie)
	m.width = 0
	m.height = 0

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(*Model)

	view := m.View().Content
	if strings.Contains(view, "sel:none") {
		t.Fatalf("expected tracing start to apply an effective viewport even when width/height are unset")
	}
}

func TestExportKeyOpensModalOnDashboard(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(*Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open on e key")
	}
}

// The e export snapshots the live ring even while the stream tab is paused, so
// a user looking at the frozen table would get different rows than shown. The
// modal must say so (and name x as the way to write the paused rows) only while
// paused; a live stream keeps the plain wording (task 2r2).
func TestExportModalWarnsWhenStreamPaused(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "write", Comm: "proc", PID: 1, FD: 3})
	m.dashboard.SetStreamSource(rb)

	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: "7"})
	m = next.(*Model)

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: "e"})
	m = next.(*Model)
	if !m.exporter.Visible() {
		t.Fatalf("expected the e modal to open")
	}
	if live := m.exporter.View(120, 30); strings.Contains(live, "paused") {
		t.Fatalf("live stream: modal must not mention the paused view:\n%s", live)
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)
	if !m.dashboard.StreamPaused() {
		t.Fatalf("expected space to pause the stream tab")
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: "e"})
	m = next.(*Model)
	paused := strings.Join(strings.Fields(strings.ReplaceAll(m.exporter.View(120, 30), "│", " ")), " ")
	if !strings.Contains(paused, "Live ring, not the paused view - use x on the Stream tab for the paused rows") {
		t.Fatalf("paused stream: modal lacks the live-ring warning:\n%s", paused)
	}
}

func TestRecordKeyOpensRecordingModalOnDashboard(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'R'}[0], Text: "R"})
	updated := next.(*Model)
	if !updated.recordModal.Visible() {
		t.Fatalf("expected recording modal to open on R key")
	}
}

func TestRecordModalSubmitStartsRecording(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	path := filepath.Join(t.TempDir(), "capture.parquet")
	m.recordModal = m.recordModal.Open(path)

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	updated := next.(*Model)
	if updated.recordModal.Visible() {
		t.Fatalf("expected recording modal to close after submit")
	}
	status := updated.runtime.Recorder().Status()
	if !status.Active {
		t.Fatalf("expected recorder to be active after modal submit")
	}
	t.Cleanup(func() {
		if err := updated.stopRecording(); err != nil {
			t.Fatalf("stopRecording() cleanup error = %v", err)
		}
	})
	if status.Path != path {
		t.Fatalf("recording path = %q, want %q", status.Path, path)
	}
}

func TestRecordModalRejectsBlankFilename(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.recordModal = m.recordModal.Open("   ")

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	updated := next.(*Model)
	if !updated.recordModal.Visible() {
		t.Fatalf("expected recording modal to stay open on blank filename")
	}
	if updated.runtime.Recorder().Status().Active {
		t.Fatalf("expected blank filename submit not to start recorder")
	}
	if !strings.Contains(updated.recordModal.View(120, 30), "filename is required") {
		t.Fatalf("expected blank filename error to be visible")
	}
}

func TestStartRecordingUpdatesDashboardStatus(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	path := filepath.Join(t.TempDir(), "capture.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}
	t.Cleanup(func() {
		if err := m.stopRecording(); err != nil {
			t.Fatalf("stopRecording() cleanup error = %v", err)
		}
	})

	status := m.runtime.Recorder().Status()
	if !status.Active {
		t.Fatalf("expected recorder to be active after startRecording()")
	}

	view := m.View().Content
	if !strings.Contains(view, "rec:") || !strings.Contains(view, "capture") {
		t.Fatalf("expected dashboard view to show recording status, got %q", view)
	}
}

func TestRecordKeyStopsActiveRecording(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	path := filepath.Join(t.TempDir(), "capture.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'R'}[0], Text: "R"})
	updated := next.(*Model)
	if updated.runtime.Recorder().Status().Active {
		t.Fatalf("expected R key to stop active recording")
	}
}

func TestQuitStopsActiveRecording(t *testing.T) {
	for _, attaching := range []bool{false, true} {
		t.Run(fmt.Sprintf("attaching=%t", attaching), func(t *testing.T) {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			m.router.showDashboard()
			m.attaching = attaching

			path := filepath.Join(t.TempDir(), "capture.parquet")
			if err := m.startRecording(path); err != nil {
				t.Fatalf("startRecording() error = %v", err)
			}

			next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: "q"})
			updated := next.(*Model)
			if cmd == nil {
				t.Fatalf("expected quit command")
			}
			if updated.runtime.Recorder().Status().Active {
				t.Fatalf("expected quit to stop active recording")
			}
		})
	}
}

func TestSelectPIDStopsActiveRecording(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	path := filepath.Join(t.TempDir(), "capture.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	updated := next.(*Model)
	if cmd == nil {
		t.Fatalf("expected picker init command")
	}
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected p to switch to pid picker, got %v", updated.router.current())
	}
	if updated.runtime.Recorder().Status().Active {
		t.Fatalf("expected pid reselect to stop active recording")
	}
}

func TestGlobalFilterApplyKeepsActiveRecordingAcrossRestart(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	path := filepath.Join(t.TempDir(), "capture.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}
	t.Cleanup(func() {
		if err := m.stopRecording(); err != nil {
			t.Fatalf("stopRecording() cleanup error = %v", err)
		}
	})

	initialRecorder := m.runtime.Recorder()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if got := m.runtime.FilterEpoch(); got != 1 {
		t.Fatalf("filter epoch after apply = %d, want 1", got)
	}
	if got := m.runtime.Recorder(); got != initialRecorder {
		t.Fatalf("expected runtime recorder to survive filter restart")
	}
	if !m.runtime.Recorder().Status().Active {
		t.Fatalf("expected active recording to survive filter restart")
	}
}

func TestFlamePauseKeyDoesNotTriggerPIDReselect(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(*Model)
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("expected flame space key to keep dashboard screen, got %v", updated.router.current())
	}
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected flame space key to toggle flame paused state")
	}
}

func TestFlamePIDShortcutOpensPIDPickerInsteadOfPausing(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	updated := next.(*Model)
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected p to open PID picker from flame tab, got %v", updated.router.current())
	}
	if strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected p not to pause flame tab")
	}
	if cmd == nil {
		t.Fatalf("expected picker init command on p")
	}
}

func TestFlameSpaceKeyReleaseFallbackTogglesPause(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(*Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release fallback to toggle flame paused state")
	}
}

func TestFlameSpacePressReleaseDoesNotDoubleTogglePause(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(*Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key press to pause flame")
	}

	next, _ = updated.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated = next.(*Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release after key press to be ignored as duplicate")
	}
}

func TestFlameSpaceReleasePressDoesNotDoubleTogglePause(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(*Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release fallback to pause flame")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated = next.(*Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected immediate matching key press after release fallback to be ignored")
	}
}

func TestNormalizeKeyEventReleaseFallbackSuppressesImmediatePressOnly(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	if !ok {
		t.Fatalf("expected release fallback to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected release fallback to normalize to KeyPressMsg, got %T", normalized)
	}

	if normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}); ok {
		t.Fatalf("expected immediate matching press to be suppressed, got %T", normalized)
	}

	// Expire suppression deterministically instead of waiting on wall clock time.
	m.kb.suppressUntil = time.Now().Add(-time.Nanosecond)
	if normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}); !ok {
		t.Fatalf("expected press to be accepted after suppression window")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected accepted message to be KeyPressMsg, got %T", normalized)
	}
}

func TestNormalizeKeyEventIgnoresUnidentifiedRelease(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	if normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{}); ok {
		t.Fatalf("expected unidentified release to be ignored, got %T", normalized)
	}

	normalized, ok := m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if !ok {
		t.Fatalf("expected subsequent real key press to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected normalized message to be KeyPressMsg, got %T", normalized)
	}
}

func TestNormalizeKeyEventReleaseFallbackDoesNotSuppressArrowPress(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{Code: tea.KeyRight})
	if !ok {
		t.Fatalf("expected right release fallback to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected release fallback to normalize to KeyPressMsg, got %T", normalized)
	}

	normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeyRight})
	if !ok {
		t.Fatalf("expected right key press to be accepted after release fallback")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected normalized message to be KeyPressMsg, got %T", normalized)
	}
}

func TestFlameOrderKeyDoesNotOpenProbeModal(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'o'}[0], Text: string([]rune{'o'})})
	updated := next.(*Model)
	if updated.probeModal.Visible() {
		t.Fatalf("expected flame order key to stay in flame tab, not open probes modal")
	}
}

func TestFlameMetricKeyDoesNotOpenProbeModal(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'b'}[0], Text: string([]rune{'b'})})
	updated := next.(*Model)
	if updated.probeModal.Visible() {
		t.Fatalf("expected flame metric key to stay in flame tab, not open probes modal")
	}
}

func TestSelectPIDKeyReturnsToFreshPickerAndStopsTrace(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: string([]rune{'p'})})
	updated := next.(*Model)

	if !stopped {
		t.Fatalf("expected active tracing to be stopped before returning to picker")
	}
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected PID picker screen, got %v", updated.router.current())
	}
	if updated.attaching {
		t.Fatalf("expected attaching=false on picker screen")
	}
	if updated.tracer.traceStop != nil {
		t.Fatalf("expected traceStop to be cleared after stopping")
	}
	if cmd == nil {
		t.Fatalf("expected picker init command when returning to picker")
	}
}

func TestPidSelectedClearsPersistentStreamBuffer(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	requireTestStreamSink(t, m.runtime.StreamBuffer()).Push(eventstream.StreamEvent{Seq: 1, Syscall: "read"})

	next, _ := m.Update(PidSelectedMsg{Pid: 42})
	m = next.(*Model)

	if got := m.runtime.StreamBuffer().Len(); got != 0 {
		t.Fatalf("expected pid reselection to clear persistent stream buffer, got len=%d", got)
	}
}

func TestSelectTIDKeyReturnsToPickerWhenPIDFilterIsAll(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'t'}[0], Text: string([]rune{'t'})})
	updated := next.(*Model)
	if !stopped {
		t.Fatalf("expected tracing stop before tid reselect")
	}
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected picker screen, got %v", updated.router.current())
	}
	if cmd == nil {
		t.Fatalf("expected picker init command")
	}
}

func TestSelectTIDKeyReturnsToPickerWhenSinglePIDSelected(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter = 1234
	m := NewModelWithConfig(cfg, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'t'}[0], Text: string([]rune{'t'})})
	updated := next.(*Model)
	if !stopped {
		t.Fatalf("expected tracing stop before tid reselect")
	}
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected picker screen, got %v", updated.router.current())
	}
	if cmd == nil {
		t.Fatalf("expected picker init command")
	}
}

func TestTidSelectedTransitionsToDashboardAndSetsTIDFilter(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter = 2222
	m := NewModelWithConfig(cfg, -1, func(context.Context, TraceRequest) error { return nil })

	next, cmd := m.Update(TidSelectedMsg{Pid: 0, Tid: 3333})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}
	updated := next.(*Model)
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.router.current())
	}
	if !updated.attaching {
		t.Fatalf("expected attaching state to be true")
	}
	if updated.proc.tid != 3333 {
		t.Fatalf("expected tid filter 3333, got %d", updated.proc.tid)
	}
	if updated.proc.pid != 2222 {
		t.Fatalf("expected pid filter to remain 2222, got %d", updated.proc.pid)
	}
}

func TestTidSelectedFromAllPIDModeSetsOwningPID(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	next, cmd := m.Update(TidSelectedMsg{Pid: 4444, Tid: 5555})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}
	updated := next.(*Model)
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.router.current())
	}
	if updated.proc.pid != 4444 {
		t.Fatalf("expected pid filter switched to owning pid 4444, got %d", updated.proc.pid)
	}
	if updated.proc.tid != 5555 {
		t.Fatalf("expected tid filter 5555, got %d", updated.proc.tid)
	}
}

func TestExportKeyIgnoredWhenExportDisabled(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.TUIExportEnable = false
	m := NewModelWithConfig(cfg, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(*Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected export modal to remain closed when export is disabled")
	}
}

func TestStreamFilterModalConsumesEKeyInsteadOfOpeningExport(t *testing.T) {

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	for _, r := range []rune{'o', 'p', 'e'} {
		next, _ = m.Update(tea.KeyPressMsg{Code: []rune{r}[0], Text: string([]rune{r})})
		m = next.(*Model)
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if m.exporter.Visible() {
		t.Fatalf("expected export modal to remain closed while stream filter modal handles typing")
	}
	if m.filters.global.Syscall == nil || m.filters.global.Syscall.Pattern != "ope" {
		t.Fatalf("expected typed syscall filter to be stored globally, got %+v", m.filters.global.Syscall)
	}
}

func TestRunExportCmdCSVWritesFilteredStreamSnapshot(t *testing.T) {
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	buffer := requireTestStreamSink(t, m.runtime.StreamBuffer())
	buffer.Push(eventstream.StreamEvent{Seq: 1, Comm: "firefox", PID: 10, TID: 100, Syscall: "read", FileName: "/tmp/a"})
	buffer.Push(eventstream.StreamEvent{Seq: 2, Comm: "bash", PID: 11, TID: 110, Syscall: "write", FileName: "/tmp/b"})
	m.setGlobalFilter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "firefox"}})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{}})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: "7"})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)

	buffer.Push(eventstream.StreamEvent{Seq: 3, Comm: "firefox", PID: 12, TID: 120, Syscall: "open", FileName: "/tmp/c"})
	next, _ = m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{}})
	m = next.(*Model)

	source, filter, exportDir := m.dashboard.ExportStreamCSVInputs()
	msg := runExportCmd(true, tuiexport.OptionCSV, source, filter, exportDir)()
	done, ok := msg.(tuiexport.CompletedMsg)
	if !ok {
		t.Fatalf("expected CompletedMsg, got %T", msg)
	}
	if done.Path == "" {
		t.Fatalf("expected export path")
	}
	if _, err := os.Stat(done.Path); err != nil {
		t.Fatalf("expected CSV file to exist: %v", err)
	}
	f, err := os.Open(done.Path)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header + 2 filtered rows, got %d records", len(records))
	}
	if records[1][0] != "1" || records[2][0] != "3" {
		t.Fatalf("expected fresh filtered stream snapshot rows 1 and 3, got %v", records[1:])
	}
	if records[1][4] != "firefox" || records[2][4] != "firefox" {
		t.Fatalf("expected firefox rows only, got %v", records[1:])
	}
}

func TestHelpKeyDoesNotToggleOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'?'}[0], Text: string([]rune{'?'})})
	updated := next.(*Model)
	if updated.router.current() != ScreenPIDPicker {
		t.Fatalf("expected ? to have no effect, got screen %v", updated.router.current())
	}
}

func TestViewShowsDashboardWithoutHelpOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.width = 100
	m.height = 30

	out := m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected bottom help hint in dashboard")
	}
}

func TestHelpOverlayOpensWithUppercaseHAndClosesWithEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 100
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(*Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to become visible after H")
	}
	view := m.View().Content
	if !strings.Contains(view, "Help") || !strings.Contains(view, "Global") || !strings.Contains(view, "Esc/q close") {
		t.Fatalf("expected global help overlay content, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)
	if m.helpOverlayVisible {
		t.Fatalf("expected esc to close help overlay")
	}
	if !strings.Contains(m.View().Content, "press H for help") {
		t.Fatalf("expected dashboard help hint after closing overlay")
	}
}

func TestHelpOverlayClosesWithQWithoutQuitting(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 100
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(*Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to become visible after H")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	m = next.(*Model)
	if cmd != nil {
		t.Fatalf("expected no quit command when closing help with q")
	}
	if m.helpOverlayVisible {
		t.Fatalf("expected q to close help overlay")
	}
	if m.quitting {
		t.Fatalf("expected q in help overlay not to set quitting state")
	}
}

func TestHelpOverlayCanOpenFromPIDPicker(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router = newScreenRouter(ScreenPIDPicker)
	m.width = 100
	m.height = 30

	// The picker's filter input starts focused and would take an H as text
	// (see textinput_keys_test.go); Down moves the selection off it, which is
	// when H is the help shortcut again.
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(*Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to open on pid picker screen")
	}
	if !strings.Contains(m.View().Content, "PID/TID Picker") {
		t.Fatalf("expected picker shortcuts in help overlay")
	}
}

func TestGlobalFilterModalOpensFromDashboardShortcut(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to open on f")
	}
}

func TestQuitClosesGlobalFilterModalWithoutQuitting(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.filterModal = m.filterModal.Open(m.filters.global)

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	m = next.(*Model)
	if cmd != nil {
		t.Fatalf("expected no quit command while closing filter modal")
	}
	if m.filterModal.Visible() {
		t.Fatalf("expected q to close global filter modal")
	}
	if m.quitting {
		t.Fatalf("expected q in filter modal not to set quitting state")
	}
}

func TestGlobalFilterModalUpdatesStoredFilterState(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to open")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to close after esc")
	}
	if m.filters.global.Syscall == nil || m.filters.global.Syscall.Pattern != "read" {
		t.Fatalf("expected stored global filter updated from modal, got %+v", m.filters.global.Syscall)
	}
	if !stopped {
		t.Fatalf("expected filter apply to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}
}

func TestGlobalFilterCloseWithoutChangesDoesNotRestartTrace(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected filter modal to open")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if cmd != nil {
		t.Fatalf("expected no restart command when filter is unchanged")
	}
	if stopped {
		t.Fatalf("expected unchanged filter close not to stop tracing")
	}
	if m.attaching {
		t.Fatalf("expected unchanged filter close not to restart tracing")
	}
}

func TestPausedStreamEnterAppliesSelectedCellAsGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{
		Seq:        1,
		Syscall:    "write",
		Comm:       "systemd",
		PID:        3655,
		TID:        4862,
		FileName:   "/var/lib/clickhouse/data",
		DurationNs: 1234,
		GapNs:      44,
		FD:         20,
	})
	m.dashboard.SetStreamSource(rb)

	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on paused stream selection to emit a global filter request")
	}

	next, cmd = m.Update(cmd())
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected applying selected-cell global filter to restart tracing")
	}
	if m.filters.global.Comm == nil || m.filters.global.Comm.Pattern != "^systemd$" {
		t.Fatalf("expected selected comm applied globally, got %+v", m.filters.global.Comm)
	}
	if !stopped {
		t.Fatalf("expected selected-cell global filter to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected selected-cell global filter to restart tracing")
	}
	if len(m.filters.stack) != 1 || m.filters.stack[0] != "comm~^systemd$" {
		t.Fatalf("expected selected-cell action pushed to filter stack, got %+v", m.filters.stack)
	}
}

func TestGlobalFilterUndoKeyPopsLatestStackEntry(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	m.attaching = false
	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'F'}[0], Text: string([]rune{'F'})})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected F to trigger global filter undo")
	}
	if m.filters.global.IsActive() {
		t.Fatalf("expected undo to restore the previous all-filter state, got %+v", m.filters.global)
	}
	if len(m.filters.stack) != 0 || len(m.filters.history) != 0 {
		t.Fatalf("expected filter stack/history cleared after undo, got stack=%+v history=%d", m.filters.stack, len(m.filters.history))
	}
	if !stopped {
		t.Fatalf("expected undo to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected undo to restart tracing")
	}
}

func TestPausedStreamEscUndoesLatestGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "systemd", PID: 1, TID: 2})
	m.dashboard.SetStreamSource(rb)
	m.attaching = false
	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected esc in paused stream to undo one global filter layer")
	}
	next, cmd = m.Update(cmd())
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected esc undo to restart tracing")
	}
	if m.filters.global.IsActive() {
		t.Fatalf("expected esc undo to restore all-filter state, got %+v", m.filters.global)
	}
	if len(m.filters.stack) != 0 {
		t.Fatalf("expected filter stack cleared after esc undo, got %+v", m.filters.stack)
	}
	if !stopped {
		t.Fatalf("expected esc undo to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected esc undo to restart tracing")
	}
}

func TestDashboardFooterShowsGlobalFilterStack(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 140
	m.height = 35

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	m.attaching = false
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(*Model)

	view := m.View().Content
	for _, want := range []string{"filter: syscall~read", "stack: syscall~read"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected dashboard footer to show %q\n%s", want, view)
		}
	}
}

func TestFilterStackHistoryCapEvictsOldestEntries(t *testing.T) {
	// Push maxFilterHistory+10 distinct filters and verify the slices never
	// exceed the cap. The oldest entries must be evicted, and the most-recent
	// maxFilterHistory entries must be retained.
	fs := newFilterStack(globalfilter.Filter{})
	for i := 0; i < maxFilterHistory+10; i++ {
		f := globalfilter.Filter{}
		f.FD = globalfilter.NewEqFilter(int64(i + 1)) // unique per iteration
		fs.push(f, "")
	}
	if len(fs.history) > maxFilterHistory {
		t.Fatalf("history exceeds cap: got %d, want <= %d", len(fs.history), maxFilterHistory)
	}
	if len(fs.stack) > maxFilterHistory {
		t.Fatalf("stack exceeds cap: got %d, want <= %d", len(fs.stack), maxFilterHistory)
	}
	if len(fs.history) != len(fs.stack) {
		t.Fatalf("history and stack lengths must match: history=%d stack=%d", len(fs.history), len(fs.stack))
	}
}

func TestProcessesTabEnterAppliesSelectedProcessAsGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.tracer.traceStop = func() { stopped = true }

	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 111, Comm: "alpha", Syscalls: 9},
		{PID: 222, Comm: "beta", Syscalls: 4},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &snap})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'5'}[0], Text: string([]rune{'5'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	m = next.(*Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on processes tab to emit a filter request")
	}

	next, cmd = m.Update(cmd())
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected selected process filter to restart tracing")
	}
	if m.filters.global.PID == nil || m.filters.global.PID.Value != 222 {
		t.Fatalf("expected selected process pid applied globally, got %+v", m.filters.global.PID)
	}
	if len(m.filters.stack) != 1 || m.filters.stack[0] != "pid=222" {
		t.Fatalf("expected pid filter pushed to stack, got %+v", m.filters.stack)
	}
	if !stopped {
		t.Fatalf("expected selected process filter to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected selected process filter to restart tracing")
	}
}

func TestGlobalFilterApplyPreservesActiveDashboardTab(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(*Model)
	if m.dashboard.ActiveTab() != dashboardui.TabFiles {
		t.Fatalf("expected files tab active before filter apply")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("log")[0], Text: string([]rune("log"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if m.dashboard.ActiveTab() != dashboardui.TabFiles {
		t.Fatalf("expected active tab preserved across filter restart")
	}
	if !m.attaching {
		t.Fatalf("expected apply to enter attaching state")
	}
}

func TestGlobalFilterApplyResetsAggregatesAndFlameToPostRestartSources(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 140
	m.height = 36

	oldSnap := aggregateTestSnapshot("write", "/tmp/old.log", "oldproc", "old-lat", "old-gap")
	newSnap := aggregateTestSnapshot("read", "/tmp/new.log", "newproc", "new-lat", "new-gap")
	oldTrie := aggregateTestTrie("oldsvc", "/srv/old")
	newTrie := aggregateTestTrie("newsvc", "/srv/new")

	m.runtime.setDashboardSnapshotSource(&fakeDashboardSource{snap: oldSnap})
	m.runtime.setLiveTrie(oldTrie)

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(*Model)
	next, _ = m.Update(messages.StatsTickMsg{Snap: oldSnap})
	m = next.(*Model)

	if label := advanceFlameSelection(t, m); !strings.Contains(label, "oldsvc") {
		t.Fatalf("expected old flame data before filter apply, got %q", label)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(*Model)

	if got := m.dashboard.LatestSnapshot(); got != nil {
		t.Fatalf("expected aggregate snapshot cleared during restart, got %+v", got)
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}

	m.runtime.setDashboardSnapshotSource(&fakeDashboardSource{snap: newSnap})
	m.runtime.setLiveTrie(newTrie)

	next, _ = m.Update(TracingStartedMsg{})
	m = next.(*Model)
	next, _ = m.Update(messages.StatsTickMsg{Snap: newSnap})
	m = next.(*Model)

	if label := advanceFlameSelection(t, m); !strings.Contains(label, "newsvc") || strings.Contains(label, "oldsvc") {
		t.Fatalf("expected flamegraph to reflect only new trie data, got %q", label)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(*Model)
	overview := m.View().Content
	for _, want := range []string{"read(1)", "/tmp/new.log(2)", "newproc/42(1)", "new-lat", "new-gap"} {
		if !strings.Contains(overview, want) {
			t.Fatalf("expected overview to contain %q, got %q", want, overview)
		}
	}
	for _, unwanted := range []string{"write", "/tmp/old.log", "oldproc", "old-lat", "old-gap"} {
		if strings.Contains(overview, unwanted) {
			t.Fatalf("expected overview to drop pre-filter data %q, got %q", unwanted, overview)
		}
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'3'}[0], Text: string([]rune{'3'})})
	m = next.(*Model)
	if view := m.View().Content; !strings.Contains(view, "read") || strings.Contains(view, "write") {
		t.Fatalf("expected syscalls view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(*Model)
	if view := m.View().Content; !strings.Contains(view, "/tmp/new.log") || strings.Contains(view, "/tmp/old.log") {
		t.Fatalf("expected files view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'5'}[0], Text: string([]rune{'5'})})
	m = next.(*Model)
	if view := m.View().Content; !strings.Contains(view, "newproc") || strings.Contains(view, "oldproc") {
		t.Fatalf("expected processes view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'6'}[0], Text: string([]rune{'6'})})
	m = next.(*Model)
	if view := m.View().Content; !strings.Contains(view, "new-lat") || !strings.Contains(view, "new-gap") || strings.Contains(view, "old-lat") || strings.Contains(view, "old-gap") {
		t.Fatalf("expected latency view to reflect post-filter histogram only, got %q", view)
	}
}

func TestQuestionMarkDoesNotBlockUnderlyingActions(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(*Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open; ? overlay is removed")
	}
}

func aggregateTestSnapshot(syscall, path, comm, latencyLabel, gapLabel string) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(
		[]float64{111},
		[]float64{222},
		[]float64{333},
		[]statsengine.SyscallSnapshot{{Name: syscall, Count: 1}},
		[]statsengine.FileSnapshot{{Path: path, Accesses: 2}},
		[]statsengine.ProcessSnapshot{{PID: 42, Comm: comm, Syscalls: 1}},
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{{Label: latencyLabel, Count: 1}}),
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{{Label: gapLabel, Count: 1}}),
	)
	snap.TotalSyscalls = 1
	snap.TotalBytes = 64
	snap.LatencyMeanNs = 111
	snap.GapMeanNs = 222
	return &snap
}

func aggregateTestTrie(comm, path string) *coreflamegraph.LiveTrie {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "count")
	trie.AddRecord(coreflamegraph.IterRecord{
		Comm:    comm,
		Path:    path,
		Pid:     42,
		Tid:     42,
		TraceID: types.SYS_ENTER_READ,
		Cnt: coreflamegraph.Counter{
			Count:          5,
			Duration:       5_000,
			DurationToPrev: 500,
			Bytes:          128,
		},
	})
	return trie
}

func selectedFlameLabel(view string) string {
	re := regexp.MustCompile(`sel:[0-9]+/[0-9]+ ([^|]+) \|`)
	match := re.FindStringSubmatch(view)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func advanceFlameSelection(t *testing.T, m *Model) string {
	t.Helper()

	before := selectedFlameLabel(m.View().Content)
	for i := 0; i < 8; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
		m = next.(*Model)
		after := selectedFlameLabel(m.View().Content)
		if after != "" && after != before && after != "root" {
			return after
		}
	}
	return selectedFlameLabel(m.View().Content)
}

func TestQuestionMarkDoesNotBreakExportModalInput(t *testing.T) {

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(*Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: []rune{'?'}[0], Text: string([]rune{'?'})})
	updated = next.(*Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to remain open after ? key")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	updated = next.(*Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected esc to close export modal")
	}
}

// TestExportDisabledHidesHintsAndShortcuts is the real gating test for
// -tuiExport=false: the global help overlay and the dashboard status help
// must not advertise any export shortcut, and the stream export modal must
// stay closed (the vacuous predecessor asserted a hint-mode view that never
// shows the binding in either configuration).
func TestExportDisabledHidesHintsAndShortcuts(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.TUIExportEnable = false
	m := NewModelWithConfig(cfg, -1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.width = 100
	m.height = 30

	disabledOut := m.View().Content
	if strings.Contains(disabledOut, "Exported:") {
		t.Fatalf("did not expect export status when export is disabled")
	}

	// The enabled configuration must still advertise the shortcuts in the
	// same surfaces, so the hiding is attributable to the flag.
	enabled := NewModelWithConfig(flags.NewFlags(), -1, func(context.Context, TraceRequest) error { return nil })
	enabled.router.showDashboard()
	enabled.width = 100
	enabled.height = 30
	enabled.helpOverlayVisible = true
	enabledOut := enabled.View().Content
	if !strings.Contains(enabledOut, "stream: x/X export  E open") {
		t.Fatalf("expected stream export hint in the help overlay when export is enabled")
	}
	if !strings.Contains(enabledOut, "e stream export") {
		t.Fatalf("expected e stream export hint in the help overlay when export is enabled")
	}
	disabledOverlay := m
	disabledOverlay.helpOverlayVisible = true
	disabledOut = disabledOverlay.View().Content
	if strings.Contains(disabledOut, "stream: x/X export") || strings.Contains(disabledOut, "e stream export") {
		t.Fatalf("did not expect export hints in the help overlay when export is disabled")
	}
}

func TestExportModalStillAllowsDashboardStatsUpdates(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.exporter = m.exporter.Open()

	snap := &statsengine.Snapshot{TotalSyscalls: 99}
	next, _ := m.Update(StatsTickMsg{Snap: snap})
	updated := next.(*Model)

	if got := updated.dashboard.LatestSnapshot(); got != snap {
		t.Fatalf("expected dashboard snapshot update while export modal visible")
	}
}

func TestDashboardTabKeysChangeActiveView(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	// Dimensions must flow through Update so that sub-model viewports are
	// kept in sync with the new pure-View contract.
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)

	out := m.View().Content
	if !strings.Contains(out, "Flame: waiting for data") {
		t.Fatalf("expected flame waiting view by default")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	updated := next.(*Model)
	out = updated.View().Content
	if !strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected overview waiting view after pressing 2")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	updated = next.(*Model)
	out = updated.View().Content
	if !strings.Contains(out, "Syscalls: waiting for stats") {
		t.Fatalf("expected syscalls waiting view after tab")
	}
}

func TestProbeModalViewDoesNotStackDashboardContent(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.runtime.setProbeManager(fakeProbeManager{states: []probemanager.ProbeState{{Syscall: "read", Active: true}}})
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager())
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	m.probeModal = m.probeModal.Open()

	out := m.View().Content
	if !strings.Contains(out, "Probes (") {
		t.Fatalf("expected probe modal content, got %q", out)
	}
	if strings.Contains(out, "Flame: waiting for data") || strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected probe modal to render as standalone view, got stacked dashboard content")
	}
}

func TestBlurPausesDashboardRefreshAndFocusResumesIt(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.dashboard = dashboardui.NewModelWithConfig(nil, nil, 1, 200, m.keys)
	m.focused = true

	next, _ := m.Update(tea.BlurMsg{})
	m = next.(*Model)
	if m.focused {
		t.Fatalf("expected focused=false after blur")
	}

	tickMsg := m.dashboard.Init()()
	next, tickCmd := m.Update(tickMsg)
	m = next.(*Model)
	if tickCmd != nil {
		t.Fatalf("expected no follow-up tick command while blurred")
	}

	next, focusCmd := m.Update(tea.FocusMsg{})
	m = next.(*Model)
	if !m.focused {
		t.Fatalf("expected focused=true after focus")
	}
	if focusCmd == nil {
		t.Fatalf("expected focus to resume refresh with a command batch")
	}
	if _, ok := focusCmd().(tea.BatchMsg); !ok {
		t.Fatalf("expected focus command to be a batch")
	}
}

func TestKeyboardEnhancementsMsgHandledGracefully(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	next, cmd := m.Update(tea.KeyboardEnhancementsMsg{Flags: 1})
	if cmd != nil {
		t.Fatalf("expected no command when handling keyboard enhancements msg")
	}

	updated := next.(*Model)
	if !updated.kb.enhancementsKnown {
		t.Fatalf("expected keyboard enhancements to be marked as known")
	}
	if !updated.kb.enhancements.SupportsKeyDisambiguation() {
		t.Fatalf("expected non-zero flags to report key disambiguation support")
	}
}

func TestViewSetsDynamicWindowTitle(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })

	m.router = newScreenRouter(ScreenPIDPicker)
	view := m.View()
	if view.WindowTitle != "ior - select process" {
		t.Fatalf("unexpected picker window title: %q", view.WindowTitle)
	}

	m.router.showDashboard()
	m.proc.pid = 1234
	view = m.View()
	if view.WindowTitle != "ior - tracing PID 1234" {
		t.Fatalf("unexpected tracing window title: %q", view.WindowTitle)
	}

	m.proc.pid = -1
	view = m.View()
	if view.WindowTitle != "ior - I/O Riot" {
		t.Fatalf("unexpected default window title: %q", view.WindowTitle)
	}
}

func TestAltScreenViewEnablesMouseCellMotion(t *testing.T) {
	view := altScreenView("test", "ior")
	if view.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("expected mouse mode cell motion, got %v", view.MouseMode)
	}
}

func TestRenderHelpOverlayUsesWideViewport(t *testing.T) {
	groups := [][]key.Binding{{key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help"))}}
	out := renderHelpOverlay(160, 40, groups)

	maxWidth := 0
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}

	if maxWidth <= 110 {
		t.Fatalf("expected wide help overlay to exceed previous 110-col cap, got %d", maxWidth)
	}
}

func TestGlobalHelpOverlayFitsStandardTerminal(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	out := renderGlobalHelpOverlay(80, 24, m.helpSections())

	lines := strings.Split(out, "\n")
	if len(lines) > 24 {
		t.Fatalf("expected help overlay to fit within 24 lines, got %d", len(lines))
	}

	maxWidth := 0
	for _, line := range lines {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}
	if maxWidth > 80 {
		t.Fatalf("expected help overlay width <= 80, got %d", maxWidth)
	}
	if !strings.Contains(out, "Dashboard Tabs") {
		t.Fatalf("expected overlay to include dashboard help section")
	}
	if !strings.Contains(out, "v bubbles") || !strings.Contains(out, "b metric") {
		t.Fatalf("expected overlay to include bubble dashboard hotkeys")
	}
}

// TestGlobalHelpOverlayKeepsFlameNoteAt80Columns: the probes-key note ("O on
// Flame") used to share a line with the family hint and was cut to "(O on
// Fla..." by the 70-cell help box at 80 columns. The Global section is the
// first thing in the overlay, so each of its lines must appear untruncated
// (other sections may still be cut; they are not this test's concern).
func TestGlobalHelpOverlayKeepsFlameNoteAt80Columns(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	sections := m.helpSections()
	out := renderGlobalHelpOverlay(80, 24, sections)

	for _, line := range sections[0].lines {
		if !strings.Contains(out, line) {
			t.Errorf("global help line cut or missing at 80 columns: %q\n%s", line, out)
		}
	}
	if !strings.Contains(out, "on Flame, o cycles the frame order") {
		t.Fatalf("help overlay lacks the Flame note for O:\n%s", out)
	}
}

// TestGlobalHelpOverlayKeepsNoteAndExportHintAt80x24: at 80x24 the overlay
// keeps only height-4 = 20 lines. A fourth Global line (added for the O note)
// once pushed the last Dashboard Tabs line, "stream: x/X export  E open", out
// of the overlay so the export keys were not documented anywhere. With default
// flags (export enabled) both the Flame/O note and the export hint must show,
// and the Global section must stay at three lines to leave room for them.
func TestGlobalHelpOverlayKeepsNoteAndExportHintAt80x24(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	if !m.keys.ExportEnabled() {
		t.Fatalf("test assumes export is enabled by default")
	}
	sections := m.helpSections()
	out := renderGlobalHelpOverlay(80, 24, sections)

	for _, want := range []string{
		"on Flame, o cycles the frame order",
		"stream: x/X export  E open",
		"e stream export",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help overlay at 80x24 lacks %q:\n%s", want, out)
		}
	}
	if got := len(sections[0].lines); got > 3 {
		t.Errorf("Global help has %d lines, want <= 3 so the export hint fits in 20 lines", got)
	}
}

// TestNextAutoResetIntervalCyclesThroughPresets walks the full preset
// sequence (off -> 10s -> 30s -> 60s -> 2m -> 5m -> off) to lock in the
// user-facing behavior of the `I` hotkey. The cycle wraps so the user
// can press `I` repeatedly without overshooting into surprise states.
func TestNextAutoResetIntervalCyclesThroughPresets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"off->10s", 0, 10 * time.Second},
		{"10s->30s", 10 * time.Second, 30 * time.Second},
		{"30s->60s", 30 * time.Second, 60 * time.Second},
		{"60s->2m", 60 * time.Second, 2 * time.Minute},
		{"2m->5m", 2 * time.Minute, 5 * time.Minute},
		{"5m->off", 5 * time.Minute, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := nextAutoResetInterval(tc.in)
			if got != tc.want {
				t.Fatalf("nextAutoResetInterval(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestNextAutoResetIntervalAdvancesCustomValueToNextPreset covers the
// custom-value passthrough: when the user passes a -resetTimer value
// that is not in the preset cycle (e.g. 47s), pressing `I` should jump
// to the smallest preset strictly greater than the current cadence
// rather than restarting from the top of the cycle.
func TestNextAutoResetIntervalAdvancesCustomValueToNextPreset(t *testing.T) {
	t.Parallel()
	if got := nextAutoResetInterval(47 * time.Second); got != 60*time.Second {
		t.Fatalf("nextAutoResetInterval(47s) = %s, want 60s", got)
	}
	if got := nextAutoResetInterval(90 * time.Second); got != 2*time.Minute {
		t.Fatalf("nextAutoResetInterval(90s) = %s, want 2m", got)
	}
	if got := nextAutoResetInterval(3 * time.Minute); got != 5*time.Minute {
		t.Fatalf("nextAutoResetInterval(3m) = %s, want 5m", got)
	}
	// A custom value larger than every preset wraps to off.
	if got := nextAutoResetInterval(10 * time.Minute); got != 0 {
		t.Fatalf("nextAutoResetInterval(10m) = %s, want 0 (off)", got)
	}
}

// TestNewTestFlamesModelSkipsPickerWithoutPidFilter guards the decoupling of
// the picker-skip decision from the pid filter. --testflames/--testliveflames
// used to pass initialPID=1 AND pidFilter=1 (the same "1" doing both jobs), so
// the model that only wanted to skip the PID picker also filtered every view to
// pid=1 — and the seeded fixtures carry synthetic pids 2001-2004, so the Stream
// tab rendered no rows at all and its CSV export was a header with no data.
func TestNewTestFlamesModelSkipsPickerWithoutPidFilter(t *testing.T) {
	m := NewTestFlamesModel(flags.NewFlags(), func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen (picker skipped), got %v", m.router.current())
	}
	if !m.attaching {
		t.Fatalf("expected attaching state so Init() requests the seeded trace")
	}
	if m.proc.pid != -1 {
		t.Fatalf("expected no pid filter, got %d", m.proc.pid)
	}
	if m.proc.tid != -1 {
		t.Fatalf("expected no tid filter, got %d", m.proc.tid)
	}
	if f := m.filters.current(); f.PID != nil || f.TID != nil {
		t.Fatalf("expected no PID/TID predicate on the startup filter, got %+v", f)
	}
}

// TestNewTestFlamesModelHonoursConfigPidFilter asserts the opposite direction:
// a genuine -pid/-tid passed alongside --testflames must still reach the model.
func TestNewTestFlamesModelHonoursConfigPidFilter(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter = 2002
	cfg.TidFilter = 2202

	m := NewTestFlamesModel(cfg, func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen (picker skipped), got %v", m.router.current())
	}
	if m.proc.pid != 2002 {
		t.Fatalf("expected pid filter 2002, got %d", m.proc.pid)
	}
	// -pid and -tid combine, exactly as on the production path through
	// resolveStartupPIDFilters (TestNewRunModelKeepsTidWithPid).
	if m.proc.tid != 2202 {
		t.Fatalf("expected -tid to combine with -pid as production does, got %d", m.proc.tid)
	}
}

// TestNewTestFlamesModelHonoursConfigTidFilterAlone pins the other half of that
// rule: with no -pid, a -tid passed alongside --testflames still reaches the
// model, matching production.
func TestNewTestFlamesModelHonoursConfigTidFilterAlone(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.TidFilter = 2202

	m := NewTestFlamesModel(cfg, func(context.Context, TraceRequest) error { return nil })

	if m.proc.tid != 2202 {
		t.Fatalf("expected tid filter 2202, got %d", m.proc.tid)
	}
}

// TestNewRunModelWiresTheProductionStartup guards the struct literal on the one
// path real users take. Every field is asserted across its two subtests
// (tidFilter is exercised by the -tid tests below): a modelStartup field is
// silently optional where a positional argument would not compile, so an
// omission anywhere in this literal is valid Go that no other test in the repo
// would notice. Dropping initialPID made `ior -pid <n>` open the PID picker
// instead of the dashboard; dropping `filter` would strip -comm/-path from the
// trace filter just as quietly.
func TestNewRunModelWiresTheProductionStartup(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter = 1234
	cfg.TidFilter = -1
	cfg.CommFilter = "ioworkload"
	cfg.PathFilter = "/srv/data"
	cfg.TUIExportEnable = false
	cfg.ResetTimer = 90 * time.Second
	cfg.TUIFastRefreshInterval = 300 * time.Millisecond

	m := newRunModel(cfg, func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenDashboard {
		t.Fatalf("a -pid attach target must start on the dashboard, got %v", m.router.current())
	}
	if !m.attaching {
		t.Fatal("a -pid attach target must start attaching, or Init() never requests the startup trace")
	}
	if m.proc.pid != 1234 {
		t.Fatalf("expected pid filter 1234, got %d", m.proc.pid)
	}
	if m.exportEnabled {
		t.Fatal("expected -tuiExport=false to reach the model")
	}
	// The startup filter carries -comm/-path into the global trace filter for
	// every real run; dropping it used to leave the whole suite green.
	startupFilter := m.filters.current()
	if startupFilter.Comm == nil || startupFilter.Comm.Pattern != "ioworkload" {
		t.Fatalf("expected -comm to reach the startup filter, got %+v", startupFilter.Comm)
	}
	if startupFilter.File == nil || startupFilter.File.Pattern != "/srv/data" {
		t.Fatalf("expected -path to reach the startup filter, got %+v", startupFilter.File)
	}
	if got := m.dashboard.AutoResetInterval(); got != 90*time.Second {
		t.Fatalf("expected -resetTimer to reach the dashboard, got %v", got)
	}
	if got := m.dashboard.FastRefreshInterval(); got != 300*time.Millisecond {
		t.Fatalf("expected -tui-fast-refresh to reach the dashboard, got %v", got)
	}
}

// TestNewRunModelWiresTidFilterWithoutPid covers the one modelStartup field the
// case above cannot reach: `ior -tid T` with no -pid is the one startup that
// leaves pidFilter at -1. Dropping tidFilter silently degrades it to -1,
// losing the model-side tid filter and the "Filter: tid=..." status display.
func TestNewRunModelWiresTidFilterWithoutPid(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter = -1
	cfg.TidFilter = 5678

	m := newRunModel(cfg, func(context.Context, TraceRequest) error { return nil })

	if m.proc.tid != 5678 {
		t.Fatalf("expected tid filter 5678 to reach the model, got %d", m.proc.tid)
	}
}

// TestNewModelWithConfigInitialPIDStillFilters pins the real (attach) startup
// path: an initialPID is a genuine attach target, so it must keep both skipping
// the picker and filtering by that pid.
func TestNewModelWithConfigInitialPIDStillFilters(t *testing.T) {
	m := NewModelWithConfig(flags.NewFlags(), 7, func(context.Context, TraceRequest) error { return nil })

	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected dashboard screen for an initial pid, got %v", m.router.current())
	}
	if !m.attaching {
		t.Fatalf("expected attaching state for an initial pid")
	}
	if m.proc.pid != 7 {
		t.Fatalf("expected pid filter 7, got %d", m.proc.pid)
	}
	if f := m.filters.current(); f.PID == nil {
		t.Fatalf("expected a PID predicate on the startup filter, got %+v", f)
	}
}

// TestFallbackWindowSizeNeverOverridesARealSize pins the precedence that keeps
// width-dependent rendering deterministic.
//
// initialWindowSizeCmd guesses a viewport when the terminal cannot be queried
// (the 80x24 default, which is what a test binary or a redirected stdout gets).
// bubbletea independently sends a real WindowSizeMsg. Both are asynchronous and
// nothing orders them, so before fallbackWindowSizeMsg existed whichever landed
// last won: the dashboard would settle at 80 columns on a 160-column terminal
// roughly whenever the guess came second. Every width-dependent rendering
// decision rides on this - the tab bar abbreviates below 90 columns, and
// syscallColumns returns 9 columns below 140 and 12 at or above.
func TestFallbackWindowSizeNeverOverridesARealSize(t *testing.T) {
	realSize := tea.WindowSizeMsg{Width: 160, Height: 48}
	fallback := fallbackWindowSizeMsg{Width: 80, Height: 24}

	t.Run("initial size command marks its result as fallback", func(t *testing.T) {
		cmd := initialWindowSizeCmd()
		if _, ok := cmd().(fallbackWindowSizeMsg); !ok {
			t.Fatal("initialWindowSizeCmd did not produce fallbackWindowSizeMsg")
		}
	})

	t.Run("guess after real size is ignored", func(t *testing.T) {
		m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
		m.Update(realSize)
		m.Update(fallback)
		if m.width != 160 || m.height != 48 {
			t.Errorf("the guessed size overrode the real one: got %dx%d, want 160x48", m.width, m.height)
		}
	})

	t.Run("guess before real size is applied, then replaced", func(t *testing.T) {
		m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
		m.Update(fallback)
		if m.width != 80 || m.height != 24 {
			t.Fatalf("the guess did not fill in an unknown size: got %dx%d, want 80x24", m.width, m.height)
		}
		m.Update(realSize)
		if m.width != 160 || m.height != 48 {
			t.Errorf("a real size did not replace the guess: got %dx%d, want 160x48", m.width, m.height)
		}
	})
}
