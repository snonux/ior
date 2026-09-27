package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/runtime"

	tea "charm.land/bubbletea/v2"
)

// newErrorScreenModel builds a dashboard-screen Model that is showing the
// full-screen error view, i.e. the state every key used to fall into.
func newErrorScreenModel(t *testing.T, err error) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 40
	m.setError(err, errorScreenFatal)
	if !strings.Contains(m.View().Content, err.Error()) {
		t.Fatalf("precondition: expected the error view to be on screen, got %q", m.View().Content)
	}
	return m
}

// newRecorderStopErrorScreen reaches the recoverable error state through the
// dashboard's real record-stop shortcut rather than setting model fields.
func newRecorderStopErrorScreen(t *testing.T) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 40

	dir := filepath.Join(t.TempDir(), "recordings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := m.startRecording(filepath.Join(dir, "capture.parquet")); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}
	// Finalisation renames the recorder's temporary file into dir. Removing
	// it makes the R shortcut's recorderStop call fail after the trace itself
	// has remained untouched.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'R', Text: "R"})
	if cmd != nil {
		t.Fatal("record-stop failure returned a command, want nil")
	}
	m = next.(*Model)
	if m.lastErr == nil {
		t.Fatal("record-stop failure did not open the error screen")
	}
	if m.errorKind != errorScreenRecoverable {
		t.Fatalf("record-stop error kind = %v, want recoverable", m.errorKind)
	}
	return m
}

// quitKeys are the three keys that leave a fatal error screen. Esc is included
// because a fatal trace failure has no healthy dashboard to return to, so
// dismissing it and quitting are the same action.
func quitKeys() map[string]tea.KeyPressMsg {
	return map[string]tea.KeyPressMsg{
		"q":      {Code: 'q', Text: "q"},
		"ctrl+c": {Code: 'c', Mod: tea.ModCtrl},
		"esc":    {Code: tea.KeyEsc},
	}
}

func assertQuits(t *testing.T, next tea.Model, cmd tea.Cmd) *Model {
	t.Helper()
	if cmd == nil {
		t.Fatalf("expected a quit command, got nil")
	}
	if msg := cmd(); !isQuitMsg(msg) {
		t.Fatalf("expected tea.QuitMsg, got %T: %v", msg, msg)
	}
	updated, ok := next.(*Model)
	if !ok {
		t.Fatalf("expected *Model, got %T", next)
	}
	if !updated.quitting {
		t.Fatalf("expected the model to record the quit")
	}
	return updated
}

// isQuitMsg reports whether msg is tea.Quit's message. tea.Batch wraps
// commands, so unwrap one level of BatchMsg before deciding.
func isQuitMsg(msg tea.Msg) bool {
	if _, ok := msg.(tea.QuitMsg); ok {
		return true
	}
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		return false
	}
	for _, cmd := range batch {
		if cmd == nil {
			continue
		}
		if isQuitMsg(cmd()) {
			return true
		}
	}
	return false
}

// TestErrorScreenQuitsOnEveryQuitKey is the z3 regression. Once m.lastErr was
// set, canHandleDashboardShortcut was false (it gates on lastErr == nil) and
// shouldRouteQuitToEsc was false too (no modal is visible), so every quit key
// fell through to handleQuitKeyPress's swallowing return and the TUI could
// only be left with a SIGKILL from another terminal.
func TestErrorScreenQuitsOnEveryQuitKey(t *testing.T) {
	// Only these keys. `isErrorScreenQuitKey` returning true for everything
	// would pass every other assertion here, and the whole rationale for
	// putting this branch first is that it takes three keys and leaves the
	// rest alone.
	for _, msg := range []tea.KeyPressMsg{
		{Code: '1', Text: "1"},
		{Code: 'H', Text: "H"},
		{Code: tea.KeyEnter},
	} {
		m := newErrorScreenModel(t, errors.New("boom"))
		if _, cmd := m.Update(msg); cmd != nil && isQuitMsg(cmd()) {
			t.Errorf("key %v quit the error screen; only q, ctrl+c and esc may", msg)
		}
	}

	for name, press := range quitKeys() {
		t.Run(name, func(t *testing.T) {
			m := newErrorScreenModel(t, errors.New("comm filter max size is 15 (got 19)"))
			next, cmd := m.Update(press)
			assertQuits(t, next, cmd)
		})
	}
}

// TestErrorScreenQuitCancelsTheTrace pins that leaving the error view is a
// real quit and not just a tea.Quit: the trace context is cancelled exactly as
// the dashboard quit path does it, so a trace that did start underneath the
// error is torn down rather than left running behind a dead UI.
func TestErrorScreenQuitCancelsTheTrace(t *testing.T) {
	for name, press := range quitKeys() {
		t.Run(name, func(t *testing.T) {
			m := newErrorScreenModel(t, errors.New("boom"))
			stopped := make(chan struct{})
			m.tracer.traceStop = func() { close(stopped) }

			next, cmd := m.Update(press)
			assertQuits(t, next, cmd)

			select {
			case <-stopped:
			case <-time.After(200 * time.Millisecond):
				t.Fatalf("expected the trace context to be cancelled on quit")
			}
		})
	}
}

// TestStartupTimeoutQuitWaitsForClaimedSessionCleanup covers the partial
// startup case: the real starter has claimed shutdown ownership and may have
// attached resources, but no TracingStartedMsg reached the model before the
// timeout. Quitting the error screen must keep rendering shutdown feedback
// until cancellation cleanup publishes completion.
func TestStartupTimeoutQuitWaitsForClaimedSessionCleanup(t *testing.T) {
	m := newErrorScreenModel(t, errors.New("trace startup timed out after 30s"))
	reporter := runtime.NewTraceShutdownReporter()
	reporter.Claim()
	m.tracer.shutdownReporter = reporter
	cancelled := make(chan struct{})
	releaseCleanup := make(chan struct{})
	m.tracer.traceStop = func() {
		close(cancelled)
		go func() {
			<-releaseCleanup
			reporter.Complete()
		}()
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := next.(*Model)
	select {
	case <-cancelled:
	default:
		t.Fatal("timeout quit did not cancel the partial trace session")
	}
	if !updated.quitting {
		t.Fatal("timeout quit did not enter the shutdown view")
	}
	if got := updated.View().Content; !strings.Contains(got, "Stopping trace and releasing BPF resources") {
		t.Fatalf("timeout shutdown view = %q", got)
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) != 2 {
		t.Fatalf("timeout quit command = %T, want spinner + completion wait", batch)
	}

	close(releaseCleanup)
	completeMsg := batch[1]()
	completeNext, quitCmd := updated.Update(completeMsg)
	if _, ok := completeNext.(*Model); !ok {
		t.Fatalf("completion model = %T, want *Model", completeNext)
	}
	if quitCmd == nil {
		t.Fatal("cleanup completion did not dispatch tea.Quit")
	}
	if _, ok := quitCmd().(tea.QuitMsg); !ok {
		t.Fatalf("cleanup completion command = %T, want tea.QuitMsg", quitCmd())
	}
}

// TestErrorScreenQuitStopsAnActiveRecording pins the other half of the
// dashboard quit path: a parquet recording started before the error is closed
// on the way out, so the file is finalised rather than left as a temp file.
func TestErrorScreenQuitStopsAnActiveRecording(t *testing.T) {
	m := newErrorScreenModel(t, errors.New("boom"))
	path := filepath.Join(t.TempDir(), "capture.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if updated.runtime.Recorder().Status().Active {
		t.Fatalf("expected quit from the error view to stop the active recording")
	}
}

// TestErrorScreenQuitSurvivesARecorderThatCannotStop covers the way into this
// screen that is itself a cleanup failure: recorderStop failing on the
// dashboard sets m.lastErr and returns without quitting, so pressing q with a
// broken recorder is exactly how a user lands here. The second attempt must
// not fail the same way - a quit that depends on the cleanup succeeding is the
// swallowed key all over again.
func TestErrorScreenQuitSurvivesARecorderThatCannotStop(t *testing.T) {
	m := newErrorScreenModel(t, errors.New("boom"))
	dir := filepath.Join(t.TempDir(), "recordings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := m.startRecording(filepath.Join(dir, "capture.parquet")); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}
	// The writer finalises by renaming its temp file into this directory;
	// removing it makes Close - and so recorderStop - fail for real.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if updated.lastErr == nil || updated.lastErr.Error() != "boom" {
		t.Fatalf("expected the displayed error to survive the quit, got %v", updated.lastErr)
	}
}

// TestRecorderStopErrorEscReturnsToDashboard pins both halves of the new
// classification: the R shortcut marks a recorder finalisation failure as
// recoverable, and Esc dismisses it without stopping the healthy trace.
func TestRecorderStopErrorEscReturnsToDashboard(t *testing.T) {
	m := newRecorderStopErrorScreen(t)
	stops := 0
	m.tracer.traceStop = func() { stops++ }

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if cmd != nil && isQuitMsg(cmd()) {
		t.Fatal("Esc quit from a recoverable recorder error")
	}
	updated := next.(*Model)
	if updated.lastErr != nil {
		t.Fatalf("Esc left the recoverable error on screen: %v", updated.lastErr)
	}
	if updated.errorKind != errorScreenFatal {
		t.Fatalf("dismissed error kind = %v, want reset fatal default", updated.errorKind)
	}
	if updated.screen != ScreenDashboard {
		t.Fatalf("screen after dismiss = %v, want dashboard", updated.screen)
	}
	if updated.quitting {
		t.Fatal("Esc put the model into quitting state")
	}
	if stops != 0 {
		t.Fatalf("Esc stopped the healthy trace %d times", stops)
	}
}

// TestRecorderStopErrorQuitKeysStillQuit ensures recoverability changes only
// Esc. The explicit quit binding must still stop the trace and leave the
// recorder error available for finalModelError to report.
func TestRecorderStopErrorQuitKeysStillQuit(t *testing.T) {
	for name, press := range map[string]tea.KeyPressMsg{
		"q":      {Code: 'q', Text: "q"},
		"ctrl+c": {Code: 'c', Mod: tea.ModCtrl},
	} {
		t.Run(name, func(t *testing.T) {
			m := newRecorderStopErrorScreen(t)
			wantErr := m.lastErr
			stops := 0
			m.tracer.traceStop = func() { stops++ }

			next, cmd := m.Update(press)
			updated := assertQuits(t, next, cmd)
			if stops != 1 {
				t.Fatalf("trace stop calls = %d, want 1", stops)
			}
			if !errors.Is(finalModelError(updated), wantErr) {
				t.Fatalf("finalModelError() = %v, want %v", finalModelError(updated), wantErr)
			}
		})
	}
}

// TestOverLongCLICommFilterStaysQuittable walks the reported route at the
// model level: an over-long -comm reaches setupTraceInfra's
// ValidateTracepointFields, arrives as TracingErrorMsg and sets m.lastErr.
func TestOverLongCLICommFilterStaysQuittable(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.CommFilter = overLongComm()
	startupErr := flags.BuildTraceFilter(cfg).ValidateTracepointFields()
	if startupErr == nil {
		t.Fatalf("precondition: expected an over-long -comm to fail validation")
	}

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = true
	m.width = 120
	m.height = 40

	errored, _ := m.Update(TracingErrorMsg{Err: startupErr})
	m = errored.(*Model)
	if !strings.Contains(m.View().Content, "comm filter max size") {
		t.Fatalf("expected the startup failure on screen, got %q", m.View().Content)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	assertQuits(t, next, cmd)
}

// TestErrorScreenQuitReportsTheFailureToTheCaller pins what the user is left
// with after quitting: the alternate screen is discarded on exit, so the
// reason has to leave the program through its return value to reach stderr.
func TestErrorScreenQuitReportsTheFailureToTheCaller(t *testing.T) {
	want := errors.New("trace startup failed")
	m := newErrorScreenModel(t, want)

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if got := finalModelError(updated); !errors.Is(got, want) {
		t.Fatalf("finalModelError() = %v, want %v", got, want)
	}
	if got := finalModelError(nil); got != nil {
		t.Fatalf("finalModelError(nil) = %v, want nil", got)
	}
}

// TestCleanExitReportsNoError guards the other side of the same wiring: a
// model that quits with no error must keep cmd/ior's exit status at zero.
func TestCleanExitReportsNoError(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if err := finalModelError(updated); err != nil {
		t.Fatalf("finalModelError() = %v, want nil after a clean quit", err)
	}
}

// TestErrorScreenAdvertisesTheWayOut pins the hint: this view answers no key
// but the quit keys, so it has to name one. A screen that looks stuck and
// says nothing is what sent the z3 reporter to another terminal.
func TestErrorScreenAdvertisesTheWayOut(t *testing.T) {
	m := newErrorScreenModel(t, errors.New("boom"))

	view := m.View().Content
	for _, want := range []string{"q", "esc", "quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected the error view to mention %q, got %q", want, view)
		}
	}
}

func TestRecoverableErrorScreenAdvertisesBackAndQuit(t *testing.T) {
	m := newRecorderStopErrorScreen(t)

	view := m.View().Content
	for _, want := range []string{"esc", "back", "q", "quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected the recoverable error view to mention %q, got %q", want, view)
		}
	}
}

// TestErrorScreenQuitOutranksAnOpenModal pins the ordering of the error-screen
// branch, which the other tests do not: moving it below the modal routing
// leaves them all green.
//
// View renders m.lastErr ahead of every modal, so when both are set the modal
// is not on screen. A key routed to it would close something invisible and
// leave the user on the error view with nothing having visibly happened - the
// dead end again, one keystroke further in. What is on screen is what must
// answer the key.
func TestErrorScreenQuitOutranksAnOpenModal(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.filterModal = m.filterModal.Open(globalfilter.Filter{})
	m.setError(errors.New("create event filter: comm filter max size is 15 (got 20)"), errorScreenFatal)

	// Precondition: the error view really is what is rendered.
	if !strings.Contains(m.View().Content, "comm filter max size") {
		t.Fatal("the error view is not on screen; this test would prove nothing")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil || !isQuitMsg(cmd()) {
		t.Fatalf("q did not quit while the error view was on screen with a modal open underneath")
	}
	if !next.(*Model).quitting {
		t.Error("the model did not enter the quitting state")
	}
}

// TestRunProgramReportsTheFinalModelError pins the wiring that makes a quit
// from the error screen say why.
//
// finalModelError has its own unit test, but nothing joined it to runProgram:
// replacing runProgram's body with `return err` left every test green while
// the binary exited 0 with no reason - which is exactly the silence the
// reporting change exists to end.
func TestRunProgramReportsTheFinalModelError(t *testing.T) {
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })

	wantErr := errors.New("create event filter: comm filter max size is 15 (got 20)")
	runTeaProgram = func(m *Model) (tea.Model, error) {
		m.setError(wantErr, errorScreenFatal)
		return m, nil
	}
	if err := runProgram(NewModel(-1, func(context.Context, TraceRequest) error { return nil })); !errors.Is(err, wantErr) {
		t.Errorf("runProgram() = %v, want the final model's error", err)
	}

	// A clean run still reports nothing, so the caller does not print a
	// spurious failure on an ordinary quit.
	runTeaProgram = func(m *Model) (tea.Model, error) { return m, nil }
	if err := runProgram(NewModel(-1, func(context.Context, TraceRequest) error { return nil })); err != nil {
		t.Errorf("runProgram() = %v on a clean quit, want nil", err)
	}

	// Bubble Tea's own failure outranks the model's, so a SIGINT still reports
	// ErrInterrupted rather than whatever the model happened to be showing.
	teaErr := errors.New("tea failed")
	runTeaProgram = func(m *Model) (tea.Model, error) {
		m.setError(wantErr, errorScreenFatal)
		return m, teaErr
	}
	if err := runProgram(NewModel(-1, func(context.Context, TraceRequest) error { return nil })); !errors.Is(err, teaErr) {
		t.Errorf("runProgram() = %v, want the program's own error to win", err)
	}
}

// TestRecoverableErrorScreenEscOutranksAndResumesPickerCancel pins both the
// error screen's routing precedence and the recovered behaviour. The visible
// screen handles Esc itself, then deliberately resumes the saved picker-return
// route rather than letting an invisible picker consume the key.
func TestRecoverableErrorScreenEscOutranksAndResumesPickerCancel(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenPIDPicker
	m.attaching = false
	// The pending return is what made esc recover here before task z3, so
	// without it this test would exercise a different branch entirely.
	m.router.savePendingReturn(-1, -1)
	m.setError(errors.New("stop recording: rename ior.parquet: no such file or directory"), errorScreenRecoverable)
	if !m.shouldCancelPickerToDashboard(tea.KeyPressMsg{Code: tea.KeyEsc}) {
		t.Fatal("the picker-cancel branch would not fire; this test would prove nothing")
	}

	if !strings.Contains(m.View().Content, "stop recording") {
		t.Fatal("the error view is not on screen; this test would prove nothing")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if cmd == nil {
		t.Fatal("Esc did not resume the picker-return trace start")
	}
	if isQuitMsg(cmd()) {
		t.Fatal("Esc quit from the recoverable error view on the PID picker")
	}
	updated := next.(*Model)
	if updated.screen != ScreenDashboard || !updated.attaching {
		t.Fatalf("state after Esc = screen %v, attaching %t; want dashboard attaching", updated.screen, updated.attaching)
	}
	if updated.lastErr != nil {
		t.Fatalf("Esc left the recoverable error on screen: %v", updated.lastErr)
	}
	if updated.router.hasPendingReturn() {
		t.Fatal("Esc left the picker return bookmark pending")
	}
}

// TestRecoverableErrorScreenQuitOutranksPickerCancel distinguishes the error
// route from the invisible picker's own q/ctrl+c-as-back route. On the error
// screen those keys must quit, leaving the return bookmark untouched.
func TestRecoverableErrorScreenQuitOutranksPickerCancel(t *testing.T) {
	for name, press := range map[string]tea.KeyPressMsg{
		"q":      {Code: 'q', Text: "q"},
		"ctrl+c": {Code: 'c', Mod: tea.ModCtrl},
	} {
		t.Run(name, func(t *testing.T) {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			m.screen = ScreenPIDPicker
			m.attaching = false
			m.router.savePendingReturn(-1, -1)
			m.setError(errors.New("stop recording: rename failed"), errorScreenRecoverable)
			if !m.shouldCancelPickerToDashboard(press) {
				t.Fatal("the picker-cancel branch would not fire; this test would prove nothing")
			}

			next, cmd := m.Update(press)
			updated := assertQuits(t, next, cmd)
			if !updated.router.hasPendingReturn() {
				t.Fatal("quit key reached the picker cancel route and consumed its bookmark")
			}
		})
	}
}

// TestErrorScreenQuitOutranksTheHelpOverlay pins the remaining ordering. The
// overlay can be open when a trace failure arrives, and View renders the error
// ahead of it, so the overlay is not what the user is looking at.
func TestErrorScreenQuitOutranksTheHelpOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.helpOverlayVisible = true
	m.setError(errors.New("setup BPF module: attach probes: no such file or directory"), errorScreenFatal)

	if !strings.Contains(m.View().Content, "attach probes") {
		t.Fatal("the error view is not on screen; this test would prove nothing")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if cmd == nil || !isQuitMsg(cmd()) {
		t.Fatal("q did not quit from the error view with the help overlay open underneath")
	}
	if !next.(*Model).quitting {
		t.Error("the model did not enter the quitting state")
	}
}

// TestExportedEntryPointsReportTheError pins that production actually goes
// through runProgram.
//
// Testing runProgram directly leaves the entry points free to bypass it:
// reverting either to `tea.NewProgram(...).Run()` keeps runProgram,
// finalModelError and the seam all present and fully tested, merely orphaned,
// and the binary is back to exiting 0 with no reason after a quit from the
// error screen. That is the "mentions the right strings and runs nothing"
// shape AGENTS.md warns about, one level up from the function it warns in.
func TestExportedEntryPointsReportTheError(t *testing.T) {
	original := runTeaProgram
	t.Cleanup(func() { runTeaProgram = original })

	wantErr := errors.New("create event filter: comm filter max size is 15 (got 20)")
	runTeaProgram = func(m *Model) (tea.Model, error) {
		m.setError(wantErr, errorScreenFatal)
		return m, nil
	}
	starter := func(context.Context, TraceRequest) error { return nil }

	for name, run := range map[string]func() error{
		"RunWithTraceStarterConfig": func() error {
			return RunWithTraceStarterConfig(flags.NewFlags(), starter)
		},
		"RunTestFlamesWithTraceStarterConfig": func() error {
			return RunTestFlamesWithTraceStarterConfig(flags.NewFlags(), starter)
		},
	} {
		if err := run(); !errors.Is(err, wantErr) {
			t.Errorf("%s() = %v, want the error the model was showing", name, err)
		}
	}
}
