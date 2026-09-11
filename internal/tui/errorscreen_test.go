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

	tea "charm.land/bubbletea/v2"
)

// newErrorScreenModel builds a dashboard-screen Model that is showing the
// full-screen error view, i.e. the state every key used to fall into.
func newErrorScreenModel(t *testing.T, err error) *Model {
	t.Helper()
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 40
	m.lastErr = err
	if !strings.Contains(m.View().Content, err.Error()) {
		t.Fatalf("precondition: expected the error view to be on screen, got %q", m.View().Content)
	}
	return m
}

// quitKeys are the three keys a user reaches for on a screen that shows an
// error and nothing else. Esc is included deliberately: the error view has
// nothing to go back to, so dismissing it and quitting are the same action.
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

	m := NewModel(-1, func(context.Context) error { return nil })
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
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := assertQuits(t, next, cmd)

	if err := finalModelError(updated); err != nil {
		t.Fatalf("finalModelError() = %v, want nil after a clean quit", err)
	}
}

// TestErrorScreenQuitIsNotAWayPastAModal keeps the pre-existing quit routing
// intact: with no error on screen the quit key still closes a visible modal
// instead of ending the session.
func TestErrorScreenQuitIsNotAWayPastAModal(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.filterModal = m.filterModal.Open(globalfilter.Filter{})

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	updated := next.(*Model)
	if updated.quitting {
		t.Fatalf("expected q to close the filter modal, not to quit")
	}
	if updated.filterModal.Visible() {
		t.Fatalf("expected q to close the filter modal")
	}
	if cmd != nil && isQuitMsg(cmd()) {
		t.Fatalf("expected no quit command while a modal is open")
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
