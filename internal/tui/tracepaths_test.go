package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// armRecorderStopFailure starts a real recording and removes its directory,
// so the next recorder stop fails when finalisation renames the temporary
// file into it.
func armRecorderStopFailure(t *testing.T, m *Model) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "recordings")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := m.startRecording(filepath.Join(dir, "capture.parquet")); err != nil {
		t.Fatalf("startRecording() error = %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll() error = %v", err)
	}
}

// countTraceStops replaces the model's trace cancel func with a counter.
func countTraceStops(m *Model) *int {
	calls := 0
	m.tracer.traceStop = func() { calls++ }
	return &calls
}

// newIdleDashboardModel returns a model on the dashboard, done attaching,
// tracing pid/tid.
func newIdleDashboardModel(pid, tid int) *Model {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	m.setProcessFilters(pid, tid)
	return m
}

// TestRestartTraceWithNoTracerRunningStartsOne is the negative case for the
// shared restart tail: with no session to stop, it must still clear the
// error, enter the attaching state and start exactly one new session.
func TestRestartTraceWithNoTracerRunningStartsOne(t *testing.T) {
	starter := newRecordingStarter()
	m := NewModel(-1, starter.start)
	t.Cleanup(m.tracer.stop)
	m.router.showDashboard()
	m.setError(errors.New("stale"), errorScreenRecoverable)
	if m.tracer.traceStop != nil {
		t.Fatal("fixture already has a trace running; this test would prove nothing")
	}

	cmd := m.restartTrace()
	if cmd == nil {
		t.Fatal("restartTrace() returned no command with no tracer running")
	}
	if !m.attaching {
		t.Fatal("restartTrace() did not enter the attaching state")
	}
	if m.lastErr != nil || m.errorKind != errorScreenFatal {
		t.Fatalf("restartTrace() left error %v (kind %v)", m.lastErr, m.errorKind)
	}
	if m.tracer.traceStop == nil {
		t.Fatal("restartTrace() did not store the new session's cancel func")
	}
	if got := m.router.current(); got != ScreenDashboard {
		t.Fatalf("restartTrace() changed the screen to %v", got)
	}

	runCmdAsync(cmd)
	session := starter.next(t)
	requireLive(t, session, "restarted trace")
	m.tracer.stop()
	requireCancelled(t, session, "restarted trace after stop")
}

// TestRestartTraceStopsTheRunningSessionExactlyOnce pins that the restart
// tail cancels the old session and that beginCmd's own stop is then a no-op.
func TestRestartTraceStopsTheRunningSessionExactlyOnce(t *testing.T) {
	m := newIdleDashboardModel(-1, -1)
	stops := countTraceStops(m)

	if cmd := m.restartTrace(); cmd == nil {
		t.Fatal("restartTrace() returned no command")
	}
	if *stops != 1 {
		t.Fatalf("old session stopped %d times, want 1", *stops)
	}
}

// TestProcessSelectionSharesOneSwitch drives both picker messages through
// the shared selectProcess path and pins how each resolves pid/tid.
func TestProcessSelectionSharesOneSwitch(t *testing.T) {
	cases := []struct {
		name             string
		msg              tea.Msg
		wantPID, wantTID int
	}{
		{name: "pid", msg: PidSelectedMsg{Pid: 42}, wantPID: 42, wantTID: -1},
		{name: "pid zero means no filter", msg: PidSelectedMsg{Pid: 0}, wantPID: -1, wantTID: -1},
		{name: "tid in current pid", msg: TidSelectedMsg{Tid: 7}, wantPID: 1111, wantTID: 7},
		{name: "tid in message pid", msg: TidSelectedMsg{Pid: 9, Tid: 7}, wantPID: 9, wantTID: 7},
		{name: "tid zero means no tid filter", msg: TidSelectedMsg{Pid: 9}, wantPID: 9, wantTID: -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newIdleDashboardModel(1111, 2222)
			m.router.showPickerWithReturn(1111, 2222)
			m.setError(errors.New("stale"), errorScreenRecoverable)
			stops := countTraceStops(m)

			next, cmd := m.Update(tc.msg)
			updated := next.(*Model)
			if cmd == nil {
				t.Fatal("selection returned no trace start command")
			}
			if updated.proc.pid != tc.wantPID || updated.proc.tid != tc.wantTID {
				t.Fatalf("pid/tid = %d/%d, want %d/%d", updated.proc.pid, updated.proc.tid, tc.wantPID, tc.wantTID)
			}
			if updated.router.current() != ScreenDashboard || !updated.attaching {
				t.Fatalf("screen %v attaching %t, want dashboard attaching", updated.router.current(), updated.attaching)
			}
			if updated.router.hasPendingReturn() {
				t.Fatal("selection left the picker return bookmark pending")
			}
			if updated.lastErr != nil {
				t.Fatalf("selection left error %v", updated.lastErr)
			}
			if *stops != 1 {
				t.Fatalf("old session stopped %d times, want 1", *stops)
			}
		})
	}
}

// TestProcessSelectionRecorderFailureKeepsThePicker is the negative case: a
// recorder that fails to stop aborts the selection, leaving the picker, its
// bookmark, the filters and the trace untouched.
func TestProcessSelectionRecorderFailureKeepsThePicker(t *testing.T) {
	for _, msg := range []tea.Msg{PidSelectedMsg{Pid: 42}, TidSelectedMsg{Pid: 42, Tid: 7}} {
		m := newIdleDashboardModel(1111, 2222)
		m.router.showPickerWithReturn(1111, 2222)
		armRecorderStopFailure(t, m)
		stops := countTraceStops(m)

		next, cmd := m.Update(msg)
		updated := next.(*Model)
		if cmd != nil {
			t.Fatalf("%T: failed selection returned a command", msg)
		}
		if updated.lastErr == nil || updated.errorKind != errorScreenRecoverable {
			t.Fatalf("%T: error = %v (kind %v), want a recoverable recorder error", msg, updated.lastErr, updated.errorKind)
		}
		if updated.router.current() != ScreenPIDPicker || updated.attaching {
			t.Fatalf("%T: screen %v attaching %t, want picker idle", msg, updated.router.current(), updated.attaching)
		}
		if state, ok := updated.router.pendingReturn(); !ok || state.pidFilter != 1111 || state.tidFilter != 2222 {
			t.Fatalf("%T: bookmark = %+v, %t; want 1111/2222 kept", msg, state, ok)
		}
		if updated.proc.pid != 1111 || updated.proc.tid != 2222 {
			t.Fatalf("%T: pid/tid = %d/%d, want 1111/2222 kept", msg, updated.proc.pid, updated.proc.tid)
		}
		if *stops != 0 {
			t.Fatalf("%T: failed selection stopped the trace %d times", msg, *stops)
		}
	}
}

// TestEnterPickerBookmarksAndShowsTheRequestedPicker pins the shared picker
// entry for both reselect keys, including which picker each one shows.
func TestEnterPickerBookmarksAndShowsTheRequestedPicker(t *testing.T) {
	cases := []struct {
		name     string
		reselect func(*Model) (tea.Model, tea.Cmd)
		title    string
	}{
		{name: "pid", reselect: (*Model).reselectPID, title: "Select PID"},
		{name: "tid", reselect: (*Model).reselectTID, title: "Select TID for PID 1111"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newIdleDashboardModel(1111, 2222)
			m.setError(errors.New("stale"), errorScreenRecoverable)
			m.filterModal = m.filterModal.Open(m.filters.current())
			stops := countTraceStops(m)

			next, cmd := tc.reselect(m)
			updated := next.(*Model)
			if cmd == nil {
				t.Fatal("reselect returned no picker init command")
			}
			if updated.router.current() != ScreenPIDPicker || updated.attaching {
				t.Fatalf("screen %v attaching %t, want picker idle", updated.router.current(), updated.attaching)
			}
			if state, ok := updated.router.pendingReturn(); !ok || state.pidFilter != 1111 || state.tidFilter != 2222 {
				t.Fatalf("bookmark = %+v, %t; want 1111/2222", state, ok)
			}
			if *stops != 1 {
				t.Fatalf("trace stopped %d times, want 1", *stops)
			}
			if updated.lastErr != nil {
				t.Fatalf("reselect left error %v", updated.lastErr)
			}
			if updated.filterModal.Visible() {
				t.Fatal("reselect left the filter modal open")
			}
			if view := updated.pidPicker.View().Content; !strings.Contains(view, tc.title) {
				t.Fatalf("picker view lacks %q:\n%s", tc.title, view)
			}
		})
	}
}

// TestEnterPickerRecorderFailureStaysOnTheDashboard is the negative case: a
// recorder that fails to stop keeps the dashboard and its running trace, and
// sets no bookmark.
func TestEnterPickerRecorderFailureStaysOnTheDashboard(t *testing.T) {
	m := newIdleDashboardModel(1111, 2222)
	armRecorderStopFailure(t, m)
	stops := countTraceStops(m)

	next, cmd := m.reselectPID()
	updated := next.(*Model)
	if cmd != nil {
		t.Fatal("failed reselect returned a command")
	}
	if updated.lastErr == nil || updated.errorKind != errorScreenRecoverable {
		t.Fatalf("error = %v (kind %v), want a recoverable recorder error", updated.lastErr, updated.errorKind)
	}
	if updated.router.current() != ScreenDashboard {
		t.Fatalf("screen = %v, want dashboard kept", updated.router.current())
	}
	if updated.router.hasPendingReturn() {
		t.Fatal("failed reselect set a picker return bookmark")
	}
	if *stops != 0 {
		t.Fatalf("failed reselect stopped the trace %d times", *stops)
	}
}

// TestCancelPickerWithoutReturnIsANoOp: on the startup picker there is no
// dashboard to go back to, so a cancel must neither switch screens nor start
// a trace.
func TestCancelPickerWithoutReturnIsANoOp(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	if m.router.current() != ScreenPIDPicker || m.router.hasPendingReturn() {
		t.Fatal("fixture is not the startup picker; this test would prove nothing")
	}

	next, cmd := m.cancelPickerToDashboard()
	updated := next.(*Model)
	if cmd != nil {
		t.Fatal("cancel without a return bookmark returned a command")
	}
	if updated.router.current() != ScreenPIDPicker || updated.attaching {
		t.Fatalf("screen %v attaching %t, want startup picker idle", updated.router.current(), updated.attaching)
	}
	if updated.tracer.traceStop != nil {
		t.Fatal("cancel without a return bookmark started a trace")
	}
}

// TestCancelPickerClearsReturnAndRestoresFilters: a successful cancel
// consumes the bookmark, restores its pid/tid and restarts tracing.
func TestCancelPickerClearsReturnAndRestoresFilters(t *testing.T) {
	m := newIdleDashboardModel(1111, 2222)
	if _, cmd := m.reselectTID(); cmd == nil {
		t.Fatal("reselectTID returned no command")
	}
	// A picker selection in flight must not leak into the restored view.
	m.setProcessFilters(3333, -1)

	next, cmd := m.cancelPickerToDashboard()
	updated := next.(*Model)
	if cmd == nil {
		t.Fatal("cancel returned no trace restart command")
	}
	if updated.router.hasPendingReturn() {
		t.Fatal("cancel left the picker return bookmark pending")
	}
	if updated.router.current() != ScreenDashboard || !updated.attaching {
		t.Fatalf("screen %v attaching %t, want dashboard attaching", updated.router.current(), updated.attaching)
	}
	if updated.proc.pid != 1111 || updated.proc.tid != 2222 {
		t.Fatalf("pid/tid = %d/%d, want 1111/2222 restored", updated.proc.pid, updated.proc.tid)
	}

	// The bookmark is gone, so a second cancel is a no-op.
	if _, cmd := updated.cancelPickerToDashboard(); cmd != nil {
		t.Fatal("second cancel returned a command")
	}
}

// TestCancelPickerRecorderFailureKeepsTheBookmark: the bookmark is only read
// before the recorder stops, so a failure leaves it (and the picker) intact
// for the next attempt instead of stranding the user on a picker with no way
// back.
func TestCancelPickerRecorderFailureKeepsTheBookmark(t *testing.T) {
	m := newIdleDashboardModel(1111, 2222)
	if _, cmd := m.reselectPID(); cmd == nil {
		t.Fatal("reselectPID returned no command")
	}
	armRecorderStopFailure(t, m)
	stops := countTraceStops(m)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	updated := next.(*Model)
	if cmd != nil {
		t.Fatal("failed cancel returned a command")
	}
	if updated.lastErr == nil || updated.errorKind != errorScreenRecoverable {
		t.Fatalf("error = %v (kind %v), want a recoverable recorder error", updated.lastErr, updated.errorKind)
	}
	if updated.router.current() != ScreenPIDPicker || updated.attaching {
		t.Fatalf("screen %v attaching %t, want picker idle", updated.router.current(), updated.attaching)
	}
	if state, ok := updated.router.pendingReturn(); !ok || state.pidFilter != 1111 || state.tidFilter != 2222 {
		t.Fatalf("bookmark = %+v, %t; want 1111/2222 kept", state, ok)
	}
	if *stops != 0 {
		t.Fatalf("failed cancel stopped the trace %d times", *stops)
	}
}
