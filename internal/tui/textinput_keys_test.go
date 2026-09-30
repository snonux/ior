package tui

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
)

// Task xq2: while a text input has focus, the global q (quit) and H (help)
// shortcuts must not fire - they are letters of the text being typed. Each test
// types a word containing both letters into one input and requires that the
// program neither quits nor opens help, and that the input received the text.

// typeText sends each rune of s to the model as its own printable key press
// and returns the model afterwards, failing the test the moment a key starts a
// shutdown or opens the help overlay.
func typeText(t *testing.T, m *Model, s string) *Model {
	t.Helper()
	for _, r := range s {
		next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
		m = next.(*Model)
		if m.quitting {
			t.Fatalf("typing %q quit the program at %q", s, string(r))
		}
		if m.helpOverlayVisible {
			t.Fatalf("typing %q opened the help overlay at %q", s, string(r))
		}
	}
	return m
}

// requireViewContains fails unless the model's rendered view holds want. It is
// what proves the typed text actually reached the input: a regression that
// swallowed the key (handled=true instead of falling through) would keep the
// program alive and the help overlay closed, so the quit/help checks in
// typeText alone cannot see it.
func requireViewContains(t *testing.T, m *Model, want string) {
	t.Helper()
	if view := m.View().Content; !strings.Contains(view, want) {
		t.Fatalf("expected the view to show the typed text %q, view:\n%s", want, view)
	}
}

func newTypingTestModel() *Model {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	return m
}

func press(t *testing.T, m *Model, k tea.KeyPressMsg) *Model {
	t.Helper()
	next, _ := m.Update(k)
	return next.(*Model)
}

func text(s string) tea.KeyPressMsg {
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func TestStartupPIDPickerTypesQAndHIntoTheFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	if m.router.current() != ScreenPIDPicker || hasReturn(m) {
		t.Fatalf("expected the startup PID picker")
	}
	m = typeText(t, m, "mysqlHypr")
	if m.router.current() != ScreenPIDPicker {
		t.Fatalf("expected to stay on the picker, got %v", m.router.current())
	}
	if !strings.Contains(m.View().Content, "mysqlHypr") {
		t.Fatalf("expected the picker input to hold the typed text, view:\n%s", m.View().Content)
	}
}

// After Up/Down blurs the picker input, q is a command again (quit), exactly as
// before: only a *focused* input owns the key.
func TestStartupPIDPickerQuitsOnQOnceTheInputIsBlurred(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.pidPicker.TextInputFocused() {
		t.Fatalf("expected Down to blur the picker input")
	}
	next, cmd := m.Update(text("q"))
	assertQuits(t, next, cmd)
}

func TestStartupPIDPickerCtrlCStillQuitsWhileTyping(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m = typeText(t, m, "my")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	assertQuits(t, next, cmd)
}

func TestReselectPIDPickerTypesQIntoTheFilterAndEscStillReturns(t *testing.T) {
	m := newTypingTestModel()
	m.proc.pid = 1111
	m.dashboard.SetPidFilter(1111)
	m = press(t, m, text("2"))
	m = press(t, m, text("p"))
	if m.router.current() != ScreenPIDPicker || !hasReturn(m) {
		t.Fatalf("expected the reselect picker")
	}
	m = typeText(t, m, "mysq")
	if m.router.current() != ScreenPIDPicker {
		t.Fatalf("typing q must not leave the reselect picker, got %v", m.router.current())
	}
	requireViewContains(t, m, "mysq")
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected Esc to still return to the dashboard, got %v", m.router.current())
	}
}

func TestFilterModalEditingTypesQIntoTheField(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("f"))
	if !m.filterModal.Visible() {
		t.Fatalf("expected the filter modal to open")
	}
	m = press(t, m, text("j")) // Syscall -> Comm
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.filterModal.TextInputFocused() {
		t.Fatalf("expected the Comm field to be in edit mode")
	}
	m = typeText(t, m, "mysqldH")
	if !m.filterModal.Visible() {
		t.Fatalf("typing q closed the filter modal")
	}
	if got := len(m.filters.labelStack()); got != 0 {
		t.Fatalf("typing must not apply a filter, stack=%v", m.filters.labelStack())
	}
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	comm := m.filters.current().Comm
	if comm == nil || comm.Pattern != "mysqldH" {
		t.Fatalf("expected the full typed comm to be applied, got %+v", comm)
	}
}

// Outside edit mode the filter modal has no text input, so q keeps its
// close-like-Esc meaning there.
func TestFilterModalNavigationStillClosesOnQ(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("f"))
	m = press(t, m, text("q"))
	if m.filterModal.Visible() || m.quitting {
		t.Fatalf("expected q to close the navigating filter modal (visible=%v quitting=%v)",
			m.filterModal.Visible(), m.quitting)
	}
}

func TestRecordModalTypesQAndH(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("R"))
	if !m.recordModal.Visible() {
		t.Fatalf("expected the record modal to open")
	}
	m = typeText(t, m, "sqlHq")
	if !m.recordModal.Visible() {
		t.Fatalf("typing closed the record modal")
	}
	if !strings.Contains(m.View().Content, "sqlHq") {
		t.Fatalf("expected the typed text in the record modal, view:\n%s", m.View().Content)
	}
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.recordModal.Visible() {
		t.Fatalf("expected Esc to close the record modal")
	}
}

func TestProbeModalSearchTypesQAndHButListKeysStillQuitTheModal(t *testing.T) {
	newModal := func() *Model {
		m := newTypingTestModel()
		m.probeModal = probes.NewModel(fakeProbeManager{
			states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
		}).Open()
		return m
	}

	m := newModal()
	m = press(t, m, text("/"))
	if !m.probeModal.TextInputFocused() {
		t.Fatalf("expected the probe search line to be open")
	}
	m = typeText(t, m, "reqH")
	if !m.probeModal.Visible() {
		t.Fatalf("typing q closed the probe modal")
	}
	requireViewContains(t, m, "reqH")

	m = newModal()
	m = press(t, m, text("q"))
	if m.probeModal.Visible() || m.quitting {
		t.Fatalf("expected q to close the probe modal when no search is open")
	}
}

func TestFlameSearchTypesQAndH(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the flame search to be focused")
	}
	m = typeText(t, m, "sqHq")
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("typing q closed the flame search")
	}
	requireViewContains(t, m, "sqHq")
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.dashboard.TextInputFocused() {
		t.Fatalf("expected Esc to close the flame search")
	}
}

func TestStreamSearchTypesQAndH(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("7"))
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the stream search modal to be focused")
	}
	m = typeText(t, m, "reqHq")
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("typing q closed the stream search")
	}
	requireViewContains(t, m, "reqHq")
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.dashboard.TextInputFocused() {
		t.Fatalf("expected Esc to close the stream search")
	}
}

func TestStreamExportFilenameTypesQAndH(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("7"))
	m = press(t, m, text(" ")) // pause: X is only active while paused
	m = press(t, m, text("X"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the stream export modal to be focused")
	}
	m = typeText(t, m, "queryHq")
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("typing q closed the stream export modal")
	}
	requireViewContains(t, m, "queryHq")
}

// With no input focused, H still opens help and q still quits from the
// dashboard: the fix must not have disabled the shortcuts wholesale.
func TestGlobalShortcutsStillWorkWithoutAFocusedInput(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("H"))
	if !m.helpOverlayVisible {
		t.Fatalf("expected H to open help on a bare dashboard")
	}
	m = press(t, m, text("q"))
	if m.helpOverlayVisible {
		t.Fatalf("expected q to close the help overlay")
	}
	m = press(t, m, text("q"))
	if !m.quitting {
		t.Fatalf("expected q to quit from a bare dashboard")
	}
}

// The TID picker shares the picker code path with the PID picker, but it is
// entered through its own key (t) and constructor, so it gets its own check.
func TestReselectTIDPickerTypesQAndHIntoTheFilter(t *testing.T) {
	m := newTypingTestModel()
	m.proc.pid = 1111
	m.dashboard.SetPidFilter(1111)
	next, _ := m.reselectTID()
	m = next.(*Model)
	if m.router.current() != ScreenPIDPicker || !hasReturn(m) {
		t.Fatalf("expected the reselect TID picker")
	}
	m = typeText(t, m, "mysqHq")
	if m.router.current() != ScreenPIDPicker {
		t.Fatalf("typing q must not leave the TID picker, got %v", m.router.current())
	}
	requireViewContains(t, m, "Select TID for PID 1111")
	requireViewContains(t, m, "mysqHq")
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.router.current() != ScreenDashboard {
		t.Fatalf("expected Esc to return to the dashboard, got %v", m.router.current())
	}
}

// Esc has no text, so it keeps its meaning while the startup picker's input is
// focused and holds typed text: it leaves the picker (and ior) as it always did.
func TestStartupPIDPickerEscStillQuitsWhileTyping(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m = typeText(t, m, "my")
	if !m.pidPicker.TextInputFocused() {
		t.Fatalf("expected the picker input to be focused")
	}
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if cmd == nil {
		t.Fatalf("expected Esc to return a quit command")
	}
	if msg := cmd(); !isQuitMsg(msg) {
		t.Fatalf("expected a quit message from Esc, got %T: %v", msg, msg)
	}
}

// Only printable keys (Key().Text != "") belong to a focused input. Modified
// keys carry no text: they must neither be inserted as characters nor trigger
// the global quit/help shortcuts by accident (alt+q is not q, ctrl+x is not x).
func TestModifiedKeysAreNeitherTextNorShortcutsWhileAnInputIsFocused(t *testing.T) {
	chords := []struct {
		name string
		key  tea.KeyPressMsg
		bad  string // text the chord must not have inserted
	}{
		{name: "alt+q", key: tea.KeyPressMsg{Code: 'q', Mod: tea.ModAlt}, bad: "abq"},
		{name: "alt+H", key: tea.KeyPressMsg{Code: 'H', Mod: tea.ModAlt}, bad: "abH"},
		{name: "ctrl+q", key: tea.KeyPressMsg{Code: 'q', Mod: tea.ModCtrl}, bad: "abq"},
		{name: "ctrl+x", key: tea.KeyPressMsg{Code: 'x', Mod: tea.ModCtrl}, bad: "abx"},
	}
	for _, tc := range chords {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			m = typeText(t, m, "ab")
			next, cmd := m.Update(tc.key)
			m = next.(*Model)
			if cmd != nil {
				if msg := cmd(); isQuitMsg(msg) {
					t.Fatalf("%s quit the program", tc.name)
				}
			}
			if m.quitting || m.helpOverlayVisible {
				t.Fatalf("%s triggered a global shortcut (quitting=%v help=%v)",
					tc.name, m.quitting, m.helpOverlayVisible)
			}
			view := m.View().Content
			if strings.Contains(view, tc.bad) {
				t.Fatalf("%s was inserted as text, view:\n%s", tc.name, view)
			}
			if !strings.Contains(view, "ab") {
				t.Fatalf("%s disturbed the typed text, view:\n%s", tc.name, view)
			}
		})
	}
}

// ctrl+r is the picker's refresh key while its input is focused (a plain r is
// text there): it rescans without touching the filter text or leaving the
// picker.
func TestCtrlRRefreshesTheFocusedPickerWithoutTyping(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m = typeText(t, m, "ab")
	next, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Mod: tea.ModCtrl})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected ctrl+r to return a rescan command")
	}
	if got := fmt.Sprintf("%T", cmd()); !strings.HasSuffix(got, "processesLoadedMsg") {
		t.Fatalf("expected the rescan result message, got %s", got)
	}
	if m.quitting || m.router.current() != ScreenPIDPicker {
		t.Fatalf("ctrl+r must stay on the picker (quitting=%v screen=%v)", m.quitting, m.router.current())
	}
	view := m.View().Content
	if strings.Contains(view, "abr") || !strings.Contains(view, "ab") {
		t.Fatalf("ctrl+r must leave the filter text alone, view:\n%s", view)
	}
	// The footer advertises the key that works in this state.
	if !strings.Contains(view, "ctrl+r refresh") {
		t.Fatalf("expected the footer to name ctrl+r while the input is focused, view:\n%s", view)
	}
}

// While the dashboard is still attaching, textInputFocused must answer false
// even if a dashboard input reports focus (a flame search opened before the
// trace restart began): the attaching overlay owns the screen, and q is the
// documented way out of it. Without the attaching guard the focused input
// would swallow that q.
func TestAttachingOverlayIgnoresAFocusedDashboardInput(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the flame search to be focused")
	}
	m.attaching = true
	if m.textInputFocused() {
		t.Fatalf("textInputFocused must be false while attaching")
	}
	next, cmd := m.Update(text("q"))
	assertQuits(t, next, cmd)
}
