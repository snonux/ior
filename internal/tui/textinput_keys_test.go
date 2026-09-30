package tui

import (
	"context"
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
