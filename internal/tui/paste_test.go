package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ior/internal/probemanager"
	"ior/internal/tui/probes"

	tea "charm.land/bubbletea/v2"
)

// Task 4r2: bubbletea v2 turns on bracketed paste, so a terminal paste reaches
// the program as ONE tea.PasteMsg instead of a run of key presses. Every text
// input has to accept it; before the fix the filter modal, the flame search,
// the stream search/export modals and the probes search line dropped it, so
// pasting a path into the File filter silently did nothing. The record modal and
// the picker already forwarded it. Each test pastes into one input and requires
// the text to be visible there (and, where cheap, applied).

// paste sends text to the model as a bracketed paste.
func paste(m *Model, content string) *Model {
	next, _ := m.Update(tea.PasteMsg{Content: content})
	return next.(*Model)
}

// openFileFilterEdit opens the filter modal and starts editing the File field.
func openFileFilterEdit(t *testing.T, m *Model) *Model {
	t.Helper()
	m = press(t, m, text("f"))
	if !m.filterModal.Visible() {
		t.Fatalf("expected the filter modal to open")
	}
	m = press(t, m, text("j")) // Syscall -> Comm
	m = press(t, m, text("j")) // Comm -> File
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.filterModal.TextInputFocused() {
		t.Fatalf("expected the File field to be in edit mode")
	}
	return m
}

func TestPasteIntoFilterModalFileFieldIsAppliedAsFilter(t *testing.T) {
	m := openFileFilterEdit(t, newTypingTestModel())
	m = paste(m, "/var/log/messages")
	requireViewContains(t, m, "/var/log/messages")
	if len(m.filters.labelStack()) != 0 {
		t.Fatalf("a paste must not apply the filter before the edit is committed")
	}
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyEsc})
	file := m.filters.current().File
	if file == nil || file.Pattern != "/var/log/messages" {
		t.Fatalf("expected the pasted path to become the File filter, got %+v", file)
	}
}

// Text already in the field stays and the paste lands at the cursor, like a
// paste in any other input; newlines are flattened by the text input, so a
// multi-line clipboard cannot smuggle a line break into a pattern.
func TestPasteIntoFilterModalAppendsAndFlattensNewlines(t *testing.T) {
	m := openFileFilterEdit(t, newTypingTestModel())
	m = typeText(t, m, "ab")
	m = paste(m, "c\nd")
	requireViewContains(t, m, "abc d")
}

// Outside edit mode the filter modal's keys are commands (c clears, q closes,
// j moves); a paste there has no input to go to and must not act as those keys.
func TestPasteIntoNavigatingFilterModalIsIgnored(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("f"))
	m = paste(m, "cjjq")
	if !m.filterModal.Visible() || m.quitting {
		t.Fatalf("a paste closed or quit the navigating filter modal")
	}
	if m.filterModal.TextInputFocused() {
		t.Fatalf("a paste must not start editing a field")
	}
	if got := len(m.filters.labelStack()); got != 0 {
		t.Fatalf("a paste must not apply a filter, stack=%v", m.filters.labelStack())
	}
}

func TestPasteIntoFlameSearch(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the flame search to be focused")
	}
	m = paste(m, "vfs_read")
	requireViewContains(t, m, "vfs_read")
	if m.quitting || m.helpOverlayVisible {
		t.Fatalf("a paste into the flame search triggered a global shortcut")
	}
}

func TestPasteIntoStreamSearch(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("7"))
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the stream search modal to be focused")
	}
	m = paste(m, "openat.*messages")
	requireViewContains(t, m, "openat.*messages")
}

func TestPasteIntoStreamExportFilename(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("7"))
	m = press(t, m, text(" ")) // pause: X is only active while paused
	m = press(t, m, text("X"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the stream export modal to be focused")
	}
	m = paste(m, "pasted-export.csv")
	requireViewContains(t, m, "pasted-export.csv")
}

func TestPasteIntoProbesSearch(t *testing.T) {
	m := newTypingTestModel()
	m.probeModal = probes.NewModel(fakeProbeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}, {Syscall: "write", Active: true}},
	}).Open()
	m = press(t, m, text("/"))
	if !m.probeModal.TextInputFocused() {
		t.Fatalf("expected the probe search line to be open")
	}
	m = paste(m, "wri")
	requireViewContains(t, m, "wri")
	view := m.View().Content
	if strings.Contains(view, "read") {
		t.Fatalf("expected the pasted search to filter out read, view:\n%s", view)
	}
}

// The probes list keys are commands (a all-on, n all-off, q close, space
// toggle); a paste with the search line closed must not run any of them.
func TestPasteIntoProbesListIsIgnored(t *testing.T) {
	m := newTypingTestModel()
	m.probeModal = probes.NewModel(fakeProbeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}).Open()
	m = paste(m, "qan")
	if !m.probeModal.Visible() || m.quitting {
		t.Fatalf("a paste closed the probes modal")
	}
	if m.probeModal.TextInputFocused() {
		t.Fatalf("a paste must not open the search line")
	}
}

// The record modal and the picker took a paste before the fix; pin them so a
// later routing change cannot regress them unnoticed.
func TestPasteIntoRecordModalStillWorks(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("R"))
	m = paste(m, "/tmp/pasted.parquet")
	requireViewContains(t, m, "/tmp/pasted.parquet")
}

func TestPasteIntoPIDPickerFocusesABlurredInput(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m = paste(m, "mysqld")
	requireViewContains(t, m, "mysqld")

	// Down blurs the input; a paste is typing, so it re-focuses it like a
	// printable key does instead of vanishing.
	m = press(t, m, tea.KeyPressMsg{Code: tea.KeyDown})
	if m.pidPicker.TextInputFocused() {
		t.Fatalf("expected Down to blur the picker input")
	}
	m = paste(m, "x")
	if !m.pidPicker.TextInputFocused() {
		t.Fatalf("expected the paste to focus the picker input")
	}
	requireViewContains(t, m, "mysqldx")
}

// With no text input open a paste is not a run of shortcuts: pasting "q7H/"
// must not quit, switch tabs, open help or open the flame search.
func TestPasteOnBareDashboardDoesNothing(t *testing.T) {
	m := newTypingTestModel()
	tab := m.dashboard.ActiveTab()
	m = paste(m, "q7H/fRX")
	if m.quitting || m.helpOverlayVisible || m.filterModal.Visible() || m.recordModal.Visible() {
		t.Fatalf("a paste on the bare dashboard ran a shortcut")
	}
	if m.dashboard.TextInputFocused() {
		t.Fatalf("a paste on the bare dashboard opened a text input")
	}
	if m.dashboard.ActiveTab() != tab {
		t.Fatalf("a paste switched the tab from %v to %v", tab, m.dashboard.ActiveTab())
	}
}

// A view that takes no text (help overlay, full-screen error, attaching) covers
// the screens; the input hiding underneath must not get the paste. The record
// modal is the probe because it accepts pastes by itself (its Update forwards
// every message to its input), so only the top-level gate can keep the text out.
func TestPasteIsDroppedWhileAnOverlayCoversTheInput(t *testing.T) {
	cases := map[string]func(m *Model){
		"help overlay": func(m *Model) { m.helpOverlayVisible = true },
		"error screen": func(m *Model) { m.lastErr = errors.New("boom") },
		"attaching":    func(m *Model) { m.attaching = true },
	}
	for name, cover := range cases {
		t.Run(name, func(t *testing.T) {
			m := press(t, newTypingTestModel(), text("R"))
			if !m.recordModal.Visible() {
				t.Fatalf("expected the record modal to open")
			}
			cover(m)
			m = paste(m, "/hidden")
			m.helpOverlayVisible, m.lastErr, m.attaching = false, nil, false
			if view := m.View().Content; strings.Contains(view, "/hidden") {
				t.Fatalf("the paste reached the record modal behind the %s, view:\n%s", name, view)
			}
		})
	}
}

// updateDashboardForModal is reached for a paste whenever a modal is visible
// over a dashboard whose own text input is focused (here the stream search:
// the state a modal opened programmatically, or by a future shortcut, would
// leave behind). The paste belongs to the modal alone; forwarding it would
// fill the search input hidden underneath, unseen, and it would show up once
// the modal closed. The modal is in navigation mode so it takes no text
// itself, which leaves the hidden input as the only possible recipient.
func TestPasteWhileModalCoversFocusedDashboardInputIsNotForwarded(t *testing.T) {
	m := newTypingTestModel()
	m = press(t, m, text("7"))
	m = press(t, m, text("/"))
	if !m.dashboard.TextInputFocused() {
		t.Fatalf("expected the stream search modal to be focused")
	}
	m.filterModal = m.filterModal.Open(m.filters.current())
	if !m.filterModal.Visible() || m.filterModal.TextInputFocused() {
		t.Fatalf("expected a navigating filter modal over the dashboard")
	}
	m = paste(m, "leaked-into-search")
	m.filterModal = m.filterModal.Close()
	if view := m.View().Content; strings.Contains(view, "leaked-into-search") {
		t.Fatalf("the paste reached the stream search behind the modal, view:\n%s", view)
	}
}

// The paste gate (textlessViewCovers) and the mouse/async gate
// (overlayCoversScreen) are built from the same two helpers; this table pins
// every overlay state against both, so a new overlay cannot be wired into one
// gate and forgotten in the other: a textless view covers the screen for both,
// a modal covers it for the mouse gate only (the modal takes the paste itself).
func TestOverlayPredicatesCoverEveryOverlayState(t *testing.T) {
	cases := []struct {
		state            string
		covers, textless bool
	}{
		{"none", false, false},
		{"attaching overlay", true, true},
		{"help overlay", true, true},
		{"error screen", true, true},
		{"quitting screen", true, true},
		{"filter modal", true, false},
		{"record modal", true, false},
		{"probe modal", true, false},
		{"export modal", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			m := newTypingTestModel()
			setTopLevelFlameRefreshHidden(m, tc.state, true)
			if got := m.overlayCoversScreen(); got != tc.covers {
				t.Fatalf("overlayCoversScreen = %t, want %t", got, tc.covers)
			}
			if got := m.textlessViewCovers(); got != tc.textless {
				t.Fatalf("textlessViewCovers = %t, want %t", got, tc.textless)
			}
			if tc.covers != (m.textlessViewCovers() || m.modalVisible()) {
				t.Fatalf("overlayCoversScreen is not textless-or-modal")
			}
		})
	}
}
