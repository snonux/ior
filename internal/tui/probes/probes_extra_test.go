package probes

import (
	"strings"
	"testing"

	"ior/internal/probemanager"

	tea "charm.land/bubbletea/v2"
)

// TestVisibleReturnsFalseBeforeOpen verifies that a freshly constructed model
// is not visible.
func TestVisibleReturnsFalseBeforeOpen(t *testing.T) {
	m := NewModel(nil)
	if m.Visible() {
		t.Fatal("expected model to be invisible after NewModel")
	}
}

// TestSetDarkModeDoesNotPanic verifies that SetDarkMode can be called without
// panicking regardless of mode.
func TestSetDarkModeDoesNotPanic(t *testing.T) {
	m := NewModel(nil)
	m = m.SetDarkMode(false)
	m = m.SetDarkMode(true)
	_ = m
}

// TestNavigationKeysMoveCursor verifies that j/k and down/up keys move the
// cursor within the filtered list.
func TestNavigationKeysMoveCursor(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{
			{Syscall: "read", Active: true},
			{Syscall: "write", Active: true},
			{Syscall: "openat", Active: true},
		},
	}
	m := NewModel(fm).Open()

	// Move down twice.
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if m.cursor != 2 {
		t.Fatalf("expected cursor=2 after two j presses, got %d", m.cursor)
	}

	// Move up once.
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.cursor != 1 {
		t.Fatalf("expected cursor=1 after k press, got %d", m.cursor)
	}

	// down/up aliases.
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if m.cursor != 2 {
		t.Fatalf("expected cursor=2 after down press, got %d", m.cursor)
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	if m.cursor != 1 {
		t.Fatalf("expected cursor=1 after up press, got %d", m.cursor)
	}
}

// TestEscClosesModal verifies that pressing esc returns an invisible model.
func TestEscClosesModal(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.Visible() {
		t.Fatal("expected modal closed after esc")
	}
}

// TestUpdateIgnoredWhenNotVisible verifies that key events are no-ops when the
// model is closed.
func TestUpdateIgnoredWhenNotVisible(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm) // not opened
	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if cmd != nil {
		t.Fatal("expected no command when model is closed")
	}
	if next.cursor != 0 {
		t.Fatalf("cursor moved while closed, got %d", next.cursor)
	}
}

// TestSearchFilterNarrowsResults verifies that typing '/' followed by a search
// term filters the visible probe list.
func TestSearchFilterNarrowsResults(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{
			{Syscall: "read", Active: true},
			{Syscall: "write", Active: true},
			{Syscall: "readlink", Active: false},
		},
	}
	m := NewModel(fm).Open()

	// Enter search mode.
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	if !m.searching {
		t.Fatal("expected searching=true after /")
	}

	// Type "read" via individual rune key presses so the textinput accumulates
	// the characters, then confirm with enter.
	for _, ch := range "read" {
		m, _ = m.Update(tea.KeyPressMsg{Code: ch, Text: string(ch)})
	}
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if m.searching {
		t.Fatal("expected searching=false after enter")
	}
	if m.search != "read" {
		t.Fatalf("expected search=read, got %q", m.search)
	}

	filtered := m.filtered()
	for _, p := range filtered {
		if !strings.Contains(p.Syscall, "read") {
			t.Fatalf("unexpected probe %q in filtered list", p.Syscall)
		}
	}
}

// TestSearchEscCancelsSearch verifies that pressing esc during search exits
// search mode without applying the filter.
func TestSearchEscCancelsSearch(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{
			{Syscall: "read", Active: true},
			{Syscall: "write", Active: true},
		},
	}
	m := NewModel(fm).Open()

	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: "/"})
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.searching {
		t.Fatal("expected searching=false after esc")
	}
	// Filter should not be active.
	if len(m.filtered()) != 2 {
		t.Fatalf("expected 2 unfiltered probes after esc, got %d", len(m.filtered()))
	}
}

// TestProbeToggledMsgUpdatesState verifies that ProbeToggledMsg triggers a
// reload and clears any previous error.
func TestProbeToggledMsgUpdatesState(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	m.lastErr = "previous error"

	// Add a new probe to the manager so reload picks it up.
	fm.states = append(fm.states, probemanager.ProbeState{Syscall: "write", Active: false})

	m, _ = m.Update(ProbeToggledMsg{Syscall: "read"})
	if m.lastErr != "" {
		t.Fatalf("expected lastErr cleared after successful toggle, got %q", m.lastErr)
	}
	if len(m.probes) != 2 {
		t.Fatalf("expected probes refreshed to 2 entries, got %d", len(m.probes))
	}
}

// TestProbeToggledMsgSetsError verifies that a ProbeToggledMsg carrying an
// error populates lastErr.
func TestProbeToggledMsgSetsError(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	m, _ = m.Update(ProbeToggledMsg{Syscall: "read", Err: &testErr{"boom"}})
	if !strings.Contains(m.lastErr, "boom") {
		t.Fatalf("expected lastErr to contain boom, got %q", m.lastErr)
	}
}

// testErr is a minimal error implementation for testing error message capture.
type testErr struct{ msg string }

func (e *testErr) Error() string { return e.msg }

// TestViewRendersEmptyProbeList verifies that View returns a non-empty string
// even when the probe list is empty.
func TestViewRendersEmptyProbeList(t *testing.T) {
	fm := &fakeManager{states: nil}
	m := NewModel(fm).Open()
	out := m.View(80, 24)
	if out == "" {
		t.Fatal("expected non-empty View output")
	}
	if !strings.Contains(out, "no probes") {
		t.Fatalf("expected 'no probes' in view output, got:\n%s", out)
	}
}

// TestViewInvisibleReturnsEmpty verifies that View returns an empty string when
// the model is not visible.
func TestViewInvisibleReturnsEmpty(t *testing.T) {
	m := NewModel(nil) // not opened
	if out := m.View(80, 24); out != "" {
		t.Fatalf("expected empty View when not visible, got %q", out)
	}
}

// TestVisibleRowsDefault verifies the fallback when height is zero.
func TestVisibleRowsDefault(t *testing.T) {
	m := NewModel(nil)
	m.height = 0
	if got := m.visibleRows(); got != 10 {
		t.Fatalf("visibleRows with height=0 = %d, want 10", got)
	}
}

// TestVisibleRowsMinimum verifies that visibleRows never returns less than 3.
func TestVisibleRowsMinimum(t *testing.T) {
	m := NewModel(nil)
	m.height = 5
	if got := m.visibleRows(); got < 3 {
		t.Fatalf("visibleRows = %d, want >= 3", got)
	}
}

// TestSanitizeOneLine verifies embedded control characters are replaced with
// spaces.
func TestSanitizeOneLine(t *testing.T) {
	out := sanitizeOneLine("a\nb\rc\td")
	if strings.ContainsAny(out, "\n\r\t") {
		t.Fatalf("sanitizeOneLine left control chars: %q", out)
	}
	if out != "a b c d" {
		t.Fatalf("sanitizeOneLine = %q, want 'a b c d'", out)
	}
}

// TestTruncateText verifies ellipsis truncation and edge cases.
func TestTruncateText(t *testing.T) {
	if got := truncateText("hello", 10); got != "hello" {
		t.Fatalf("truncateText no-op = %q, want hello", got)
	}
	if got := truncateText("hello world", 8); got != "hello..." {
		t.Fatalf("truncateText 8 = %q, want hello...", got)
	}
	if got := truncateText("ab", 2); got != "ab" {
		t.Fatalf("truncateText exact = %q, want ab", got)
	}
	if got := truncateText("abc", 3); got != "abc" {
		t.Fatalf("truncateText exact 3 = %q, want abc", got)
	}
	if got := truncateText("abcde", 3); got != "abc" {
		t.Fatalf("truncateText short limit = %q, want abc", got)
	}
	if got := truncateText("abcde", 0); got != "" {
		t.Fatalf("truncateText 0 = %q, want empty", got)
	}
}

// TestToggleCmdNilManager verifies that toggleCmd with a nil manager returns a
// ProbeToggledMsg carrying an error.
func TestToggleCmdNilManager(t *testing.T) {
	cmd := toggleCmd(nil, "read")
	msg := cmd()
	toggled, ok := msg.(ProbeToggledMsg)
	if !ok {
		t.Fatalf("expected ProbeToggledMsg, got %T", msg)
	}
	if toggled.Err == nil {
		t.Fatal("expected error from nil manager toggle")
	}
}

// TestBulkToggleCmdNilManager verifies that bulkToggleCmd with a nil manager
// returns a ProbeToggledMsg carrying an error.
func TestBulkToggleCmdNilManager(t *testing.T) {
	cmd := bulkToggleCmd(nil, nil, false)
	msg := cmd()
	toggled, ok := msg.(ProbeToggledMsg)
	if !ok {
		t.Fatalf("expected ProbeToggledMsg, got %T", msg)
	}
	if toggled.Err == nil {
		t.Fatal("expected error from nil manager bulk toggle")
	}
}

// TestEnterKeyTogglesSelectedProbe verifies that pressing enter emits a toggle
// command equivalent to space.
func TestEnterKeyTogglesSelectedProbe(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "write", Active: false}},
	}
	m := NewModel(fm).Open()
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("expected toggle command on enter")
	}
	msg := cmd()
	toggled, ok := msg.(ProbeToggledMsg)
	if !ok {
		t.Fatalf("expected ProbeToggledMsg, got %T", msg)
	}
	if toggled.Err != nil {
		t.Fatalf("unexpected toggle error: %v", toggled.Err)
	}
}

// TestFKeySetsSearchMode verifies that pressing 'f' also enters search mode.
func TestFKeySetsSearchMode(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: "f"})
	if !m.searching {
		t.Fatal("expected searching=true after 'f'")
	}
}

// TestViewWithProbeErrors verifies that View shows probe error annotations.
func TestViewWithProbeErrors(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{
			{Syscall: "read", Active: true, Error: "attach failed"},
		},
	}
	m := NewModel(fm).Open()
	out := m.View(80, 24)
	if !strings.Contains(out, "attach failed") {
		t.Fatalf("expected probe error in view, got:\n%s", out)
	}
}

// TestViewRendersLastError verifies that lastErr is shown in the view.
func TestViewRendersLastError(t *testing.T) {
	fm := &fakeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}
	m := NewModel(fm).Open()
	m.lastErr = "something went wrong"
	out := m.View(80, 24)
	if !strings.Contains(out, "something went wrong") {
		t.Fatalf("expected lastErr in view, got:\n%s", out)
	}
}
