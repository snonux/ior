package export

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// TestViewInvisibleReturnsEmpty verifies that View returns an empty string when
// the modal is not visible.
func TestViewInvisibleReturnsEmpty(t *testing.T) {
	m := NewModel()
	if out := m.View(80, 24); out != "" {
		t.Fatalf("expected empty view when invisible, got %q", out)
	}
}

// TestViewVisibleContainsOptionLabels verifies that View renders option labels
// while the modal is open.
func TestViewVisibleContainsOptionLabels(t *testing.T) {
	m := NewModel().Open()
	out := m.View(80, 24)
	for _, label := range optionLabels {
		if !strings.Contains(out, label) {
			t.Fatalf("expected option label %q in view, got:\n%s", label, out)
		}
	}
	if !strings.Contains(out, "Enter confirm") {
		t.Fatalf("expected help text in view, got:\n%s", out)
	}
}

// TestViewZeroDimensionsUsesDefaults verifies that zero width/height fall back
// to defaults without panicking.
func TestViewZeroDimensionsUsesDefaults(t *testing.T) {
	m := NewModel().Open()
	out := m.View(0, 0)
	if out == "" {
		t.Fatal("expected non-empty view with zero dimensions")
	}
}

// TestViewNarrowWidthClamped verifies that very narrow widths are clamped to a
// minimum modal width.
func TestViewNarrowWidthClamped(t *testing.T) {
	m := NewModel().Open()
	// Should not panic on very narrow terminals.
	out := m.View(10, 24)
	if out == "" {
		t.Fatal("expected non-empty view on narrow terminal")
	}
}

// TestViewExportingHidesHelp verifies that the help text "Enter confirm" is
// hidden while an export is in progress.
func TestViewExportingHidesHelp(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	out := m.View(80, 24)
	if strings.Contains(out, "Enter confirm") {
		t.Fatalf("expected help hidden while exporting, got:\n%s", out)
	}
}

// TestViewShowsStatus verifies that status messages appear in the view.
func TestViewShowsStatus(t *testing.T) {
	m := NewModel().Open()
	m.status = "Export done: out.csv"
	out := m.View(80, 24)
	if !strings.Contains(out, "Export done: out.csv") {
		t.Fatalf("expected status in view, got:\n%s", out)
	}
}

// TestUpDownKeysChangeSelection verifies that up/down and j/k move the
// selected option index.
func TestUpDownKeysChangeSelection(t *testing.T) {
	m := NewModel().Open()

	// Move down to last option.
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if m.selected != 1 {
		t.Fatalf("expected selected=1 after j, got %d", m.selected)
	}

	// Move up back to first.
	m, _ = m.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: "k"})
	if m.selected != 0 {
		t.Fatalf("expected selected=0 after k, got %d", m.selected)
	}

	// down key alias.
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if m.selected != 1 {
		t.Fatalf("expected selected=1 after down, got %d", m.selected)
	}

	// up key alias.
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyUp})
	if m.selected != 0 {
		t.Fatalf("expected selected=0 after up, got %d", m.selected)
	}
}

// TestKeyIgnoredWhenNotVisible verifies that key events are no-ops when the
// modal is closed.
func TestKeyIgnoredWhenNotVisible(t *testing.T) {
	m := NewModel() // not opened
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("expected no command when modal is invisible")
	}
	if next.selected != 0 {
		t.Fatalf("expected no selection change when invisible, got %d", next.selected)
	}
}

// TestEscWhileExportingCloses verifies that esc can close the modal even while
// an export is in progress.
func TestEscWhileExportingCloses(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	m, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	if m.Visible() {
		t.Fatal("expected modal closed by esc while exporting")
	}
}

// TestCompletedMsgWithEmptyPathUsesDone verifies that an empty path in
// CompletedMsg defaults to "done".
func TestCompletedMsgWithEmptyPathUsesDone(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	m, _ = m.Update(CompletedMsg{Path: ""})
	if !strings.Contains(m.status, "done") {
		t.Fatalf("expected 'done' in status for empty path, got %q", m.status)
	}
}

// TestFailedMsgWithNilErrUsesDefault verifies that a nil error in FailedMsg
// produces a non-empty error message.
func TestFailedMsgWithNilErrUsesDefault(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	m, _ = m.Update(FailedMsg{Err: nil})
	if m.status == "" {
		t.Fatal("expected non-empty status after FailedMsg with nil error")
	}
}

// TestUnknownMsgIsNoOp verifies that unsupported message types leave the model
// unchanged.
func TestUnknownMsgIsNoOp(t *testing.T) {
	m := NewModel().Open()
	next, cmd := m.Update("unknown message type")
	if cmd != nil {
		t.Fatal("expected no command for unknown message")
	}
	if next.selected != m.selected {
		t.Fatalf("unexpected state change on unknown msg")
	}
}

// TestKeyIgnoredWhenExportingAndNotEsc verifies that non-esc keys are ignored
// during an in-progress export.
func TestKeyIgnoredWhenExportingAndNotEsc(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	origSelected := m.selected
	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: "j"})
	if cmd != nil {
		t.Fatal("expected no command for j during export")
	}
	if next.selected != origSelected {
		t.Fatalf("expected selection unchanged during export, got %d", next.selected)
	}
	if !next.Visible() {
		t.Fatal("expected modal still visible during export")
	}
}

// TestUpdateWithErrors verifies the error recovery path for unknown errors.
func TestUpdateWithErrors(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true
	m, _ = m.Update(FailedMsg{Err: errors.New("disk full")})
	if !strings.Contains(m.status, "disk full") {
		t.Fatalf("expected disk full in status, got %q", m.status)
	}
	if m.exporting {
		t.Fatal("expected exporting=false after failure")
	}
}
