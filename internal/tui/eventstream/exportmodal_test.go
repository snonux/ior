package eventstream

import (
	"errors"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func modalKey(t *testing.T, m ExportModal, msg tea.KeyPressMsg) ExportModal {
	t.Helper()
	m, _, submitted := m.Update(msg)
	if submitted {
		t.Fatalf("key %v unexpectedly submitted", msg)
	}
	return m
}

// TestExportModalRejectKeepsTheCursor: Reject reopens the input as the user
// left it, so a cursor in the middle of the name stays there instead of
// jumping to the end (Open's behaviour) and the name can be fixed in place.
func TestExportModalRejectKeepsTheCursor(t *testing.T) {
	m := NewExportModal().Open("abcdef")
	for range 3 {
		m = modalKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	}
	m, name, submitted := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !submitted || name != "abcdef" || m.Visible() {
		t.Fatalf("setup: submitted=%v name=%q visible=%v", submitted, name, m.Visible())
	}

	m = m.Reject(name, errors.New("nope"))
	if !m.Visible() || m.err != "nope" || m.textInput.Value() != "abcdef" {
		t.Fatalf("Reject: visible=%v err=%q value=%q", m.Visible(), m.err, m.textInput.Value())
	}
	if got := m.textInput.Position(); got != 3 {
		t.Fatalf("cursor at %d after Reject, want 3 (where the user left it)", got)
	}
	if !m.textInput.Focused() {
		t.Fatal("the rejected input must be focused for further typing")
	}
}

// TestExportModalRejectTrimmedNameKeepsTypedText: the submitted name is
// trimmed, but the input still holds what was typed, spaces included, and the
// cursor with it.
func TestExportModalRejectTrimmedNameKeepsTypedText(t *testing.T) {
	m := NewExportModal().Open("  a  ")
	m, name, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = m.Reject(name, errors.New("nope"))
	if got := m.textInput.Value(); got != "  a  " {
		t.Fatalf("typed text changed to %q", got)
	}
	if got := m.textInput.Position(); got != 5 {
		t.Fatalf("cursor at %d, want 5", got)
	}
}

// TestExportModalRejectOtherNameReplacesInput: a Reject for a name the input
// does not hold (a caller passing a different name) shows that name, cursor
// at the end like Open.
func TestExportModalRejectOtherNameReplacesInput(t *testing.T) {
	m := NewExportModal().Open("old").Close()
	m = m.Reject("other.csv", errors.New("nope"))
	if !m.Visible() || m.textInput.Value() != "other.csv" || m.textInput.Position() != len("other.csv") {
		t.Fatalf("visible=%v value=%q pos=%d", m.Visible(), m.textInput.Value(), m.textInput.Position())
	}
}

// TestExportModalErrorClearsOnEdit pins when an error goes away: typing or
// deleting makes it stale and clears it (this covers the "filename is
// required" message too), cursor movement keeps it.
func TestExportModalErrorClearsOnEdit(t *testing.T) {
	m := NewExportModal().Open("")
	m, _, submitted := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if submitted || m.err != "filename is required" {
		t.Fatalf("setup: submitted=%v err=%q", submitted, m.err)
	}
	m = modalKey(t, m, tea.KeyPressMsg{Code: tea.KeyLeft})
	if m.err == "" {
		t.Fatal("cursor movement must not clear the error")
	}
	m = modalKey(t, m, tea.KeyPressMsg{Code: 'a', Text: "a"})
	if m.err != "" {
		t.Fatalf("typing should clear the error, still %q", m.err)
	}

	m = m.Reject("a", errors.New("nope"))
	m = modalKey(t, m, tea.KeyPressMsg{Code: tea.KeyBackspace})
	if m.err != "" {
		t.Fatalf("deleting should clear the error, still %q", m.err)
	}
}
