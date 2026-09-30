package export

import (
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func TestOpenAndClose(t *testing.T) {
	m := NewModel().Open()
	if !m.Visible() {
		t.Fatalf("expected modal to be visible after Open")
	}
	m = m.Close()
	if m.Visible() {
		t.Fatalf("expected modal to be hidden after Close")
	}
}

func TestEnterEmitsRequest(t *testing.T) {
	m := NewModel().Open()
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatalf("expected request command on enter")
	}
	if !next.exporting {
		t.Fatalf("expected exporting state after enter")
	}
	req, ok := cmd().(RequestMsg)
	if !ok {
		t.Fatalf("expected RequestMsg from enter command")
	}
	if req.Option != OptionCSV {
		t.Fatalf("expected CSV as default export option, got %v", req.Option)
	}
}

func TestCancelOptionCloses(t *testing.T) {
	m := NewModel().Open()
	m.selected = len(optionValues) - 1
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil {
		t.Fatalf("expected no command when selecting cancel")
	}
	if next.Visible() {
		t.Fatalf("expected modal to close on cancel option")
	}
}

func TestStatusMessages(t *testing.T) {
	m := NewModel().Open()
	m.exporting = true

	next, _ := m.Update(CompletedMsg{Path: "out.csv"})
	if next.exporting {
		t.Fatalf("expected exporting=false after completion")
	}
	if !strings.Contains(next.status, "out.csv") {
		t.Fatalf("expected completion path in status")
	}

	next.exporting = true
	next, _ = next.Update(FailedMsg{Err: errors.New("boom")})
	if next.exporting {
		t.Fatalf("expected exporting=false after failure")
	}
	if !strings.Contains(next.status, "boom") {
		t.Fatalf("expected failure reason in status")
	}
}

// The modal states that the export is the live ring only while the stream is
// paused; a live stream keeps the original wording (task 2r2).
func TestViewPausedNoteOnlyWhilePaused(t *testing.T) {
	live := NewModel().Open().View(80, 24)
	if strings.Contains(live, "paused") || !strings.Contains(live, "CSV stream rows") {
		t.Fatalf("live modal wording changed:\n%s", live)
	}
	paused := strings.Join(strings.Fields(strings.ReplaceAll(NewModel().OpenFor(true).View(80, 24), "│", " ")), " ")
	for _, want := range []string{"CSV stream rows", "Live ring, not the paused view - use x on the Stream tab for the paused rows"} {
		if !strings.Contains(paused, want) {
			t.Fatalf("paused modal lacks %q:\n%s", want, paused)
		}
	}
	if strings.Contains(NewModel().OpenFor(true).Open().View(80, 24), "paused") {
		t.Fatalf("Open must reset to the live wording")
	}
}

// The note must survive word-wrapping intact at every plausible terminal width
// (the modal shrinks to width-4, floor 30) and must point at the Stream tab,
// since x/X do nothing from the other tabs (task 2r2).
func TestPausedNoteWrapsCleanlyAtNarrowWidths(t *testing.T) {
	if !strings.Contains(PausedNote, "Stream tab") {
		t.Fatalf("note must name the Stream tab: %q", PausedNote)
	}
	for _, width := range []int{40, 60, 80, 120} {
		view := NewModel().OpenFor(true).View(width, 24)
		got := strings.Join(strings.Fields(strings.ReplaceAll(view, "│", " ")), " ")
		if !strings.Contains(got, PausedNote) {
			t.Fatalf("width %d: note lost or mangled by wrapping:\n%s", width, view)
		}
	}
}
