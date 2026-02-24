package export

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
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
