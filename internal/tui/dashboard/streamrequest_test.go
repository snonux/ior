package dashboard

import (
	"strings"
	"testing"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// runeKey builds the key press for a single printable rune.
func runeKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

// TestStreamEnterReturnsGlobalFilterRequest drives the dashboard with a key
// press and checks the stream's request surfaces as the command's message,
// rather than being parked on the stream model for a later drain.
func TestStreamEnterReturnsGlobalFilterRequest(t *testing.T) {
	m := newPausedStreamModel(t)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected paused stream enter to return a command")
	}
	req, ok := cmd().(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %#v", cmd())
	}
	if req.Action == "" || !req.Filter.IsActive() {
		t.Fatalf("expected a labelled, active filter request, got %+v", req)
	}

	// A following navigation key must not replay the request.
	_, cmd = m.Update(runeKey('j'))
	if cmd != nil {
		if _, replayed := cmd().(messages.GlobalFilterRequestedMsg); replayed {
			t.Fatalf("expected navigation not to re-emit the filter request")
		}
	}
}

// TestStreamOpenLastExportRoundTrip covers x then E on the paused stream: E
// returns an OpenEditorRequestedMsg, and feeding that message back into Update
// yields the editor process command.
func TestStreamOpenLastExportRoundTrip(t *testing.T) {
	t.Chdir(t.TempDir()) // the stream exports into the working directory
	t.Setenv("EDITOR", "true")
	m := newPausedStreamModel(t)

	next, _ := m.Update(runeKey('x'))
	m = next.(*Model)

	next, cmd := m.Update(runeKey('E'))
	m = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected E after an export to return a command")
	}
	req, ok := cmd().(messages.OpenEditorRequestedMsg)
	if !ok {
		t.Fatalf("expected OpenEditorRequestedMsg, got %#v", cmd())
	}
	if req.Path == "" {
		t.Fatalf("expected the export path in the editor request")
	}

	_, cmd = m.Update(req)
	if cmd == nil {
		t.Fatalf("expected OpenEditorRequestedMsg to produce the editor process command")
	}
}

// TestStreamOpenWithoutExportReturnsNoRequest is the negative case: E before
// any export only sets a status line and asks nothing of the parent.
func TestStreamOpenWithoutExportReturnsNoRequest(t *testing.T) {
	m := newPausedStreamModel(t)

	next, cmd := m.Update(runeKey('E'))
	m = next.(*Model)
	if cmd != nil {
		if msg, ok := cmd().(messages.OpenEditorRequestedMsg); ok {
			t.Fatalf("expected no editor request without an export, got %+v", msg)
		}
	}
	if view := m.View().Content; !strings.Contains(view, "No stream export yet") {
		t.Fatalf("expected the stream status to read %q, got %q", "No stream export yet", view)
	}
}
