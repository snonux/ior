package tui

import (
	"context"
	"testing"

	"ior/internal/tui/messages"
)

// TestOpenEditorRequestRoutesToDashboard checks the stream's editor request,
// which the dashboard returns as a command, finds its way back through the
// top-level Update to the dashboard that runs the editor process.
func TestOpenEditorRequestRoutesToDashboard(t *testing.T) {
	t.Setenv("EDITOR", "true")
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	_, cmd := m.Update(messages.OpenEditorRequestedMsg{Path: "stream.csv"})
	if cmd == nil {
		t.Fatalf("expected the dashboard to answer an editor request with the editor process command")
	}
}
