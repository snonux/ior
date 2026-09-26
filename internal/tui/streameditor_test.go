package tui

import (
	"context"
	"strings"
	"testing"

	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// newEditorRoutingModel returns a top-level model on the dashboard, not
// attaching, with a no-op editor configured.
func newEditorRoutingModel(t *testing.T) *Model {
	t.Helper()
	t.Setenv("EDITOR", "true")
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	return m
}

// TestOpenEditorRequestRouting checks the stream's editor request, which the
// dashboard returns as a command, is answered by the dashboard with the editor
// process command when the dashboard is live, and is cancelled (not silently
// dropped) when it is not.
func TestOpenEditorRequestRouting(t *testing.T) {
	req := messages.OpenEditorRequestedMsg{Path: "stream.csv"}

	t.Run("dashboard", func(t *testing.T) {
		m := newEditorRoutingModel(t)
		_, cmd := m.Update(req)
		if cmd == nil {
			t.Fatalf("expected the editor process command")
		}
	})

	t.Run("modal visible", func(t *testing.T) {
		m := newEditorRoutingModel(t)
		next, _ := m.Update(tea.KeyPressMsg{Code: 'f', Text: "f"})
		m = next.(*Model)
		if !m.filterModal.Visible() {
			t.Fatalf("precondition: expected the global filter modal open")
		}
		_, cmd := m.Update(req)
		if cmd == nil {
			t.Fatalf("expected a modal over the dashboard not to swallow the editor request")
		}
	})

	cancelled := []struct {
		name  string
		setup func(m *Model)
	}{
		{"attaching", func(m *Model) { m.attaching = true }},
		{"pid picker", func(m *Model) { m.screen = ScreenPIDPicker }},
		{"quitting", func(m *Model) { m.quitting = true }},
	}
	for _, tc := range cancelled {
		t.Run(tc.name, func(t *testing.T) {
			m := newEditorRoutingModel(t)
			tc.setup(m)
			_, cmd := m.Update(req)
			if cmd != nil {
				t.Fatalf("expected no editor command while %s", tc.name)
			}
			if got := pausedStreamFooter(t, m); !strings.Contains(got, "Open cancelled: stream.csv") {
				t.Fatalf("expected the stream status to report the cancelled open, got %q", got)
			}
		})
	}
}

// pausedStreamFooter restores m to a live dashboard, switches to the stream
// tab, pauses it (so its footer and status line render) and returns the view.
func pausedStreamFooter(t *testing.T, m *Model) string {
	t.Helper()
	m.screen = ScreenDashboard
	m.attaching = false
	m.quitting = false
	for _, msg := range []tea.Msg{
		tea.WindowSizeMsg{Width: 120, Height: 30},
		tea.KeyPressMsg{Code: '7', Text: "7"},
		tea.KeyPressMsg{Code: tea.KeySpace, Text: " "},
	} {
		next, _ := m.Update(msg)
		m = next.(*Model)
	}
	return m.View().Content
}
