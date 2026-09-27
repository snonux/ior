package tui

import (
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// handleOpenEditorRequested routes the stream tab's editor request explicitly
// rather than leaving it to modal dispatch and the active screen, either of
// which could swallow it and leave the stream footer claiming the editor is
// opening. The request goes to the dashboard only while the dashboard is the
// live screen (a modal on top of it does not matter: the editor suspends the
// whole program); otherwise the dashboard is told to mark it cancelled.
func (m *Model) handleOpenEditorRequested(msg messages.OpenEditorRequestedMsg) (tea.Model, tea.Cmd) {
	if m.router.current() != ScreenDashboard || m.attaching || m.quitting {
		m.dashboard.CancelOpenEditorRequest(msg)
		return m, nil
	}
	next, cmd := m.dashboard.Update(msg)
	m.dashboard = next.(*dashboardui.Model)
	return m, cmd
}
