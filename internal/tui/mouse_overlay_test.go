package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	tea "charm.land/bubbletea/v2"
)

// newFlameMouseModel returns a dashboard on the Flame tab with a rendered
// flame graph, settled at the unzoomed root.
func newFlameMouseModel(t *testing.T) *Model {
	t.Helper()
	m := newTopLevelFlameRefreshModel(t)
	flameTick, completion := dispatchTopLevelFlameRefresh(t, m)
	next, _ := m.Update(completion)
	m = next.(*Model)
	for range 10 {
		next, _ = m.Update(flameTick)
		m = next.(*Model)
	}
	if !strings.Contains(flameHeader(m), "view:root |") {
		t.Fatalf("precondition: flame not at the unzoomed root: %q", flameHeader(m))
	}
	return m
}

// flameHeader returns the flame tab's status header line as drawn, which
// names the zoomed view ("view:root", "view:root/api", ...).
func flameHeader(m *Model) string {
	return strings.SplitN(ansi.Strip(m.View().Content), "\n", 3)[1]
}

// apiRowClick returns a left click on the wide "api" frame of the root
// layout, which zooms the flame graph into view:root/api.
func apiRowClick(t *testing.T, m *Model) tea.MouseClickMsg {
	t.Helper()
	for y, line := range strings.Split(ansi.Strip(m.View().Content), "\n") {
		if strings.HasPrefix(line, "api") {
			return tea.MouseClickMsg{X: 1, Y: y, Button: tea.MouseLeft}
		}
	}
	t.Fatal("no api frame row in the flame view")
	return tea.MouseClickMsg{}
}

// TestMouseClickZoomsVisibleFlame pins the control case: without an overlay
// the same click zooms, so the overlay tests below fail for the right reason.
func TestMouseClickZoomsVisibleFlame(t *testing.T) {
	m := newFlameMouseModel(t)
	click := apiRowClick(t, m)
	next, _ := m.Update(click)
	m = next.(*Model)
	if got := flameHeader(m); !strings.Contains(got, "view:root/api") {
		t.Fatalf("click on the visible flame did not zoom: %q", got)
	}
}

// TestMouseIgnoredWhileOverlayCoversDashboard is the regression test for task
// 5r2: a click (and any other pointer event) made while the help overlay, a
// modal, or the error, attaching or shutdown screen is showing must not reach
// the Flame tab behind it and zoom it while hidden.
func TestMouseIgnoredWhileOverlayCoversDashboard(t *testing.T) {
	states := []string{
		"attaching overlay",
		"filter modal",
		"record modal",
		"probe modal",
		"export modal",
		"help overlay",
		"error screen",
		"quitting screen",
	}
	for _, state := range states {
		t.Run(state, func(t *testing.T) {
			m := newFlameMouseModel(t)
			click := apiRowClick(t, m)

			setTopLevelFlameRefreshHidden(m, state, true)
			if !topLevelFlameRefreshHidden(m, state) {
				t.Fatal("test setup did not hide the dashboard")
			}
			pointer := click.Mouse()
			for _, msg := range []tea.Msg{
				click,
				tea.MouseReleaseMsg(pointer),
				tea.MouseMotionMsg(pointer),
				tea.MouseWheelMsg{X: pointer.X, Y: pointer.Y, Button: tea.MouseWheelDown},
			} {
				next, cmd := m.Update(msg)
				if next != m {
					t.Fatalf("%T returned %T at a different address", msg, next)
				}
				if cmd != nil {
					t.Fatalf("%T while hidden scheduled a command", msg)
				}
			}

			setTopLevelFlameRefreshHidden(m, state, false)
			if got := flameHeader(m); !strings.Contains(got, "view:root |") {
				t.Fatalf("mouse events reached the hidden flame tab: %q", got)
			}
		})
	}
}
