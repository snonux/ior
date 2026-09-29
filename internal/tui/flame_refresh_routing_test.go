package tui

import (
	"context"
	"errors"
	"testing"

	coreflamegraph "ior/internal/flamegraph"

	tea "charm.land/bubbletea/v2"
)

func TestDispatchedFlameRefreshCompletionSurvivesTopLevelOverlays(t *testing.T) {
	states := []string{
		"pid picker",
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
			m := newTopLevelFlameRefreshModel(t)
			flameTick, completion := dispatchTopLevelFlameRefresh(t, m)

			setTopLevelFlameRefreshHidden(m, state, true)
			if !topLevelFlameRefreshHidden(m, state) {
				t.Fatal("test setup did not hide the dashboard")
			}
			next, cmd := m.Update(completion)
			m = next.(*Model)
			if cmd != nil {
				t.Fatalf("hidden refresh completion scheduled a command")
			}

			setTopLevelFlameRefreshHidden(m, state, false)
			next, cmd = m.Update(flameTick)
			if next != m {
				t.Fatalf("flame tick returned %T at a different address", next)
			}
			batch := requireTopLevelBatch(t, cmd)
			if len(batch) < 2 {
				t.Fatalf("later flame tick dispatched %d commands, want tick plus refresh", len(batch))
			}
		})
	}
}

func setTopLevelFlameRefreshHidden(m *Model, state string, hidden bool) {
	switch state {
	case "pid picker":
		if hidden {
			m.router = newScreenRouter(ScreenPIDPicker)
		} else {
			m.router.showDashboard()
		}
	case "attaching overlay":
		m.attaching = hidden
	case "filter modal":
		if hidden {
			m.filterModal = m.filterModal.Open(m.filters.current())
		} else {
			m.filterModal = m.filterModal.Close()
		}
	case "record modal":
		if hidden {
			m.recordModal = m.recordModal.Open("capture.parquet")
		} else {
			m.recordModal = m.recordModal.Close()
		}
	case "probe modal":
		if hidden {
			m.probeModal = m.probeModal.Open()
		} else {
			m.probeModal = m.probeModal.Close()
		}
	case "export modal":
		if hidden {
			m.exporter = m.exporter.Open()
		} else {
			m.exporter = m.exporter.Close()
		}
	case "help overlay":
		m.helpOverlayVisible = hidden
	case "error screen":
		if hidden {
			m.lastErr = errors.New("trace failed")
		} else {
			m.lastErr = nil
		}
	case "quitting screen":
		m.quitting = hidden
	}
}

func topLevelFlameRefreshHidden(m *Model, state string) bool {
	switch state {
	case "pid picker":
		return m.router.current() == ScreenPIDPicker
	case "attaching overlay":
		return m.attaching
	case "filter modal":
		return m.filterModal.Visible()
	case "record modal":
		return m.recordModal.Visible()
	case "probe modal":
		return m.probeModal.Visible()
	case "export modal":
		return m.exporter.Visible()
	case "help overlay":
		return m.helpOverlayVisible
	case "error screen":
		return m.lastErr != nil
	case "quitting screen":
		return m.quitting
	default:
		return false
	}
}

func newTopLevelFlameRefreshModel(t *testing.T) *Model {
	t.Helper()
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 0)

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = 120
	m.height = 30
	m.runtime.SetLiveTrie(liveTrie)
	next, _ := m.Update(TracingStartedMsg{})
	m = next.(*Model)
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 1)
	return m
}

func dispatchTopLevelFlameRefresh(t *testing.T, m *Model) (tea.Msg, tea.Msg) {
	t.Helper()
	// Init only asks for the tick chains to start; handling that request
	// schedules the refresh and flame ticks. The auto-reset timer is off
	// so Init's single command is that request.
	m.dashboard.SetAutoResetInterval(0)
	next, startCmd := m.Update(m.dashboard.Init()())
	if next != m {
		t.Fatalf("tick chain start returned %T at a different address", next)
	}
	startBatch := requireTopLevelBatch(t, startCmd)
	if len(startBatch) < 2 {
		t.Fatalf("tick chain start dispatched %d commands, want standard and flame ticks", len(startBatch))
	}
	flameTick := startBatch[1]()
	next, cmd := m.Update(flameTick)
	if next != m {
		t.Fatalf("flame tick returned %T at a different address", next)
	}
	refreshBatch := requireTopLevelBatch(t, cmd)
	if len(refreshBatch) < 2 {
		t.Fatalf("flame tick dispatched %d commands, want tick plus refresh", len(refreshBatch))
	}
	return flameTick, refreshBatch[1]()
}

func requireTopLevelBatch(t *testing.T, cmd tea.Cmd) tea.BatchMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected batch command")
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("command produced %T, want tea.BatchMsg", msg)
	}
	return batch
}
