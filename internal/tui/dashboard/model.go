package dashboard

import (
	"fmt"
	"ior/internal/statsengine"
	"ior/internal/tui"
	"ior/internal/tui/messages"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

const defaultRefreshMs = 1000

// SnapshotSource is the dashboard data source.
type SnapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

type refreshTickMsg struct{}

// Model is the dashboard tab framework model.
type Model struct {
	activeTab Tab

	engine SnapshotSource
	latest *statsengine.Snapshot

	width  int
	height int

	refreshEvery time.Duration
	keys         tui.KeyMap
}

// NewModel creates a dashboard model with default refresh cadence.
func NewModel(engine SnapshotSource) Model {
	return NewModelWithConfig(engine, defaultRefreshMs, tui.Keys)
}

// NewModelWithConfig creates a dashboard model with explicit refresh and keys.
func NewModelWithConfig(engine SnapshotSource, refreshMs int, keys tui.KeyMap) Model {
	if refreshMs <= 0 {
		refreshMs = defaultRefreshMs
	}
	return Model{
		activeTab:    TabOverview,
		engine:       engine,
		refreshEvery: time.Duration(refreshMs) * time.Millisecond,
		keys:         keys,
	}
}

// Init starts periodic refresh ticks.
func (m Model) Init() tea.Cmd {
	return tickCmd(m.refreshEvery)
}

// Update handles ticks, snapshots, tab changes, and resize events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case refreshTickMsg:
		snap := m.snapshot()
		return m, tea.Batch(
			tickCmd(m.refreshEvery),
			func() tea.Msg { return messages.StatsTickMsg{Snap: snap} },
		)
	case messages.StatsTickMsg:
		m.latest = msg.Snap
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Tab):
		m.activeTab = nextTab(m.activeTab)
	case key.Matches(msg, m.keys.ShiftTab):
		m.activeTab = prevTab(m.activeTab)
	case key.Matches(msg, m.keys.One):
		m.activeTab = TabOverview
	case key.Matches(msg, m.keys.Two):
		m.activeTab = TabSyscalls
	case key.Matches(msg, m.keys.Three):
		m.activeTab = TabFiles
	case key.Matches(msg, m.keys.Four):
		m.activeTab = TabProcesses
	case key.Matches(msg, m.keys.Five):
		m.activeTab = TabLatency
	case key.Matches(msg, m.keys.Six):
		m.activeTab = TabGaps
	}
	return m, nil
}

func (m Model) snapshot() *statsengine.Snapshot {
	if m.engine == nil {
		return nil
	}
	return m.engine.Snapshot()
}

// View renders the tab bar, active tab scaffold, and help bar.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, m.width))
	b.WriteString("\n")
	b.WriteString(renderActiveTab(m.activeTab, m.latest, m.width, m.height))
	b.WriteString("\n")
	b.WriteString(renderHelpBar(m.keys))
	return tui.ScreenStyle.Render(b.String())
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

func renderActiveTab(tab Tab, snap *statsengine.Snapshot, width, height int) string {
	_ = width
	_ = height

	if snap == nil {
		return tui.PanelStyle.Render(tab.String() + ": waiting for stats...")
	}

	switch tab {
	case TabOverview:
		return tui.PanelStyle.Render(fmt.Sprintf("Overview: %d syscalls", snap.TotalSyscalls))
	case TabSyscalls:
		return tui.PanelStyle.Render(fmt.Sprintf("Syscalls: %d rows", len(snap.Syscalls())))
	case TabFiles:
		return tui.PanelStyle.Render(fmt.Sprintf("Files: %d rows", len(snap.Files())))
	case TabProcesses:
		return tui.PanelStyle.Render(fmt.Sprintf("Processes: %d rows", len(snap.Processes())))
	case TabLatency:
		return tui.PanelStyle.Render("Latency histogram")
	case TabGaps:
		return tui.PanelStyle.Render("Gap histogram")
	default:
		return tui.PanelStyle.Render("Unknown tab")
	}
}
