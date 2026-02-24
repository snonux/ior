package dashboard

import (
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
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

	refreshEvery    time.Duration
	keys            common.KeyMap
	syscallsOffset  int
	filesOffset     int
	processesOffset int
}

// NewModel creates a dashboard model with default refresh cadence.
func NewModel(engine SnapshotSource) Model {
	return NewModelWithConfig(engine, defaultRefreshMs, common.Keys)
}

// NewModelWithConfig creates a dashboard model with explicit refresh and keys.
func NewModelWithConfig(engine SnapshotSource, refreshMs int, keys common.KeyMap) Model {
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
		m.syscallsOffset = clampOffset(m.syscallsOffset, m.maxSyscallsRows())
		m.filesOffset = clampOffset(m.filesOffset, m.maxFilesRows())
		m.processesOffset = clampOffset(m.processesOffset, m.maxProcessesRows())
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	keyStr := msg.String()
	if m.handleArrowTabKey(keyStr) {
		return m, nil
	}
	if m.handleScrollKey(keyStr) {
		return m, nil
	}

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
	case key.Matches(msg, m.keys.Refresh):
		snap := m.snapshot()
		return m, func() tea.Msg { return messages.StatsTickMsg{Snap: snap} }
	}
	return m, nil
}

func (m *Model) handleArrowTabKey(keyStr string) bool {
	switch keyStr {
	case "right", "l":
		m.activeTab = nextTab(m.activeTab)
		return true
	case "left", "h":
		m.activeTab = prevTab(m.activeTab)
		return true
	default:
		return false
	}
}

func (m *Model) handleScrollKey(keyStr string) bool {
	switch m.activeTab {
	case TabSyscalls:
		return scrollOffset(keyStr, &m.syscallsOffset, m.maxSyscallsRows())
	case TabFiles:
		return scrollOffset(keyStr, &m.filesOffset, m.maxFilesRows())
	case TabProcesses:
		return scrollOffset(keyStr, &m.processesOffset, m.maxProcessesRows())
	default:
		return false
	}
}

func scrollOffset(keyStr string, offset *int, maxRows int) bool {
	switch keyStr {
	case "down", "j":
		if *offset < maxRows-1 {
			*offset++
		}
		return true
	case "up", "k":
		if *offset > 0 {
			*offset--
		}
		return true
	default:
		return false
	}
}

func (m Model) maxSyscallsRows() int {
	if m.latest == nil {
		return 0
	}
	return m.latest.SyscallsCount()
}

func (m Model) maxFilesRows() int {
	if m.latest == nil {
		return 0
	}
	return m.latest.FilesCount()
}

func (m Model) maxProcessesRows() int {
	if m.latest == nil {
		return 0
	}
	return m.latest.ProcessesCount()
}

func (m Model) snapshot() *statsengine.Snapshot {
	if m.engine == nil {
		return nil
	}
	return m.engine.Snapshot()
}

// LatestSnapshot returns the most recently received snapshot.
func (m Model) LatestSnapshot() *statsengine.Snapshot {
	return m.latest
}

// View renders the tab bar, active tab scaffold, and help bar.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, m.width))
	b.WriteString("\n")
	b.WriteString(renderActiveTab(m.activeTab, m.latest, m.width, m.height, m.syscallsOffset, m.filesOffset, m.processesOffset))
	b.WriteString("\n")
	b.WriteString(common.HighlightStyle.Render("Press ? for help"))
	b.WriteString("\n")
	b.WriteString(renderHelpBar(m.keys))
	return common.ScreenStyle.Render(b.String())
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

func renderActiveTab(tab Tab, snap *statsengine.Snapshot, width, height, syscallsOffset, filesOffset, processesOffset int) string {
	if snap == nil {
		return common.PanelStyle.Render(tab.String() + ": waiting for stats...")
	}

	switch tab {
	case TabOverview:
		return renderOverview(snap, width, height)
	case TabSyscalls:
		return renderSyscallsWithOffset(snap, width, height, syscallsOffset)
	case TabFiles:
		return renderFilesWithOffset(snap, width, height, filesOffset)
	case TabProcesses:
		return renderProcessesWithOffset(snap, width, height, processesOffset)
	case TabLatency:
		return renderLatencyTab(snap, width, height)
	case TabGaps:
		return renderGapsTab(snap, width, height)
	default:
		return common.PanelStyle.Render("Unknown tab")
	}
}
