package dashboard

import (
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	"ior/internal/tui/messages"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

const defaultRefreshMs = 1000
const streamRefreshMs = 200

// SnapshotSource is the dashboard data source.
type SnapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

type refreshTickMsg struct{}
type streamTickMsg struct{}

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
	filesDirGrouped bool
	filesDirOffset  int
	processesOffset int
	streamModel     eventstream.Model
}

// NewModel creates a dashboard model with default refresh cadence.
func NewModel(engine SnapshotSource, streamSource *eventstream.RingBuffer) Model {
	return NewModelWithConfig(engine, streamSource, defaultRefreshMs, common.Keys)
}

// NewModelWithConfig creates a dashboard model with explicit refresh and keys.
func NewModelWithConfig(engine SnapshotSource, streamSource *eventstream.RingBuffer, refreshMs int, keys common.KeyMap) Model {
	if refreshMs <= 0 {
		refreshMs = defaultRefreshMs
	}
	return Model{
		activeTab:    TabOverview,
		engine:       engine,
		refreshEvery: time.Duration(refreshMs) * time.Millisecond,
		keys:         keys,
		streamModel:  eventstream.NewModel(streamSource),
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
	case streamTickMsg:
		if m.activeTab != TabStream {
			return m, nil
		}
		m.streamModel.Refresh()
		return m, streamTickCmd()
	case messages.StatsTickMsg:
		m.latest = msg.Snap
		m.syscallsOffset = clampOffset(m.syscallsOffset, m.maxSyscallsRows())
		m.filesOffset = clampOffset(m.filesOffset, m.maxFilesRows())
		m.filesDirOffset = clampOffset(m.filesDirOffset, m.maxFilesDirRows())
		m.processesOffset = clampOffset(m.processesOffset, m.maxProcessesRows())
		m.streamModel.Refresh()
		return m, nil
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	prevActiveTab := m.activeTab
	var cmd tea.Cmd
	keyStr := msg.String()
	handled := m.handleArrowTabKey(keyStr) || m.handleScrollKey(keyStr)

	if !handled {
		switch {
		case key.Matches(msg, m.keys.Tab):
			m.activeTab = nextTab(m.activeTab)
			handled = true
		case key.Matches(msg, m.keys.ShiftTab):
			m.activeTab = prevTab(m.activeTab)
			handled = true
		case key.Matches(msg, m.keys.One):
			m.activeTab = TabOverview
			handled = true
		case key.Matches(msg, m.keys.Two):
			m.activeTab = TabSyscalls
			handled = true
		case key.Matches(msg, m.keys.Three):
			m.activeTab = TabFiles
			handled = true
		case key.Matches(msg, m.keys.Four):
			m.activeTab = TabProcesses
			handled = true
		case key.Matches(msg, m.keys.Five):
			m.activeTab = TabLatency
			handled = true
		case key.Matches(msg, m.keys.Six):
			m.activeTab = TabStream
			handled = true
		case key.Matches(msg, m.keys.Seven):
			m.activeTab = TabStream
			handled = true
		case key.Matches(msg, m.keys.Refresh):
			snap := m.snapshot()
			cmd = func() tea.Msg { return messages.StatsTickMsg{Snap: snap} }
			handled = true
		case key.Matches(msg, m.keys.DirGroup):
			if m.activeTab == TabFiles {
				m.filesDirGrouped = !m.filesDirGrouped
				handled = true
			}
		}
	}
	if !handled {
		return m, nil
	}
	if prevActiveTab != TabStream && m.activeTab == TabStream {
		if cmd == nil {
			return m, streamTickCmd()
		}
		return m, tea.Batch(cmd, streamTickCmd())
	}
	return m, cmd
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
		if m.filesDirGrouped {
			return scrollOffset(keyStr, &m.filesDirOffset, m.maxFilesDirRows())
		}
		return scrollOffset(keyStr, &m.filesOffset, m.maxFilesRows())
	case TabProcesses:
		return scrollOffset(keyStr, &m.processesOffset, m.maxProcessesRows())
	case TabStream:
		return m.streamModel.HandleKey(keyStr)
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

func (m Model) maxFilesDirRows() int {
	if m.latest == nil {
		return 0
	}
	return len(aggregateFilesByDir(m.latest.Files()))
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

// BlocksGlobalShortcuts reports whether modal UI in the active tab should
// suppress top-level shortcuts (for example global export key handling).
func (m Model) BlocksGlobalShortcuts() bool {
	return m.activeTab == TabStream && m.streamModel.FilterModalVisible()
}

// SetStreamSource updates the live stream source used by the stream tab.
func (m *Model) SetStreamSource(source *eventstream.RingBuffer) {
	m.streamModel.SetSource(source)
}

// View renders the tab bar, active tab scaffold, and help bar.
func (m Model) View() string {
	width, height := common.EffectiveViewport(m.width, m.height)

	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, width))
	b.WriteString("\n")
	b.WriteString(renderActiveTab(
		m.activeTab,
		m.latest,
		&m.streamModel,
		width,
		height,
		m.syscallsOffset,
		m.filesOffset,
		m.filesDirGrouped,
		m.filesDirOffset,
		m.processesOffset,
	))
	b.WriteString("\n")
	b.WriteString(common.HighlightStyle.Render("Press ? for help"))
	b.WriteString("\n")
	b.WriteString(renderHelpBar(m.keys))
	return common.ScreenStyle.Render(b.String())
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

func renderActiveTab(tab Tab, snap *statsengine.Snapshot, streamModel *eventstream.Model, width, height, syscallsOffset, filesOffset int, filesDirGrouped bool, filesDirOffset, processesOffset int) string {
	if tab == TabStream {
		if streamModel == nil {
			return common.PanelStyle.Render("Stream: waiting for source...")
		}
		return streamModel.View(width, height)
	}

	if snap == nil {
		return common.PanelStyle.Render(tab.String() + ": waiting for stats...")
	}

	switch tab {
	case TabOverview:
		return renderOverview(snap, width, height)
	case TabSyscalls:
		return renderSyscallsWithOffset(snap, width, height, syscallsOffset)
	case TabFiles:
		if filesDirGrouped {
			return renderFilesDirGrouped(snap, width, height, filesDirOffset)
		}
		return renderFilesWithOffset(snap, width, height, filesOffset)
	case TabProcesses:
		return renderProcessesWithOffset(snap, width, height, processesOffset)
	case TabLatency:
		return renderLatencyGapsTab(snap, width, height)
	default:
		return common.PanelStyle.Render("Unknown tab")
	}
}

func streamTickCmd() tea.Cmd {
	return tea.Tick(streamRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return streamTickMsg{} })
}
