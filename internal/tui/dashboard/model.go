package dashboard

import (
	"strings"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	flamegraphtui "ior/internal/tui/flamegraph"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

const defaultRefreshMs = 1000
const streamRefreshMs = 200
const flameRefreshMs = 200
const bubbleRefreshMs = 33
const streamChromeRows = 4
const dashboardHelpHintRows = 1
const dashboardExpandedHelpRows = 2
const dashboardTabBarRows = 1

// SnapshotSource is the dashboard data source.
type SnapshotSource interface {
	Snapshot() *statsengine.Snapshot
}

type resettableSnapshotSource interface {
	Reset()
	Snapshot() *statsengine.Snapshot
}

type refreshTickMsg struct{}
type streamTickMsg struct{}
type flameTickMsg struct{}
type bubbleTickMsg struct{}
type streamEditorDoneMsg struct {
	err error
}

type tabVizMode uint8

const (
	tabVizModeTable tabVizMode = iota
	tabVizModeBubbles
	tabVizModeTreemap
	tabVizModeIcicle
)

// Model is the dashboard tab framework model.
type Model struct {
	activeTab Tab

	engine   SnapshotSource
	latest   *statsengine.Snapshot
	liveTrie flamegraphtui.LiveTrieSource

	width  int
	height int

	refreshEvery             time.Duration
	keys                     common.KeyMap
	globalFilter             globalfilter.Filter
	pidFilter                int
	syscallsOffset           int
	syscallsTreemapSelection int
	filesOffset              int
	filesDirGrouped          bool
	filesDirOffset           int
	processesOffset          int
	syscallsVizMode          tabVizMode
	filesVizMode             tabVizMode
	processesVizMode         tabVizMode
	streamModel              eventstream.Model
	flamegraphModel          flamegraphtui.Model
	syscallsChart            bubbleChart
	filesChart               bubbleChart
	processesChart           bubbleChart
	showHelp                 bool
	isDark                   bool
	focused                  bool
}

// NewModel creates a dashboard model with default refresh cadence.
func NewModel(engine SnapshotSource, streamSource eventstream.Source) Model {
	return NewModelWithConfig(engine, streamSource, defaultRefreshMs, common.Keys)
}

// NewModelWithConfig creates a dashboard model with explicit refresh and keys.
func NewModelWithConfig(engine SnapshotSource, streamSource eventstream.Source, refreshMs int, keys common.KeyMap) Model {
	if refreshMs <= 0 {
		refreshMs = defaultRefreshMs
	}
	m := Model{
		activeTab:        TabFlame,
		engine:           engine,
		refreshEvery:     time.Duration(refreshMs) * time.Millisecond,
		keys:             keys,
		pidFilter:        -1,
		syscallsVizMode:  tabVizModeTable,
		filesVizMode:     tabVizModeTable,
		processesVizMode: tabVizModeTable,
		streamModel:      eventstream.NewModel(streamSource),
		flamegraphModel:  flamegraphtui.NewModel(nil),
		syscallsChart:    newBubbleChart(),
		filesChart:       newBubbleChart(),
		processesChart:   newBubbleChart(),
		isDark:           true,
		focused:          true,
	}
	m.SetDarkMode(true)
	return m
}

// Init starts periodic refresh ticks.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{tickCmd(m.refreshEvery)}
	switch m.activeTab {
	case TabStream:
		cmds = append(cmds, streamTickCmd())
	case TabFlame:
		cmds = append(cmds, flameTickCmd())
	default:
		if m.bubbleEnabledForTab(m.activeTab) {
			cmds = append(cmds, bubbleTickCmdFn())
		}
	}
	if len(cmds) == 1 {
		return cmds[0]
	}
	return tea.Batch(cmds...)
}

// Update handles ticks, snapshots, tab changes, and resize events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.handleWindowSize(msg)
	case refreshTickMsg:
		return m.handleRefreshTick()
	case streamTickMsg:
		return m.handleStreamTick()
	case flameTickMsg:
		return m.handleFlameTick()
	case bubbleTickMsg:
		return m.handleBubbleTick()
	case messages.StatsTickMsg:
		return m.handleStatsTick(msg)
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	case streamEditorDoneMsg:
		return m.handleStreamEditorDone(msg)
	}
	return m.handleActiveTabMsg(msg)
}

func (m Model) handleWindowSize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.width = msg.Width
	m.height = msg.Height
	streamWidth, streamHeight := streamViewport(msg.Width, msg.Height)
	m.streamModel.SetViewport(streamWidth, streamHeight)
	flameWidth, flameHeight := flameViewport(msg.Width, msg.Height, m.showHelp)
	m.flamegraphModel.SetViewport(flameWidth, flameHeight)
	m.setBubbleViewports(flameWidth, flameHeight)
	if m.bubbleEnabledForTab(m.activeTab) && m.refreshBubbleData() {
		return m, bubbleTickCmdFn()
	}
	return m, nil
}

func (m Model) handleRefreshTick() (tea.Model, tea.Cmd) {
	if !m.focused {
		return m, nil
	}
	snap := m.snapshot()
	return m, tea.Batch(
		tickCmd(m.refreshEvery),
		func() tea.Msg { return messages.StatsTickMsg{Snap: snap} },
	)
}

func (m Model) handleStreamTick() (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabStream {
		return m, nil
	}
	m.streamModel.Refresh()
	return m, streamTickCmd()
}

func (m Model) handleFlameTick() (tea.Model, tea.Cmd) {
	if !m.focused || m.activeTab != TabFlame {
		return m, nil
	}
	var animCmd tea.Cmd
	if m.liveTrie != nil && m.flamegraphModel.RefreshFromLiveTrie() {
		animCmd = m.flamegraphModel.AnimationCmd()
	}
	if animCmd == nil {
		return m, flameTickCmd()
	}
	return m, tea.Batch(flameTickCmd(), animCmd)
}

func (m Model) handleBubbleTick() (tea.Model, tea.Cmd) {
	if !m.focused || !m.bubbleEnabledForTab(m.activeTab) {
		return m, nil
	}
	_ = m.tickActiveBubbleChart()
	if m.activeBubbleChartHasNodes() {
		return m, bubbleTickCmdFn()
	}
	return m, nil
}

func (m Model) handleStatsTick(msg messages.StatsTickMsg) (tea.Model, tea.Cmd) {
	m.latest = msg.Snap
	m.syscallsOffset = clampOffset(m.syscallsOffset, m.maxSyscallsRows())
	m.syscallsTreemapSelection = clampOffset(m.syscallsTreemapSelection, m.maxSyscallsRows())
	m.filesOffset = clampOffset(m.filesOffset, m.maxFilesRows())
	m.filesDirOffset = clampOffset(m.filesDirOffset, m.maxFilesDirRowsForMode())
	m.processesOffset = clampOffset(m.processesOffset, m.maxProcessesRows())
	m.streamModel.Refresh()
	if m.refreshBubbleData() {
		return m, bubbleTickCmdFn()
	}
	return m, nil
}

func (m Model) handleStreamEditorDone(msg streamEditorDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.streamModel.SetStatusMessage("Open failed: " + msg.err.Error())
	}
	return m, nil
}

func (m Model) handleActiveTabMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.activeTab != TabFlame {
		return m, nil
	}
	next, cmd := m.flamegraphModel.Update(translateFlamegraphMsg(msg))
	m.flamegraphModel = next.(flamegraphtui.Model)
	return m, cmd
}

func (m Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if handled, next, cmd := m.handleHelpToggleKey(msg); handled {
		return next, cmd
	}
	if handled, next, cmd := m.handleFlameConsumedKey(msg); handled {
		return next, cmd
	}

	prevActiveTab := m.activeTab
	handled, cmd := m.handleScrollKey(msg)
	if handled && isStreamResumeKey(msg) && m.activeTab == TabStream && !m.streamModel.Paused() {
		cmd = streamTickCmd()
	}
	if !handled {
		handled, cmd = m.handleShortcutKey(msg)
	}
	if !handled {
		return m.handleUnhandledKey(msg)
	}
	return m, m.postKeyTransitionCmd(prevActiveTab, cmd)
}

func (m Model) handleHelpToggleKey(msg tea.KeyPressMsg) (bool, tea.Model, tea.Cmd) {
	if msg.String() != "H" {
		return false, m, nil
	}
	m.showHelp = !m.showHelp
	flameWidth, flameHeight := flameViewport(m.width, m.height, m.showHelp)
	m.flamegraphModel.SetViewport(flameWidth, flameHeight)
	return true, m, nil
}

func (m Model) handleFlameConsumedKey(msg tea.KeyPressMsg) (bool, tea.Model, tea.Cmd) {
	if m.activeTab != TabFlame || !m.flamegraphModel.ConsumesKey(msg) {
		return false, m, nil
	}
	next, cmd := m.flamegraphModel.Update(msg)
	m.flamegraphModel = next.(flamegraphtui.Model)
	return true, m, cmd
}

func (m *Model) handleShortcutKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.One):
		m.activeTab = TabFlame
		return true, nil
	case key.Matches(msg, m.keys.Tab):
		m.activeTab = nextTab(m.activeTab)
		return true, nil
	case key.Matches(msg, m.keys.ShiftTab):
		m.activeTab = prevTab(m.activeTab)
		return true, nil
	case key.Matches(msg, m.keys.Two):
		m.activeTab = TabOverview
		return true, nil
	case key.Matches(msg, m.keys.Three):
		m.activeTab = TabSyscalls
		return true, nil
	case key.Matches(msg, m.keys.Four):
		m.activeTab = TabFiles
		return true, nil
	case key.Matches(msg, m.keys.Five):
		m.activeTab = TabProcesses
		return true, nil
	case key.Matches(msg, m.keys.Six):
		m.activeTab = TabLatency
		return true, nil
	case key.Matches(msg, m.keys.Seven):
		m.activeTab = TabStream
		return true, nil
	case key.Matches(msg, m.keys.Visualize):
		return true, m.cycleVisualizationMode()
	case key.Matches(msg, m.keys.Metric):
		return true, m.toggleBubbleMetric()
	case key.Matches(msg, m.keys.Refresh):
		return true, m.resetBaselineCmd()
	case key.Matches(msg, m.keys.DirGroup):
		if m.activeTab != TabFiles {
			return false, nil
		}
		return true, m.toggleFilesDirGrouping()
	default:
		return false, nil
	}
}

func (m *Model) toggleFilesDirGrouping() tea.Cmd {
	m.filesDirGrouped = !m.filesDirGrouped
	if !m.filesDirGrouped && m.filesVizMode != tabVizModeTable {
		m.filesVizMode = tabVizModeTable
	}
	if m.bubbleEnabledForTab(m.activeTab) && m.refreshBubbleData() {
		return bubbleTickCmdFn()
	}
	return nil
}

func (m Model) handleUnhandledKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.activeTab != TabFlame {
		return m, nil
	}
	next, flameCmd := m.flamegraphModel.Update(msg)
	m.flamegraphModel = next.(flamegraphtui.Model)
	return m, flameCmd
}

func (m Model) postKeyTransitionCmd(prevActiveTab Tab, cmd tea.Cmd) tea.Cmd {
	cmds := make([]tea.Cmd, 0, 4)
	cmds = append(cmds, cmd)
	if prevActiveTab != TabStream && m.activeTab == TabStream {
		cmds = append(cmds, streamTickCmd())
	}
	if prevActiveTab != TabFlame && m.activeTab == TabFlame {
		cmds = append(cmds, flameTickCmd())
	}
	if prevActiveTab != m.activeTab && m.bubbleEnabledForTab(m.activeTab) {
		cmds = append(cmds, bubbleTickCmdFn())
	}
	return batchCmds(cmds...)
}

func isStreamResumeKey(msg tea.KeyPressMsg) bool {
	keyStr := msg.String()
	return keyStr == " " || keyStr == "space"
}

func batchCmds(cmds ...tea.Cmd) tea.Cmd {
	nonNil := make([]tea.Cmd, 0, len(cmds))
	for _, cmd := range cmds {
		if cmd != nil {
			nonNil = append(nonNil, cmd)
		}
	}
	switch len(nonNil) {
	case 0:
		return nil
	case 1:
		return nonNil[0]
	default:
		return tea.Batch(nonNil...)
	}
}

func (m *Model) handleScrollKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	if m.bubbleEnabledForTab(m.activeTab) {
		switch keyStr {
		case "down", "j", "right", "l":
			return m.moveBubbleSelection(1), nil
		case "up", "k", "left", "h":
			return m.moveBubbleSelection(-1), nil
		default:
			return false, nil
		}
	}
	switch m.activeTab {
	case TabSyscalls:
		if m.syscallsVizMode == tabVizModeTreemap {
			return scrollOffset(keyStr, &m.syscallsTreemapSelection, m.maxSyscallsRows()), nil
		}
		return scrollOffset(keyStr, &m.syscallsOffset, m.maxSyscallsRows()), nil
	case TabFiles:
		if m.filesDirGrouped {
			return scrollOffset(keyStr, &m.filesDirOffset, m.maxFilesDirRowsForMode()), nil
		}
		return scrollOffset(keyStr, &m.filesOffset, m.maxFilesRows()), nil
	case TabProcesses:
		return scrollOffset(keyStr, &m.processesOffset, m.maxProcessesRows()), nil
	case TabStream:
		streamWidth, streamHeight := streamViewport(m.width, m.height)
		m.streamModel.SetViewport(streamWidth, streamHeight)
		handled := m.streamModel.HandleTeaKey(msg)
		if path, ok := m.streamModel.ConsumeOpenEditorRequest(); ok {
			editorCmd, err := eventstream.EditorCommandForPath(path)
			if err != nil {
				m.streamModel.SetStatusMessage("Open failed: " + err.Error())
				return true, nil
			}
			return true, tea.ExecProcess(editorCmd, func(err error) tea.Msg {
				return streamEditorDoneMsg{err: err}
			})
		}
		return handled, nil
	default:
		return false, nil
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

func (m Model) maxFilesDirRowsForMode() int {
	if m.filesVizMode != tabVizModeIcicle {
		return m.maxFilesDirRows()
	}
	width, height := flameViewport(m.width, m.height, m.showHelp)
	return filesIcicleTileCount(m.latest, width, height, m.filesChart.Metric())
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

func (m *Model) resetBaselineCmd() tea.Cmd {
	if m.liveTrie != nil {
		m.liveTrie.Reset()
	}

	var snap *statsengine.Snapshot
	if resettable, ok := m.engine.(resettableSnapshotSource); ok {
		resettable.Reset()
		snap = resettable.Snapshot()
	} else {
		snap = m.snapshot()
	}
	return func() tea.Msg { return messages.StatsTickMsg{Snap: snap} }
}

// LatestSnapshot returns the most recently received snapshot.
func (m Model) LatestSnapshot() *statsengine.Snapshot {
	return m.latest
}

// ActiveTab returns the currently selected dashboard tab.
func (m Model) ActiveTab() Tab {
	return m.activeTab
}

// BlocksGlobalShortcuts reports whether the active tab should suppress a
// top-level shortcut for the given key press.
func (m Model) BlocksGlobalShortcuts(msg tea.KeyPressMsg) bool {
	if m.activeTab == TabStream {
		return m.streamModel.ExportModalVisible() || m.streamModel.SearchModalVisible()
	}
	if m.activeTab == TabFlame {
		return m.flamegraphModel.ConsumesKey(msg)
	}
	return false
}

// SetStreamSource updates the live stream source used by the stream tab.
func (m *Model) SetStreamSource(source eventstream.Source) {
	m.streamModel.SetSource(source)
}

// SetGlobalFilter forwards the shared TUI filter into the stream tab so
// buffered rows can be re-filtered immediately.
func (m *Model) SetGlobalFilter(filter globalfilter.Filter) {
	m.globalFilter = filter.Clone()
	m.streamModel.SetFilter(eventstream.Filter(filter))
}

// SetLiveTrie updates the live trie source used by the flamegraph tab.
func (m *Model) SetLiveTrie(liveTrie flamegraphtui.LiveTrieSource) {
	m.liveTrie = liveTrie
	m.flamegraphModel.SetLiveTrie(liveTrie)
	if m.width > 0 && m.height > 0 {
		m.flamegraphModel.SetViewport(m.width, m.height)
	}
	m.flamegraphModel.RefreshFromLiveTrie()
}

// PrepareForTraceRestart clears aggregate state while keeping the current tab
// and retained stream rows intact for the next trace session.
func (m *Model) PrepareForTraceRestart() {
	m.latest = nil
	m.liveTrie = nil
	m.flamegraphModel.SetLiveTrie(nil)
	m.refreshBubbleData()
}

// SetDarkMode updates dashboard child models for the active theme.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.streamModel.SetDarkMode(isDark)
	m.flamegraphModel.SetDarkMode(isDark)
	m.syscallsChart.SetDarkMode(isDark)
	m.filesChart.SetDarkMode(isDark)
	m.processesChart.SetDarkMode(isDark)
}

// SetFocused controls whether periodic refresh ticks are processed.
func (m *Model) SetFocused(focused bool) {
	m.focused = focused
}

// SnapshotCmd returns a command that fetches and emits a fresh dashboard snapshot.
func (m Model) SnapshotCmd() tea.Cmd {
	snap := m.snapshot()
	return func() tea.Msg { return messages.StatsTickMsg{Snap: snap} }
}

// SetPidFilter updates the active PID filter used by tab render hints.
func (m *Model) SetPidFilter(pid int) {
	m.pidFilter = pid
}

// View renders the tab bar, active tab scaffold, and help bar.
func (m Model) View() tea.View {
	width, height := common.EffectiveViewport(m.width, m.height)
	_, activeHeight := flameViewport(width, height, m.showHelp)
	streamModel := m.streamModel
	streamModel.SetFooterVisible(m.showHelp)
	if m.activeTab == TabStream {
		_, activeHeight = streamViewport(width, height)
	}

	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, width))
	b.WriteString("\n")
	b.WriteString(m.renderActiveContent(width, activeHeight, &streamModel))
	b.WriteString("\n")
	if m.showHelp {
		b.WriteString(renderHelpBarWithStatus(m.keys, width, m.filterSummary()))
	} else {
		b.WriteString(renderHelpHintWithStatus(width, m.filterSummary()))
	}
	return tea.NewView(common.ScreenStyle.Render(b.String()))
}

func (m Model) filterSummary() string {
	return "filter: " + m.globalFilter.Summary()
}

func (m Model) renderActiveContent(width, activeHeight int, streamModel *eventstream.Model) string {
	if m.activeTab == TabSyscalls && m.syscallsVizMode == tabVizModeTreemap {
		return renderSyscallsTreemap(m.latest, width, activeHeight, m.syscallsChart.Metric(), m.syscallsTreemapSelection, m.isDark)
	}
	if m.activeTab == TabFiles && m.filesVizMode == tabVizModeTreemap && m.filesDirGrouped {
		return renderFilesTreemap(m.latest, width, activeHeight, m.filesChart.Metric(), m.filesDirOffset, m.isDark)
	}
	if m.activeTab == TabFiles && m.filesVizMode == tabVizModeIcicle && m.filesDirGrouped {
		return renderFilesIcicle(m.latest, width, activeHeight, m.filesChart.Metric(), m.filesDirOffset, m.isDark)
	}
	if m.activeTab == TabProcesses && m.processesVizMode == tabVizModeTreemap {
		return renderProcessesTreemap(m.latest, width, activeHeight, m.processesChart.Metric(), m.processesOffset, m.isDark)
	}
	if m.bubbleEnabledForTab(m.activeTab) {
		switch m.activeTab {
		case TabSyscalls:
			chart := m.syscallsChart
			return chart.Render("Syscalls", width, activeHeight)
		case TabFiles:
			chart := m.filesChart
			return chart.Render("Files/Dirs", width, activeHeight)
		case TabProcesses:
			chart := m.processesChart
			return chart.Render("Processes", width, activeHeight)
		}
	}
	return renderActiveTab(
		m.activeTab,
		m.latest,
		streamModel,
		&m.flamegraphModel,
		width,
		activeHeight,
		m.pidFilter,
		m.syscallsOffset,
		m.filesOffset,
		m.filesDirGrouped,
		m.filesDirOffset,
		m.processesOffset,
	)
}

func (m *Model) setBubbleViewports(width, height int) {
	m.syscallsChart.SetViewport(width, height)
	m.filesChart.SetViewport(width, height)
	m.processesChart.SetViewport(width, height)
}

func (m *Model) refreshBubbleData() bool {
	flameWidth, flameHeight := flameViewport(m.width, m.height, m.showHelp)
	m.setBubbleViewports(flameWidth, flameHeight)

	syscallsAnimating := m.syscallsChart.SetData(syscallBubbleData(m.latest))

	if m.filesDirGrouped {
		m.filesChart.SetStatusHint("")
	} else {
		m.filesChart.SetStatusHint("Files bubble view requires directory mode (press d).")
	}
	filesAnimating := false
	if m.filesDirGrouped {
		filesAnimating = m.filesChart.SetData(filesDirBubbleData(m.latest))
	} else {
		m.filesChart.SetData(nil)
	}
	processesAnimating := m.processesChart.SetData(processBubbleData(m.latest))

	switch m.activeTab {
	case TabSyscalls:
		return m.syscallsVizMode == tabVizModeBubbles && syscallsAnimating
	case TabFiles:
		return m.filesVizMode == tabVizModeBubbles && filesAnimating
	case TabProcesses:
		return m.processesVizMode == tabVizModeBubbles && processesAnimating
	default:
		return false
	}
}

func (m *Model) tickActiveBubbleChart() bool {
	switch m.activeTab {
	case TabSyscalls:
		if m.syscallsVizMode != tabVizModeBubbles {
			return false
		}
		return m.syscallsChart.Tick(0)
	case TabFiles:
		if m.filesVizMode != tabVizModeBubbles {
			return false
		}
		return m.filesChart.Tick(0)
	case TabProcesses:
		if m.processesVizMode != tabVizModeBubbles {
			return false
		}
		return m.processesChart.Tick(0)
	default:
		return false
	}
}

func (m *Model) moveBubbleSelection(delta int) bool {
	switch m.activeTab {
	case TabSyscalls:
		return m.syscallsChart.MoveSelection(delta)
	case TabFiles:
		return m.filesChart.MoveSelection(delta)
	case TabProcesses:
		return m.processesChart.MoveSelection(delta)
	default:
		return false
	}
}

func (m Model) activeBubbleChartHasNodes() bool {
	switch m.activeTab {
	case TabSyscalls:
		return m.syscallsChart.HasNodes()
	case TabFiles:
		return m.filesChart.HasNodes()
	case TabProcesses:
		return m.processesChart.HasNodes()
	default:
		return false
	}
}

func (m Model) bubbleEnabledForTab(tab Tab) bool {
	switch tab {
	case TabSyscalls:
		return m.syscallsVizMode == tabVizModeBubbles
	case TabFiles:
		return m.filesDirGrouped && m.filesVizMode == tabVizModeBubbles
	case TabProcesses:
		return m.processesVizMode == tabVizModeBubbles
	default:
		return false
	}
}

func (m *Model) cycleVisualizationMode() tea.Cmd {
	allowed := m.allowedVizModes(m.activeTab)
	if len(allowed) < 2 {
		return nil
	}
	current := m.tabVizModeFor(m.activeTab)
	next := nextVizMode(current, allowed)
	m.setTabVizMode(m.activeTab, next)

	if next == tabVizModeBubbles {
		m.refreshBubbleData()
		if m.activeBubbleChartHasNodes() {
			return bubbleTickCmdFn()
		}
	}
	return nil
}

func (m *Model) toggleBubbleMetric() tea.Cmd {
	switch m.activeTab {
	case TabSyscalls:
		m.syscallsChart.SetMetric(nextBubbleMetric(m.syscallsChart.Metric()))
		m.refreshBubbleData()
		if m.syscallsVizMode == tabVizModeBubbles && m.activeBubbleChartHasNodes() {
			return bubbleTickCmdFn()
		}
	case TabFiles:
		if !m.filesDirGrouped {
			return nil
		}
		m.filesChart.SetMetric(nextBubbleMetric(m.filesChart.Metric()))
		m.refreshBubbleData()
		if m.filesVizMode == tabVizModeBubbles && m.activeBubbleChartHasNodes() {
			return bubbleTickCmdFn()
		}
	case TabProcesses:
		m.processesChart.SetMetric(nextBubbleMetric(m.processesChart.Metric()))
		m.refreshBubbleData()
		if m.processesVizMode == tabVizModeBubbles && m.activeBubbleChartHasNodes() {
			return bubbleTickCmdFn()
		}
	}
	return nil
}

func (m Model) tabVizModeFor(tab Tab) tabVizMode {
	switch tab {
	case TabSyscalls:
		return m.syscallsVizMode
	case TabFiles:
		return m.filesVizMode
	case TabProcesses:
		return m.processesVizMode
	default:
		return tabVizModeTable
	}
}

func (m *Model) setTabVizMode(tab Tab, mode tabVizMode) {
	switch tab {
	case TabSyscalls:
		m.syscallsVizMode = mode
	case TabFiles:
		m.filesVizMode = mode
	case TabProcesses:
		m.processesVizMode = mode
	}
}

func (m Model) allowedVizModes(tab Tab) []tabVizMode {
	switch tab {
	case TabSyscalls:
		return []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap}
	case TabProcesses:
		return []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap}
	case TabFiles:
		if m.filesDirGrouped {
			return []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap, tabVizModeIcicle}
		}
		return []tabVizMode{tabVizModeTable}
	default:
		return []tabVizMode{tabVizModeTable}
	}
}

func nextVizMode(current tabVizMode, allowed []tabVizMode) tabVizMode {
	if len(allowed) == 0 {
		return tabVizModeTable
	}
	for idx, mode := range allowed {
		if mode == current {
			return allowed[(idx+1)%len(allowed)]
		}
	}
	return allowed[0]
}

func nextBubbleMetric(metric bubbleMetric) bubbleMetric {
	if metric == bubbleMetricBytes {
		return bubbleMetricCount
	}
	return bubbleMetricBytes
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

func renderActiveTab(tab Tab, snap *statsengine.Snapshot, streamModel *eventstream.Model, flameModel *flamegraphtui.Model, width, height, pidFilter, syscallsOffset, filesOffset int, filesDirGrouped bool, filesDirOffset, processesOffset int) string {
	if tab == TabStream {
		if streamModel == nil {
			return common.PanelStyle.Render("Stream: waiting for source...")
		}
		return streamModel.View(width, height)
	}
	if tab == TabFlame {
		if flameModel == nil {
			return common.PanelStyle.Render("Flame: waiting for model...")
		}
		flameModel.SetViewport(width, height)
		return flameModel.View().Content
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
		return renderProcessesWithOffset(snap, width, height, processesOffset, pidFilter)
	case TabLatency:
		return renderLatencyGapsTab(snap, width, height)
	default:
		return common.PanelStyle.Render("Unknown tab")
	}
}

func streamTickCmd() tea.Cmd {
	return tea.Tick(streamRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return streamTickMsg{} })
}

func flameTickCmd() tea.Cmd {
	return tea.Tick(flameRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return flameTickMsg{} })
}

func bubbleTickCmdFn() tea.Cmd {
	return tea.Tick(bubbleRefreshMs*time.Millisecond, func(time.Time) tea.Msg { return bubbleTickMsg{} })
}

func streamViewport(width, height int) (int, int) {
	width, height = common.EffectiveViewport(width, height)
	height -= streamChromeRows
	if height < 1 {
		height = 1
	}
	return width, height
}

func flameViewport(width, height int, showHelp bool) (int, int) {
	width, height = common.EffectiveViewport(width, height)
	chromeRows := dashboardTabBarRows + dashboardHelpHintRows
	if showHelp {
		chromeRows = dashboardTabBarRows + dashboardExpandedHelpRows
	}
	height -= chromeRows
	if height < 1 {
		height = 1
	}
	return width, height
}

func translateFlamegraphMsg(msg tea.Msg) tea.Msg {
	switch mouse := msg.(type) {
	case tea.MouseClickMsg:
		m := mouse.Mouse()
		m.Y -= dashboardTabBarRows
		return tea.MouseClickMsg(m)
	case tea.MouseReleaseMsg:
		m := mouse.Mouse()
		m.Y -= dashboardTabBarRows
		return tea.MouseReleaseMsg(m)
	case tea.MouseMotionMsg:
		m := mouse.Mouse()
		m.Y -= dashboardTabBarRows
		return tea.MouseMotionMsg(m)
	case tea.MouseWheelMsg:
		m := mouse.Mouse()
		m.Y -= dashboardTabBarRows
		return tea.MouseWheelMsg(m)
	default:
		return msg
	}
}
