package dashboard

import (
	"fmt"
	"slices"
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

// autoResetTickMsg fires when the auto-reset timer elapses. It carries the
// generation it was scheduled for so that stale ticks (from a previous
// interval setting) are ignored rather than triggering a wrong-cadence reset.
type autoResetTickMsg struct {
	generation uint64
}
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

	refreshEvery time.Duration
	// autoResetEvery is the cadence for the periodic auto-reset of
	// aggregate state (live trie + stats engine). Zero disables it.
	autoResetEvery time.Duration
	// autoResetGen is incremented every time autoResetEvery changes so
	// in-flight ticks scheduled under the previous cadence can be ignored.
	autoResetGen uint64
	// autoResetArmedAt is the wall-clock instant the current tick was
	// scheduled. The next reset is expected at autoResetArmedAt +
	// autoResetEvery; autoResetStatus uses this to render the live
	// countdown ("12s/30s") in the chrome. Updated on every arm
	// (SetAutoResetInterval, focus regain, tick re-arm).
	autoResetArmedAt time.Time
	keys         common.KeyMap
	globalFilter             globalfilter.Filter
	filterStack              []string
	recordingStatus          string
	pidFilter                int
	syscallsOffset           int
	syscallsCol              int
	syscallsSort             tableSortState[syscallSortKey]
	syscallsTreemapSelection int
	filesOffset              int
	filesCol                 int
	filesSort                tableSortState[fileSortKey]
	filesDirGrouped          bool
	filesDirOffset           int
	filesDirCol              int
	filesDirSort             tableSortState[fileDirSortKey]
	processesOffset          int
	processesCol             int
	processesSort            tableSortState[processSortKey]
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
	if cmd := m.autoResetTickCmd(); cmd != nil {
		cmds = append(cmds, cmd)
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
	case autoResetTickMsg:
		return m.handleAutoResetTick(msg)
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
	m.clampTableColumns()
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
	selectedSyscall := ""
	selectedFile := ""
	selectedDir := ""
	selectedProcess := uint32(0)
	if m.syscallsSort.active {
		selectedSyscall = m.selectedSyscallName()
	}
	if m.filesVizMode == tabVizModeTable {
		if !m.filesDirGrouped && m.filesSort.active {
			selectedFile = m.selectedFilePath()
		}
		if m.filesDirGrouped && m.filesDirSort.active {
			selectedDir = m.selectedDirPath()
		}
	}
	if m.processesVizMode == tabVizModeTable && m.processesSort.active {
		selectedProcess = m.selectedProcessPID()
	}
	m.latest = msg.Snap
	m.reanchorSyscallsOffset(selectedSyscall)
	m.reanchorFilesOffset(selectedFile)
	m.reanchorFilesDirOffset(selectedDir)
	m.reanchorProcessesOffset(selectedProcess)
	m.syscallsTreemapSelection = clampOffset(m.syscallsTreemapSelection, m.maxSyscallsRows())
	m.clampTableColumns()
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
		handled, cmd = m.handleEnterKey(msg)
	}
	if !handled {
		handled, cmd = m.handleSortKey(msg)
	}
	if !handled {
		handled, cmd = m.handleShortcutKey(msg)
	}
	if !handled {
		return m.handleUnhandledKey(msg)
	}
	return m, m.postKeyTransitionCmd(prevActiveTab, cmd)
}

func (m Model) handleEnterKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if !key.Matches(msg, m.keys.Enter) {
		return false, nil
	}
	switch m.activeTab {
	case TabSyscalls:
		if m.syscallsVizMode != tabVizModeTable {
			return false, nil
		}
		filter, action, ok := m.selectedSyscallFilter()
		if !ok {
			return false, nil
		}
		return true, func() tea.Msg { return messages.GlobalFilterRequestedMsg{Filter: filter, Action: action} }
	case TabFiles:
		if m.filesVizMode != tabVizModeTable {
			return false, nil
		}
		filter, action, ok := m.selectedFileFilter()
		if !ok {
			return false, nil
		}
		return true, func() tea.Msg { return messages.GlobalFilterRequestedMsg{Filter: filter, Action: action} }
	case TabProcesses:
		filter, action, ok := m.selectedProcessFilter()
		if !ok {
			return false, nil
		}
		return true, func() tea.Msg { return messages.GlobalFilterRequestedMsg{Filter: filter, Action: action} }
	default:
		return false, nil
	}
}

func (m Model) selectedSyscallFilter() (globalfilter.Filter, string, bool) {
	selected, ok := m.selectedSyscallSnapshot()
	if !ok {
		return globalfilter.Filter{}, "", false
	}
	if strings.TrimSpace(selected.Name) == "" {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	filter.Syscall = &globalfilter.StringFilter{Pattern: selected.Name}
	return filter, "syscall~" + selected.Name, true
}

func (m Model) selectedSyscallSnapshot() (statsengine.SyscallSnapshot, bool) {
	rows := m.sortedSyscallRows()
	if len(rows) == 0 {
		return statsengine.SyscallSnapshot{}, false
	}
	index := clampOffset(m.syscallsOffset, len(rows))
	return rows[index], true
}

func (m Model) sortedSyscallRows() []statsengine.SyscallSnapshot {
	return sortedSyscallSnapshots(m.snapshotOrZero().Syscalls(), m.syscallsSort)
}

func (m Model) selectedSyscallName() string {
	selected, ok := m.selectedSyscallSnapshot()
	if !ok {
		return ""
	}
	return selected.Name
}

func (m *Model) handleSortKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	reverse := key.Matches(msg, m.keys.ReverseSort)
	if !reverse && !key.Matches(msg, m.keys.Sort) {
		return false, nil
	}
	switch m.activeTab {
	case TabSyscalls:
		return m.handleSyscallsSortKey(reverse)
	case TabFiles:
		return m.handleFilesSortKey(reverse)
	case TabProcesses:
		return m.handleProcessesSortKey(reverse)
	default:
		return false, nil
	}
}

func (m *Model) handleSyscallsSortKey(reverse bool) (bool, tea.Cmd) {
	if m.syscallsVizMode != tabVizModeTable {
		return false, nil
	}
	key, ok := syscallSortKeyForColumn(m.width, m.syscallsCol)
	if !ok {
		return false, nil
	}
	selectedName := m.selectedSyscallName()
	m.syscallsSort = m.syscallsSort.toggled(key, reverse)
	m.reanchorSyscallsOffset(selectedName)
	return true, nil
}

func (m *Model) handleFilesSortKey(reverse bool) (bool, tea.Cmd) {
	if m.filesVizMode != tabVizModeTable {
		return false, nil
	}
	if m.filesDirGrouped {
		key, ok := fileDirSortKeyForColumn(m.filesDirCol)
		if !ok {
			return false, nil
		}
		selectedDir := m.selectedDirPath()
		m.filesDirSort = m.filesDirSort.toggled(key, reverse)
		m.reanchorFilesDirOffset(selectedDir)
		return true, nil
	}
	key, ok := fileSortKeyForColumn(m.filesCol)
	if !ok {
		return false, nil
	}
	selectedPath := m.selectedFilePath()
	m.filesSort = m.filesSort.toggled(key, reverse)
	m.reanchorFilesOffset(selectedPath)
	return true, nil
}

func (m *Model) handleProcessesSortKey(reverse bool) (bool, tea.Cmd) {
	if m.processesVizMode != tabVizModeTable {
		return false, nil
	}
	key, ok := processSortKeyForColumn(m.processesCol)
	if !ok {
		return false, nil
	}
	selectedPID := m.selectedProcessPID()
	m.processesSort = m.processesSort.toggled(key, reverse)
	m.reanchorProcessesOffset(selectedPID)
	return true, nil
}

func (m *Model) reanchorSyscallsOffset(selectedName string) {
	m.syscallsOffset = reanchorOffset(m.syscallsOffset, m.sortedSyscallRows(), selectedName, findSyscallOffset)
}

func (m *Model) reanchorFilesOffset(selectedPath string) {
	m.filesOffset = reanchorOffset(m.filesOffset, m.sortedFileRows(), selectedPath, findFileOffset)
}

func (m *Model) reanchorFilesDirOffset(selectedDir string) {
	m.filesDirOffset = reanchorOffset(m.filesDirOffset, m.sortedDirRows(), selectedDir, findDirOffset)
}

func (m *Model) reanchorProcessesOffset(selectedPID uint32) {
	m.processesOffset = reanchorOffset(m.processesOffset, m.sortedProcessTableRows(), selectedPID, findProcessOffset)
}

func reanchorOffset[T any, K comparable](current int, rows []T, selected K, find func([]T, K) (int, bool)) int {
	if len(rows) == 0 {
		return 0
	}
	var zero K
	if selected != zero {
		if index, ok := find(rows, selected); ok {
			return index
		}
	}
	return clampOffset(current, len(rows))
}

func (m Model) selectedFileFilter() (globalfilter.Filter, string, bool) {
	if m.latest == nil {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	if m.filesDirGrouped {
		selected, ok := m.selectedDirSnapshot()
		if !ok {
			return globalfilter.Filter{}, "", false
		}
		if strings.TrimSpace(selected.Dir) == "" {
			return globalfilter.Filter{}, "", false
		}
		filter.File = &globalfilter.StringFilter{Pattern: selected.Dir}
		return filter, "file~" + selected.Dir, true
	}
	selected, ok := m.selectedFileSnapshot()
	if !ok {
		return globalfilter.Filter{}, "", false
	}
	if strings.TrimSpace(selected.Path) == "" {
		return globalfilter.Filter{}, "", false
	}
	filter.File = &globalfilter.StringFilter{Pattern: selected.Path}
	return filter, "file~" + selected.Path, true
}

func (m Model) selectedFileSnapshot() (statsengine.FileSnapshot, bool) {
	rows := m.sortedFileRows()
	if len(rows) == 0 {
		return statsengine.FileSnapshot{}, false
	}
	index := clampOffset(m.filesOffset, len(rows))
	return rows[index], true
}

func (m Model) sortedFileRows() []statsengine.FileSnapshot {
	return sortedFileSnapshots(m.snapshotOrZero().Files(), m.filesSort)
}

func (m Model) selectedFilePath() string {
	selected, ok := m.selectedFileSnapshot()
	if !ok {
		return ""
	}
	return selected.Path
}

func (m Model) selectedDirSnapshot() (DirSnapshot, bool) {
	rows := m.sortedDirRows()
	if len(rows) == 0 {
		return DirSnapshot{}, false
	}
	index := clampOffset(m.filesDirOffset, len(rows))
	return rows[index], true
}

func (m Model) sortedDirRows() []DirSnapshot {
	return sortedDirSnapshots(aggregateFilesByDir(m.snapshotOrZero().Files()), m.filesDirSort)
}

func (m Model) selectedDirPath() string {
	selected, ok := m.selectedDirSnapshot()
	if !ok {
		return ""
	}
	return selected.Dir
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

func (m Model) selectedProcessFilter() (globalfilter.Filter, string, bool) {
	proc, ok := m.selectedProcessSnapshot()
	if !ok || proc.PID == 0 {
		return globalfilter.Filter{}, "", false
	}
	filter := m.globalFilter.Clone()
	if m.processesCol == 1 {
		comm := strings.TrimSpace(proc.Comm)
		if comm != "" {
			filter.Comm = &globalfilter.StringFilter{Pattern: comm}
			return filter, "comm~" + comm, true
		}
	}
	filter.PID = &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: int64(proc.PID)}
	return filter, fmt.Sprintf("pid=%d", proc.PID), true
}

func (m Model) selectedProcessSnapshot() (statsengine.ProcessSnapshot, bool) {
	rows := m.snapshotOrZero().Processes()
	if len(rows) == 0 {
		return statsengine.ProcessSnapshot{}, false
	}

	switch {
	case m.processesVizMode == tabVizModeTreemap:
		return indexedProcessSnapshot(sortedProcessSnapshots(rows, m.processesChart.Metric(), maxSyscallTreemapItems), m.processesOffset)
	case m.processesVizMode == tabVizModeBubbles:
		return indexedProcessSnapshot(sortedProcessSnapshots(rows, m.processesChart.Metric(), bubbleMaxItems), m.processesChart.selected)
	default:
		return indexedProcessSnapshot(m.sortedProcessTableRows(), m.processesOffset)
	}
}

func (m Model) sortedProcessTableRows() []statsengine.ProcessSnapshot {
	return sortedProcessTableRows(m.snapshotOrZero().Processes(), m.processesSort)
}

func (m Model) selectedProcessPID() uint32 {
	selected, ok := m.selectedProcessSnapshot()
	if !ok {
		return 0
	}
	return selected.PID
}

func indexedProcessSnapshot(rows []statsengine.ProcessSnapshot, index int) (statsengine.ProcessSnapshot, bool) {
	if len(rows) == 0 {
		return statsengine.ProcessSnapshot{}, false
	}
	index = clampOffset(index, len(rows))
	if index < 0 || index >= len(rows) {
		return statsengine.ProcessSnapshot{}, false
	}
	return rows[index], true
}

func sortedProcessSnapshots(rows []statsengine.ProcessSnapshot, metric bubbleMetric, limit int) []statsengine.ProcessSnapshot {
	if len(rows) == 0 {
		return nil
	}
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(left, right statsengine.ProcessSnapshot) int {
		lv := processMetricValue(left, metric)
		rv := processMetricValue(right, metric)
		switch {
		case lv > rv:
			return -1
		case lv < rv:
			return 1
		}
		llabel := processSelectionLabel(left)
		rlabel := processSelectionLabel(right)
		switch {
		case llabel < rlabel:
			return -1
		case llabel > rlabel:
			return 1
		default:
			return 0
		}
	})
	if limit > 0 && len(sorted) > limit {
		sorted = sorted[:limit]
	}
	return sorted
}

func processMetricValue(proc statsengine.ProcessSnapshot, metric bubbleMetric) uint64 {
	switch metric {
	case bubbleMetricBytes:
		return proc.Bytes
	case bubbleMetricDuration:
		return proc.TotalLatencyNs
	default:
		return proc.Syscalls
	}
}

func processSelectionLabel(proc statsengine.ProcessSnapshot) string {
	label := fmt.Sprintf("%d", proc.PID)
	if comm := strings.TrimSpace(proc.Comm); comm != "" {
		label = fmt.Sprintf("%d:%s", proc.PID, comm)
	}
	return label
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
		return common.HandleTableNavigationKey(keyStr, &m.syscallsOffset, &m.syscallsCol, m.maxSyscallsRows(), len(syscallColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
	case TabFiles:
		if m.filesDirGrouped {
			return common.HandleTableNavigationKey(keyStr, &m.filesDirOffset, &m.filesDirCol, m.maxFilesDirRowsForMode(), len(fileDirColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
		}
		return common.HandleTableNavigationKey(keyStr, &m.filesOffset, &m.filesCol, m.maxFilesRows(), len(fileColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
	case TabProcesses:
		return common.HandleTableNavigationKey(keyStr, &m.processesOffset, &m.processesCol, m.maxProcessesRows(), len(processColumns()), tablePageStep(m.activeTableHeight())), nil
	case TabStream:
		streamWidth, streamHeight := streamViewport(m.width, m.height)
		m.streamModel.SetViewport(streamWidth, streamHeight)
		handled := m.streamModel.HandleTeaKey(msg)
		if m.streamModel.ConsumeGlobalFilterUndoRequest() {
			return true, func() tea.Msg { return messages.GlobalFilterUndoRequestedMsg{} }
		}
		if filter, action, ok := m.streamModel.ConsumeGlobalFilterRequest(); ok {
			return true, func() tea.Msg { return messages.GlobalFilterRequestedMsg{Filter: filter, Action: action} }
		}
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

func (m *Model) clampTableColumns() {
	m.syscallsCol = common.ClampTableCol(m.syscallsCol, len(syscallColumns(m.width)))
	m.filesCol = common.ClampTableCol(m.filesCol, len(fileColumns(m.width)))
	m.filesDirCol = common.ClampTableCol(m.filesDirCol, len(fileDirColumns(m.width)))
	m.processesCol = common.ClampTableCol(m.processesCol, len(processColumns()))
}

func (m Model) maxSyscallsRows() int {
	return m.snapshotOrZero().SyscallsCount()
}

func (m Model) maxFilesRows() int {
	return m.snapshotOrZero().FilesCount()
}

func (m Model) maxFilesDirRows() int {
	return len(aggregateFilesByDir(m.snapshotOrZero().Files()))
}

func (m Model) maxFilesDirRowsForMode() int {
	if m.filesVizMode != tabVizModeIcicle {
		return m.maxFilesDirRows()
	}
	width, height := flameViewport(m.width, m.height, m.showHelp)
	return filesIcicleTileCount(m.latest, width, height, m.filesChart.Metric())
}

func (m Model) maxProcessesRows() int {
	return m.snapshotOrZero().ProcessesCount()
}

func (m Model) snapshot() *statsengine.Snapshot {
	if m.engine == nil {
		return nil
	}
	return m.engine.Snapshot()
}

func (m Model) snapshotOrZero() statsengine.Snapshot {
	if m.latest == nil {
		return statsengine.Snapshot{}
	}
	return *m.latest
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

// autoResetTickCmd returns a command that fires an autoResetTickMsg after
// the current auto-reset interval. Returns nil when the timer is disabled
// (interval <= 0) or while the dashboard is blurred, so callers can
// compose it without extra branching. SetFocused re-arms the tick when
// focus returns.
func (m Model) autoResetTickCmd() tea.Cmd {
	if m.autoResetEvery <= 0 || !m.focused {
		return nil
	}
	gen := m.autoResetGen
	return tea.Tick(m.autoResetEvery, func(time.Time) tea.Msg {
		return autoResetTickMsg{generation: gen}
	})
}

// handleAutoResetTick fires the same reset path as the `r` key (live trie
// + stats engine) and re-arms the timer for the next tick. Stale ticks
// from a previous cadence are dropped via the generation counter so that
// changing the interval does not double-fire. While the dashboard is
// blurred the tick is also dropped without re-arming; SetFocused will
// arm a fresh tick on focus regain.
func (m Model) handleAutoResetTick(msg autoResetTickMsg) (tea.Model, tea.Cmd) {
	if msg.generation != m.autoResetGen || m.autoResetEvery <= 0 || !m.focused {
		return m, nil
	}
	m.autoResetArmedAt = time.Now()
	resetCmd := m.resetBaselineCmd()
	nextTick := m.autoResetTickCmd()
	switch {
	case resetCmd == nil && nextTick == nil:
		return m, nil
	case resetCmd == nil:
		return m, nextTick
	case nextTick == nil:
		return m, resetCmd
	default:
		return m, tea.Batch(resetCmd, nextTick)
	}
}

// SetAutoResetInterval reconfigures the auto-reset cadence. A zero or
// negative value disables the timer. Returns a tea.Cmd that arms the new
// timer (or nil when disabling). The generation counter is bumped so any
// in-flight tick scheduled under the previous interval is ignored.
func (m *Model) SetAutoResetInterval(d time.Duration) tea.Cmd {
	if d < 0 {
		d = 0
	}
	m.autoResetEvery = d
	m.autoResetGen++
	if d > 0 {
		m.autoResetArmedAt = time.Now()
	} else {
		m.autoResetArmedAt = time.Time{}
	}
	return m.autoResetTickCmd()
}

// AutoResetInterval reports the current auto-reset cadence. Zero means
// the timer is disabled.
func (m Model) AutoResetInterval() time.Duration {
	return m.autoResetEvery
}

// LatestSnapshot returns the most recently received snapshot.
func (m Model) LatestSnapshot() *statsengine.Snapshot {
	return m.latest
}

// ActiveTab returns the currently selected dashboard tab.
func (m Model) ActiveTab() Tab {
	return m.activeTab
}

// ExportStreamCSV exports a fresh filtered snapshot of the stream ringbuffer.
func (m Model) ExportStreamCSV() (string, error) {
	return m.streamModel.ExportSnapshotToCSV("")
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

// SetFilterStack forwards the shared global filter stack into dashboard views.
func (m *Model) SetFilterStack(stack []string) {
	m.filterStack = append(m.filterStack[:0], stack...)
	m.streamModel.SetFilterStack(stack)
}

// SetRecordingStatus updates the visible recording state summary rendered in the dashboard chrome.
func (m *Model) SetRecordingStatus(status string) {
	m.recordingStatus = status
}

// SetLiveTrie updates the live trie source used by the flamegraph tab.
func (m *Model) SetLiveTrie(liveTrie flamegraphtui.LiveTrieSource) {
	m.liveTrie = liveTrie
	m.flamegraphModel.SetLiveTrie(liveTrie)
	if m.width > 0 && m.height > 0 {
		flameWidth, flameHeight := flameViewport(m.width, m.height, m.showHelp)
		m.flamegraphModel.SetViewport(flameWidth, flameHeight)
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

// SetFocused controls whether periodic refresh ticks are processed and
// returns a tea.Cmd that arms a fresh auto-reset tick when focus returns
// (or nil otherwise). The auto-reset generation counter is bumped on
// every focus change so any in-flight tick scheduled before a blur is
// dropped when it eventually arrives — the tick payload's generation
// will no longer match. Without bumping, a tick that was already in
// flight when blur occurred could fire moments after the user re-focuses
// and surprise them with a reset.
func (m *Model) SetFocused(focused bool) tea.Cmd {
	if m.focused == focused {
		return nil
	}
	m.focused = focused
	m.autoResetGen++
	if !focused {
		return nil
	}
	if m.autoResetEvery > 0 {
		m.autoResetArmedAt = time.Now()
	}
	return m.autoResetTickCmd()
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
	flameModel := m.flamegraphModel
	streamModel.SetFooterVisible(m.showHelp)
	if m.activeTab == TabStream {
		_, activeHeight = streamViewport(width, height)
	}
	if m.activeTab == TabFlame {
		flameModel.SetViewport(width, activeHeight)
	}

	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, width))
	b.WriteString("\n")
	b.WriteString(m.renderActiveContent(width, activeHeight, &streamModel, &flameModel))
	b.WriteString("\n")
	if m.showHelp {
		b.WriteString(renderHelpBarWithStatus(m.keys, width, m.filterSummary()))
	} else {
		b.WriteString(renderHelpHintWithStatus(width, m.filterSummary()))
	}
	return tea.NewView(common.ScreenStyle.Render(b.String()))
}

func (m Model) filterSummary() string {
	summary := "filter: " + m.globalFilter.Summary()
	if len(m.filterStack) > 0 {
		summary += " | stack: " + strings.Join(m.filterStack, " | ")
	}
	if m.recordingStatus != "" {
		summary += " | " + m.recordingStatus
	}
	summary += " | " + m.autoResetStatus()
	return summary
}

// autoResetStatus is the human-readable label for the current
// auto-reset cadence shown in the dashboard chrome.
//   - "off" when the timer is disabled.
//   - "<remaining>/<total>" while running and focused, e.g. "12s/30s".
//     The countdown updates on every render (driven by the periodic
//     refresh tick) so users can see when the next reset will fire.
//   - "<total> (paused)" when enabled but the TUI has lost focus, so
//     the user knows the timer will not fire until focus returns.
//
// Disabled timers stay "off" regardless of focus.
func (m Model) autoResetStatus() string {
	if m.autoResetEvery <= 0 {
		return "auto-reset: off"
	}
	if !m.focused {
		return "auto-reset: " + m.autoResetEvery.String() + " (paused)"
	}
	return "auto-reset: " + formatAutoResetRemaining(m.autoResetArmedAt, m.autoResetEvery) + "/" + m.autoResetEvery.String()
}

// formatAutoResetRemaining renders the time left until the next
// scheduled tick as a compact whole-second duration string ("12s",
// "1m23s"). When armedAt is the zero value (e.g. just after enabling)
// or the deadline has already elapsed, it returns "0s" so the chrome
// always shows a value rather than an empty placeholder.
func formatAutoResetRemaining(armedAt time.Time, every time.Duration) string {
	if armedAt.IsZero() || every <= 0 {
		return "0s"
	}
	remaining := time.Until(armedAt.Add(every))
	if remaining < 0 {
		remaining = 0
	}
	seconds := int(remaining.Round(time.Second).Seconds())
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	minutes := seconds / 60
	secs := seconds % 60
	if secs == 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%dm%ds", minutes, secs)
}

func (m Model) renderActiveContent(width, activeHeight int, streamModel *eventstream.Model, flameModel *flamegraphtui.Model) string {
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
	if m.activeTab == TabSyscalls && m.latest != nil {
		return renderSyscallsWithSort(m.latest, width, activeHeight, m.syscallsOffset, m.syscallsCol, m.syscallsSort)
	}
	if m.activeTab == TabFiles && m.latest != nil && m.filesVizMode == tabVizModeTable {
		if m.filesDirGrouped {
			return renderFilesDirGroupedWithSort(m.latest, width, activeHeight, m.filesDirOffset, m.filesDirCol, m.filesDirSort)
		}
		return renderFilesWithSort(m.latest, width, activeHeight, m.filesOffset, m.filesCol, m.filesSort)
	}
	if m.activeTab == TabProcesses && m.latest != nil && m.processesVizMode == tabVizModeTable {
		return renderProcessesWithSort(m.latest, width, activeHeight, m.processesOffset, m.processesCol, m.pidFilter, m.processesSort)
	}
	return renderActiveTab(
		m.activeTab,
		m.latest,
		streamModel,
		flameModel,
		width,
		activeHeight,
		m.pidFilter,
		m.syscallsOffset,
		m.syscallsCol,
		m.filesOffset,
		m.filesCol,
		m.filesDirGrouped,
		m.filesDirOffset,
		m.filesDirCol,
		m.processesOffset,
		m.processesCol,
	)
}

func (m Model) activeTableHeight() int {
	_, activeHeight := flameViewport(m.width, m.height, m.showHelp)
	return activeHeight
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
	// 3-way cycle: count (events) → bytes → duration → count.
	switch metric {
	case bubbleMetricCount:
		return bubbleMetricBytes
	case bubbleMetricBytes:
		return bubbleMetricDuration
	default:
		return bubbleMetricCount
	}
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return refreshTickMsg{} })
}

func renderActiveTab(tab Tab, snap *statsengine.Snapshot, streamModel *eventstream.Model, flameModel *flamegraphtui.Model, width, height, pidFilter, syscallsOffset, syscallsCol, filesOffset, filesCol int, filesDirGrouped bool, filesDirOffset, filesDirCol, processesOffset, processesCol int) string {
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
		return flameModel.View().Content
	}

	if snap == nil {
		return common.PanelStyle.Render(tab.String() + ": waiting for stats...")
	}

	switch tab {
	case TabOverview:
		return renderOverview(snap, width, height)
	case TabSyscalls:
		return renderSyscallsWithOffset(snap, width, height, syscallsOffset, syscallsCol)
	case TabFiles:
		if filesDirGrouped {
			return renderFilesDirGrouped(snap, width, height, filesDirOffset, filesDirCol)
		}
		return renderFilesWithOffset(snap, width, height, filesOffset, filesCol)
	case TabProcesses:
		return renderProcessesWithOffset(snap, width, height, processesOffset, processesCol, pidFilter)
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
	return dashboardViewport(width, height, streamChromeRows)
}

func flameViewport(width, height int, showHelp bool) (int, int) {
	chromeRows := dashboardTabBarRows + dashboardHelpHintRows
	if showHelp {
		chromeRows = dashboardTabBarRows + dashboardExpandedHelpRows
	}
	return dashboardViewport(width, height, chromeRows)
}

func dashboardViewport(width, height, chromeRows int) (int, int) {
	width, height = common.EffectiveViewport(width, height)
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
