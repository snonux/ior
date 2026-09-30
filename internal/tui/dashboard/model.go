package dashboard

import (
	"strings"
	"sync/atomic"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	flamegraphtui "ior/internal/tui/flamegraph"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

const streamChromeRows = 4
const dashboardHelpHintRows = 1
const dashboardExpandedHelpRows = 2
const dashboardTabBarRows = 1

// SnapshotSource is the dashboard data source. Snapshot returns nil, nil when
// the engine is nil. A non-nil error indicates that snapshot construction
// failed and the caller should discard the result. Reset clears accumulated
// state and restarts the series baselines; the dashboard calls it on every
// stats reset (refresh key, auto-reset ticks and ResetStats for probe toggles
// and in-place filter swaps), so it is part of the contract rather than an
// optional capability. It mirrors
// runtime.ResettableSnapshotSource.
//
// Concurrency contract: implementations must be goroutine-safe. Snapshot is
// called from Bubble Tea command goroutines (statstick.go), not from the UI
// goroutine, so it can run while Reset is called on the UI goroutine (a reset
// key press, auto-reset or ResetStats during an in-flight build), and two
// Snapshot calls can overlap (a SnapshotCmd or reset command alongside a
// periodic refresh; only the refresh path is single-flighted). The real
// engine qualifies: it hands its scratch buffers out exclusively per call and
// a Reset during an in-flight Snapshot is documented as harmless (the
// dashboard's generation check drops such a snapshot anyway).
type SnapshotSource interface {
	Snapshot() (*statsengine.Snapshot, error)
	Reset()
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

// Model is the dashboard root: the tab framework plus the per-tab view state.
// Receiver policy: every method takes *Model,
// so *Model (not Model) is the Bubble Tea model that Init/Update/View
// implement - the same policy the stream tab's model follows
// (internal/tui/eventstream). The mixed value/pointer receivers this type
// used to have worked only while every value happened to be addressable:
// the value-receiver Update called pointer-receiver mutators on its local
// copy, so any non-addressable or later-copied Model silently lost those
// mutations.
type Model struct {
	activeTab Tab

	engine   SnapshotSource
	latest   *statsengine.Snapshot
	liveTrie coreflamegraph.LiveTrieSource
	// statsGen is the current stats generation. It starts at 1 so every tick
	// is versioned (statsTick, statsTickCmd and refreshStatsCmd all build
	// through buildStatsTick and stamp the generation captured when the
	// request was made), and advances on every stats reset so handleStatsTick
	// can drop ticks built before the reset.
	statsGen uint64
	// refreshBuilding is set while a periodic refresh command is building a
	// snapshot off the UI goroutine (refreshStatsCmd). It is a pointer so the
	// command can clear it after the build ends, and created lazily so a
	// zero-value Model works.
	refreshBuilding *atomic.Bool

	width  int
	height int

	// ticks owns the cadences of the periodic tick chains (ticks.go).
	ticks tickScheduler
	// autoReset owns the periodic auto-reset of aggregate state (live trie
	// + stats engine): cadence, tick generation and countdown
	// (autoreset.go).
	autoReset    autoReset
	keys         common.KeyMap
	globalFilter globalfilter.Filter
	filterStack  []string
	// filterNotice explains why the last requested filter change was not
	// applied. It is empty whenever the displayed globalFilter is the one
	// the user last asked for, and is rendered ahead of the filter summary
	// in the chrome so a refusal is read before the filter that survived it.
	filterNotice string
	// familyHint says the dashboard is scoped to a syscall family with no
	// attached probe. It is kept apart from filterNotice because the two are
	// independent kinds of notice with independent lifetimes: the hint
	// follows the family scope and the attach state, the notice follows
	// filter requests. Sharing one field let a hint refresh (after any probe
	// change) overwrite a refusal the user had not read yet.
	familyHint      string
	recordingStatus string
	pidFilter       int
	// The three table tabs' state (selected offset/col, live sort, viz mode,
	// bubble chart) plus the Files tab's directory-grouped sub-table, which
	// shares the navigation and sort machinery but never has a viz mode or
	// chart of its own. syscallsTreemapOffset and processesTreemapOffset
	// stay plain fields: each is an offset into its treemap's item list
	// (syscallsTreemapSelection, processesTreemapSelection), not into the
	// table the state above selects in, so clamping the treemap selection
	// (a PID outside the top tiles) never moves the table selection. See
	// tabletab.go for what the component is for.
	syscallsTab            tableTabState[syscallSortKey]
	syscallsTreemapOffset  int
	syscallsTreemapWanted  stickyKey
	filesTab               tableTabState[fileSortKey]
	filesDirGrouped        bool
	filesDirTab            tableTabState[fileDirSortKey]
	processesTab           tableTabState[processSortKey]
	processesTreemapOffset int
	processesTreemapWanted stickyKey
	streamModel            eventstream.Model
	flamegraphModel        *flamegraphtui.Model
	showHelp               bool
	isDark                 bool
	focused                bool
}

// NewModel creates a dashboard model with default refresh cadence.
// Like every method on Model the constructors return the pointer form:
// *Model is the Bubble Tea model (all-pointer receiver policy, same as the
// stream tab's model - see the receiver note on Model above).
func NewModel(engine SnapshotSource, streamSource eventstream.Source) *Model {
	return NewModelWithConfig(engine, streamSource, defaultRefreshMs, 0, common.Keys)
}

// NewModelWithConfig creates a dashboard model with explicit refresh and keys.
// fastRefreshMs controls the high-frequency tick cadence for the stream and
// flame tabs (e.g. 200 ms). A value of 0 uses the package-level constants
// streamRefreshMs / flameRefreshMs (200 ms) so existing call sites are
// backwards-compatible.
func NewModelWithConfig(engine SnapshotSource, streamSource eventstream.Source, refreshMs int, fastRefreshMs int, keys common.KeyMap) *Model {
	m := &Model{
		activeTab:       TabFlame,
		engine:          engine,
		statsGen:        1,
		ticks:           newTickScheduler(refreshMs, fastRefreshMs),
		keys:            keys,
		pidFilter:       -1,
		streamModel:     eventstream.NewModel(streamSource),
		flamegraphModel: flamegraphtui.NewModel(nil),
		isDark:          true,
		focused:         true,
	}
	// The tableTabState zero value already means table mode; only the bubble
	// charts need construction.
	m.forEachBubbleChart(func(chart *bubbleChart) { *chart = newBubbleChart() })
	// showHelp starts false; align the stream footer visibility so it matches
	// from the first render without relying on View() to fix up the mismatch.
	m.streamModel.SetFooterVisible(false)
	// Gate the stream tab's x/X/E export shortcuts and hints from the shared
	// key map: the top-level model blanks keys.Export when -tuiExport=false.
	m.streamModel.SetExportEnabled(keys.ExportEnabled())
	m.SetDarkMode(true)
	return m
}

// Init starts periodic refresh ticks. The tab registry's InitCmd field is
// consulted to start any additional high-frequency tick the active tab needs
// (e.g. stream and flame use a fast cadence controlled by fastRefreshEvery,
// defaulting to streamRefreshMs / flameRefreshMs when not explicitly set).
//
// Init only reads the model. Starting a tick chain supersedes the one
// already running (and, for auto-reset, restarts the chrome countdown), so
// Init asks Update to do it: the refresh and tab chains through a
// tickChainsStartMsg, the auto-reset chain through an autoResetArmMsg.
func (m *Model) Init() tea.Cmd {
	return batchCmds(
		tickChainsStartCmd(),
		m.autoReset.armCmd(m.focused),
	)
}

// Update handles ticks, snapshots, tab changes, and resize events.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.handleWindowSize(msg)
	case tickChainsStartMsg:
		return m.handleTickChainsStart()
	case refreshTickMsg:
		return m.handleRefreshTick(msg)
	case streamTickMsg:
		return m.handleStreamTick(msg)
	case flameTickMsg:
		return m.handleFlameTick(msg)
	case bubbleTickMsg:
		return m.handleBubbleTick(msg)
	case autoResetTickMsg:
		return m.handleAutoResetTick(msg)
	case autoResetArmMsg:
		return m.handleAutoResetArm(msg)
	case messages.StatsTickMsg:
		return m.handleStatsTick(msg)
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	case messages.OpenEditorRequestedMsg:
		return m.handleOpenEditorRequested(msg)
	case streamEditorDoneMsg:
		return m.handleStreamEditorDone(msg)
	}
	return m.handleActiveTabMsg(msg)
}

func (m *Model) handleWindowSize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	// A resize is a global layout change: viewport-dependent item lists
	// (the Files icicle's tiles) can reorder or drop under the selection.
	m.keepAllSelections(func() {
		m.width = msg.Width
		m.height = msg.Height
	})
	m.clampTableColumns()
	m.syncStreamViewport()
	// Sync stream footer visibility so it matches the current help-bar state.
	// This covers the case where showHelp was set before the first resize event.
	m.streamModel.SetFooterVisible(m.showHelp)
	flameCmd := m.syncFlameViewport()
	m.setBubbleViewports()
	if m.bubbleEnabledForTab(m.activeTab) && m.refreshBubbleData() {
		return m, batchCmds(flameCmd, m.ticks.startBubble())
	}
	return m, flameCmd
}

func (m *Model) handleStatsTick(msg messages.StatsTickMsg) (tea.Model, tea.Cmd) {
	if msg.Generation != 0 && msg.Generation < m.statsGen {
		// Built before the latest stats reset: applying it would put the
		// pre-reset numbers back over the post-reset snapshot.
		return m, nil
	}
	if msg.Err != nil {
		// A failed snapshot build carries no data: keep rendering the last
		// good snapshot instead of blanking the view on a transient failure.
		return m, nil
	}
	// Every tab (not only the active one) records its selection against the
	// old snapshot and re-anchors it once the new one is in place.
	var reanchors []func()
	for _, tab := range orderedTabs() {
		if d := tabDescriptors[tab]; d.CaptureSelection != nil {
			reanchors = append(reanchors, d.CaptureSelection(m))
		}
	}
	m.latest = msg.Snap
	for _, reanchor := range reanchors {
		reanchor()
	}
	m.clampTableColumns()
	// The stream re-snapshots and re-filters the whole ring buffer, so only
	// do it while the Stream tab is visible; a hidden stream is brought up
	// to date when it is entered again (see onTabEntered).
	if m.activeTab == TabStream {
		m.streamModel.Refresh()
	}
	if m.refreshBubbleData() {
		return m, m.ticks.startBubble()
	}
	return m, nil
}

func (m *Model) handleStreamEditorDone(msg streamEditorDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.streamModel.SetStatusMessage("Open failed: " + msg.err.Error())
	}
	return m, nil
}

func (m *Model) handleActiveTabMsg(msg tea.Msg) (tea.Model, tea.Cmd) {
	if handled, cmd := m.HandleFlameRefreshCompletion(msg, true); handled {
		return m, cmd
	}
	if m.activeTab != TabFlame {
		return m, nil
	}
	next, cmd := m.flamegraphModel.Update(translateFlamegraphMsg(msg))
	m.flamegraphModel = next.(*flamegraphtui.Model)
	return m, cmd
}

// HandleFlameRefreshCompletion offers a background flamegraph result to its
// persistent owner even when a top-level screen or modal currently owns normal
// message routing. apply is further gated by the active tab so hidden results
// release their in-flight slot without starting an invisible animation.
func (m *Model) HandleFlameRefreshCompletion(msg tea.Msg, apply bool) (bool, tea.Cmd) {
	return m.flamegraphModel.HandleRefreshCompletion(msg, apply && m.activeTab == TabFlame)
}

func (m *Model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if handled, next, cmd := m.handleHelpToggleKey(msg); handled {
		return next, cmd
	}
	if handled, next, cmd := m.handleFlameConsumedKey(msg); handled {
		return next, cmd
	}

	prevActiveTab := m.activeTab
	handled, cmd := m.handleScrollKey(msg)
	if handled && isStreamResumeKey(msg) && m.activeTab == TabStream && !m.streamModel.Paused() {
		// Restart the stream tick with the configurable fast-refresh cadence
		// after the user unpauses the stream with a scroll/space key. The
		// chain keeps ticking while paused, so this supersedes it rather
		// than running a second one.
		cmd = m.ticks.startStream()
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
	if prevActiveTab != m.activeTab {
		cmd = batchCmds(cmd, m.onTabEntered(m.activeTab))
	}
	return m, m.postKeyTransitionCmd(prevActiveTab, cmd)
}

// handleEnterKey applies Enter-on-selected-row through the active tab's
// registered HandleEnter hook, so a new table tab needs only a registry
// entry - this dispatcher is tab-agnostic.
func (m *Model) handleEnterKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if !key.Matches(msg, m.keys.Enter) {
		return false, nil
	}
	if d := lookupTab(m.activeTab); d.HandleEnter != nil {
		return d.HandleEnter(m)
	}
	return false, nil
}

// reanchorFilesOffset keeps the plain Files table selection stable across a
// snapshot refresh (handleStatsTick): it finds the previously selected path
// in the freshly ordered rows and falls back to clamping the current offset.
// Like every keyed selection it survives an empty snapshot (the auto-reset):
// the path is remembered in filesTab.wanted and found again when rows return
// (see stickyKey for how long and until when).
func (m *Model) reanchorFilesOffset(selectedPath string) {
	m.filesTab.offset = reanchorSticky(m.filesTab.offset, &m.filesTab.wanted, m.sortedFileRows(), selectedPath, findFileOffset)
}

// selectedSyscallSnapshot returns the row Enter and the stats-tick
// re-anchor operate on, via the generic tableTabState selection.
func (m *Model) selectedSyscallSnapshot() (statsengine.SyscallSnapshot, bool) {
	rows := m.sortedSyscallRows()
	index, ok := m.syscallsTab.selected(len(rows))
	if !ok {
		return statsengine.SyscallSnapshot{}, false
	}
	return rows[index], true
}

func (m *Model) sortedSyscallRows() []statsengine.SyscallSnapshot {
	snap := m.snapshotOrZero()
	return sortedSyscallSnapshots(m.visibleSyscallRows(&snap), m.syscallsTab.sort)
}

// visibleSyscallRows returns the syscall rows of snap scoped to the active
// global filter's row-level dimensions (Family and Syscall name). It is the
// single source of truth shared by the Syscalls tab renderer, the
// selection/sort/scroll paths, and the row-count/clamp logic, so that what is
// displayed always matches what Enter/sort/scroll operate on. Only the Syscall
// and Family string dimensions are applied (see Filter.MatchesSyscallRow);
// trace-scope dimensions are deliberately left out so synthetic processes stay
// visible in --testflames. When no Syscall/Family filter is active every row
// passes through unchanged.
func (m *Model) visibleSyscallRows(snap *statsengine.Snapshot) []statsengine.SyscallSnapshot {
	if snap == nil {
		return nil
	}
	rows := snap.Syscalls()
	if m.globalFilter.Syscall == nil && m.globalFilter.Family == nil {
		return rows
	}
	filtered := make([]statsengine.SyscallSnapshot, 0, len(rows))
	for _, row := range rows {
		if m.globalFilter.MatchesSyscallRow(row.Name, string(row.TraceID.Family())) {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

// handleSortKey applies the sort / reverse-sort keys through the active
// tab's registered HandleSort hook, so a new table tab needs only a
// registry entry - this dispatcher is tab-agnostic.
func (m *Model) handleSortKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	reverse := key.Matches(msg, m.keys.ReverseSort)
	if !reverse && !key.Matches(msg, m.keys.Sort) {
		return false, nil
	}
	if d := lookupTab(m.activeTab); d.HandleSort != nil {
		return d.HandleSort(m, reverse)
	}
	return false, nil
}

// handleSyscallsSortKey is the Syscalls tab's HandleSort hook: capture the
// selected syscall name, toggle the selected column's sort, and re-anchor
// the selection so that row stays in view in the new order. All the state
// mechanics live in tableTabState.applySort.
func (m *Model) handleSyscallsSortKey(reverse bool) (bool, tea.Cmd) {
	rows := m.sortedSyscallRows()
	idx := m.syscallsTab.selectedIndex(len(rows))
	var selectedName string
	if idx < len(rows) {
		selectedName = rows[idx].Name
	}
	handled := m.syscallsTab.applySort(reverse, m.syscallsTab.col,
		func(col int) (syscallSortKey, bool) { return syscallSortKeyForColumn(m.width, col) },
		func(current int) int {
			return reanchorOffset(current, m.sortedSyscallRows(), selectedName, findSyscallOffset)
		})
	return handled, nil
}

// handleFilesSortKey is the Files tab's HandleSort hook, dispatching between
// the dir-grouped and the plain sub-table; both use the same applySort
// mechanics with their own anchor row.
func (m *Model) handleFilesSortKey(reverse bool) (bool, tea.Cmd) {
	// The whole tab is gated on its viz mode, covering both sub-tables: the
	// dir sub-table has no mode of its own, and the old switch arm ignored
	// the sort key in bubbles/treemap/icicle exactly like this gate does.
	if m.filesTab.mode != tabVizModeTable {
		return false, nil
	}
	if m.filesDirGrouped {
		rows := m.sortedDirRows()
		idx := m.filesDirTab.selectedIndex(len(rows))
		var selectedDir string
		if idx < len(rows) {
			selectedDir = rows[idx].Dir
		}
		handled := m.filesDirTab.applySort(reverse, m.filesDirTab.col,
			fileDirSortKeyForColumn,
			func(current int) int {
				return reanchorOffset(current, m.sortedDirRows(), selectedDir, findDirOffset)
			})
		return handled, nil
	}
	rows := m.sortedFileRows()
	idx := m.filesTab.selectedIndex(len(rows))
	var selectedPath string
	if idx < len(rows) {
		selectedPath = rows[idx].Path
	}
	handled := m.filesTab.applySort(reverse, m.filesTab.col,
		fileSortKeyForColumn,
		func(current int) int {
			return reanchorOffset(current, m.sortedFileRows(), selectedPath, findFileOffset)
		})
	return handled, nil
}

// handleProcessesSortKey is the Processes tab's HandleSort hook; the anchor
// row is the selected process row (processKey: PID and lifetime, since a
// recycled PID has one row per lifetime), so the selection survives the
// re-order.
func (m *Model) handleProcessesSortKey(reverse bool) (bool, tea.Cmd) {
	rows := m.sortedProcessTableRows()
	idx := m.processesTab.selectedIndex(len(rows))
	var selectedKey string
	if idx < len(rows) {
		selectedKey = processRowKey(rows[idx])
	}
	handled := m.processesTab.applySort(reverse, m.processesTab.col,
		processSortKeyForColumn,
		func(current int) int {
			return reanchorOffset(current, m.sortedProcessTableRows(), selectedKey, findProcessOffset)
		})
	return handled, nil
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

func (m *Model) selectedFileSnapshot() (statsengine.FileSnapshot, bool) {
	rows := m.sortedFileRows()
	index, ok := m.filesTab.selected(len(rows))
	if !ok {
		return statsengine.FileSnapshot{}, false
	}
	return rows[index], true
}

func (m *Model) sortedFileRows() []statsengine.FileSnapshot {
	return sortedFileSnapshots(m.snapshotOrZero().Files(), m.filesTab.sort)
}

func (m *Model) selectedFilePath() string {
	selected, ok := m.selectedFileSnapshot()
	if !ok {
		return ""
	}
	return selected.Path
}

func (m *Model) selectedDirSnapshot() (DirSnapshot, bool) {
	rows := m.sortedDirRows()
	index, ok := m.filesDirTab.selected(len(rows))
	if !ok {
		return DirSnapshot{}, false
	}
	return rows[index], true
}

func (m *Model) sortedDirRows() []DirSnapshot {
	snap := m.snapshotOrZero()
	return sortedDirSnapshots(snapshotDirRows(&snap), m.filesDirTab.sort)
}

func (m *Model) handleHelpToggleKey(msg tea.KeyPressMsg) (bool, tea.Model, tea.Cmd) {
	// The expanded dashboard help bar is bound to F1 because H is
	// intercepted at the top level (tui.handleGlobalKeyPress) to open the
	// global help overlay, leaving the bar with no reachable key when it
	// was bound to H (audit domain-05 F4).
	if msg.Code != tea.KeyF1 {
		return false, m, nil
	}
	// The help bar's height is a global layout change: it resizes the
	// content viewport and so viewport-dependent item lists (the Files
	// icicle's tiles).
	m.keepAllSelections(func() { m.showHelp = !m.showHelp })
	// Keep sub-model state in sync so View() stays a pure render pass.
	// The flamegraph viewport shrinks/grows when the help bar expands/collapses;
	// the live stream footer row follows the help bar, while the paused
	// selection/column/search footer always renders (see eventstream.Model.View).
	flameCmd := m.syncFlameViewport()
	m.streamModel.SetFooterVisible(m.showHelp)
	return true, m, flameCmd
}

func (m *Model) handleFlameConsumedKey(msg tea.KeyPressMsg) (bool, tea.Model, tea.Cmd) {
	if m.activeTab != TabFlame || !m.flamegraphModel.ConsumesKey(msg) {
		return false, m, nil
	}
	next, cmd := m.flamegraphModel.Update(msg)
	m.flamegraphModel = next.(*flamegraphtui.Model)
	return true, m, cmd
}

// handleShortcutKey processes tab-navigation and action shortcuts. The
// active tab's own keys (HandleKey) and the numeric shortcuts are resolved
// via the tab registry so that adding a new tab requires only a new
// tabDescriptor entry — this function never needs to be modified (OCP).
func (m *Model) handleShortcutKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Tab):
		m.activeTab = nextTab(m.activeTab)
		return true, nil
	case key.Matches(msg, m.keys.ShiftTab):
		m.activeTab = prevTab(m.activeTab)
		return true, nil
	case key.Matches(msg, m.keys.Visualize):
		return true, m.cycleVisualizationMode()
	case key.Matches(msg, m.keys.Metric):
		return true, m.toggleBubbleMetric()
	case key.Matches(msg, m.keys.Refresh):
		return true, m.resetBaselineCmd()
	}
	if d := lookupTab(m.activeTab); d.HandleKey != nil {
		if handled, cmd := d.HandleKey(m, msg); handled {
			return true, cmd
		}
	}
	// Fall through to registry-driven numeric tab shortcuts. Each tab
	// registers its own key binding in tabDescriptors; no changes here
	// are needed when new tabs are added.
	if tab, ok := tabForShortcutKey(msg, m.keys); ok {
		m.activeTab = tab
		return true, nil
	}
	return false, nil
}

// toggleFilesDirGrouping flips the Files tab's directory grouping. It needs no
// bubble tick chain: the alternative views (bubbles, treemap, icicle) exist
// only while grouped, and leaving grouped mode resets the tab to the table, so
// a toggle never lands on a visible bubble chart. The chart is fed by the next
// stats tick and by entering bubbles mode (cycleVisualizationMode), both of
// which start the chain. (Test: TestDirGroupingToggleNeverNeedsABubbleChain.)
func (m *Model) toggleFilesDirGrouping() {
	m.filesDirGrouped = !m.filesDirGrouped
	if !m.filesDirGrouped && m.filesTab.mode != tabVizModeTable {
		m.filesTab.mode = tabVizModeTable
	}
}

func (m *Model) handleUnhandledKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.activeTab != TabFlame {
		return m, nil
	}
	next, flameCmd := m.flamegraphModel.Update(msg)
	m.flamegraphModel = next.(*flamegraphtui.Model)
	return m, flameCmd
}

func (m *Model) selectedProcessSnapshot() (statsengine.ProcessSnapshot, bool) {
	rows := m.snapshotOrZero().Processes()
	if len(rows) == 0 {
		return statsengine.ProcessSnapshot{}, false
	}

	switch {
	case m.processesTab.mode == tabVizModeTreemap:
		// The same item the treemap highlights (processesTreemapSelection).
		return processByKey(rows, m.processesTreemapSelection().selectedKey())
	case m.processesTab.mode == tabVizModeBubbles:
		// The highlighted bubble's ID is its processKey (processBubbleData),
		// so resolve it by key like the treemap. Re-sorting the rows here to
		// find the same index broke on metric ties: the chart breaks them by
		// the display label ("20#1:x") and a second sort by any other string
		// disagrees whenever a recycled PID is present.
		return processByKey(rows, m.processesTab.bubble.selectedID())
	default:
		return indexedProcessSnapshot(m.sortedProcessTableRows(), m.processesTab.offset)
	}
}

func (m *Model) sortedProcessTableRows() []statsengine.ProcessSnapshot {
	return sortedProcessTableRows(m.snapshotOrZero().Processes(), m.processesTab.sort)
}

// processByKey returns the row whose selection key (processKey) is key; an
// empty key matches no row.
func processByKey(rows []statsengine.ProcessSnapshot, key string) (statsengine.ProcessSnapshot, bool) {
	for _, row := range rows {
		if processRowKey(row) == key {
			return row, true
		}
	}
	return statsengine.ProcessSnapshot{}, false
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

// postKeyTransitionCmd assembles the commands needed when the active tab
// changes after a key press. Each tab's InitCmd is started when we first
// enter that tab so high-frequency ticks (stream, flame) resume correctly.
func (m *Model) postKeyTransitionCmd(prevActiveTab Tab, cmd tea.Cmd) tea.Cmd {
	cmds := make([]tea.Cmd, 0, 4)
	cmds = append(cmds, cmd)
	if prevActiveTab != m.activeTab {
		cmds = append(cmds, m.tabEntryTickCmd(m.activeTab))
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

// handleScrollKey dispatches navigation key presses to the active tab's
// registered scroll handler. Bubble-chart scroll is handled first since it
// applies regardless of which tab-specific handler is registered.
func (m *Model) handleScrollKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if m.bubbleEnabledForTab(m.activeTab) {
		return m.handleBubbleScrollKey(msg)
	}
	d := lookupTab(m.activeTab)
	if d.HandleScroll == nil {
		return false, nil
	}
	return d.HandleScroll(m, msg)
}

// handleBubbleScrollKey handles directional keys when a bubble chart is active.
func (m *Model) handleBubbleScrollKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	switch msg.String() {
	case "down", "j", "right", "l":
		return m.moveBubbleSelection(1), nil
	case "up", "k", "left", "h":
		return m.moveBubbleSelection(-1), nil
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

// clampTableColumns clamps every tab's selected column(s) through the
// registry ClampColumns hooks.
func (m *Model) clampTableColumns() {
	for _, tab := range orderedTabs() {
		if d := tabDescriptors[tab]; d.ClampColumns != nil {
			d.ClampColumns(m)
		}
	}
}

// The row-count helpers feed the tab registry's RowCount hooks and the
// scroll handlers' clamping. They read the live snapshot on every call so
// a stats tick that changes the row set immediately changes the clamp.
func (m *Model) syscallsRowCount() int {
	snap := m.snapshotOrZero()
	return len(m.visibleSyscallRows(&snap))
}

func (m *Model) filesPlainRowCount() int {
	return m.snapshotOrZero().FilesCount()
}

func (m *Model) filesDirRowCount() int {
	snap := m.snapshotOrZero()
	return len(snapshotDirRows(&snap))
}

// filesDirRowCountForMode is the navigation bound of the dir-grouped view:
// the number of items filesDirTab.offset selects among in the active mode.
func (m *Model) filesDirRowCountForMode() int {
	return len(m.filesDirSelectionKeys())
}

// filesDirSelectionKeys returns, in selection order, the stable identity of
// every item filesDirTab.offset indexes in the active viz mode: directory
// paths of the sorted table rows (also the bubbles-mode fallback), of the
// treemap items, or the full paths of the icicle tiles. Each list is built
// the way its renderer builds it, so offset i here is item i on screen.
func (m *Model) filesDirSelectionKeys() []string {
	metric := m.filesTab.bubble.Metric()
	switch m.filesTab.mode {
	case tabVizModeTreemap:
		return treemapItemKeys(buildFilesTreemapItems(m.latest, metric))
	case tabVizModeIcicle:
		// The Files viewport, the size View() lays the icicle out in.
		width, height := m.contentViewport(TabFiles, m.width, m.height)
		return filesIcicleTileKeys(m.latest, width, height, metric)
	default:
		return keysOf(m.sortedDirRows(), dirKey)
	}
}

// filesDirAnchorsByKey reports whether a stats tick re-anchors the
// dir-grouped selection by identity: always in the treemap and icicle, which
// reorder their items by metric value on every refresh, and in the table
// only once a sort is chosen (unsorted it tracks the position). Bubbles
// mode follows the table rule because the offset indexes the table rows
// there; the bubble chart keeps its own selection.
func (m *Model) filesDirAnchorsByKey() bool {
	switch m.filesTab.mode {
	case tabVizModeTreemap, tabVizModeIcicle:
		return true
	default:
		return m.filesDirTab.sort.active
	}
}

// keepFilesDirSelection runs change - a mode, metric or viewport change
// that reorders or resizes the dir-grouped item list - and re-finds the
// previously selected item afterwards, clamping when it is gone.
func (m *Model) keepFilesDirSelection(change func()) {
	if !m.filesDirGrouped {
		change()
		return
	}
	m.filesDirSelection().keep(change)
}

// filesDirSelection is the dir-grouped selection over the items of the
// active viz mode (filesDirSelectionKeys).
func (m *Model) filesDirSelection() keyedSelection {
	return keyedSelection{offset: &m.filesDirTab.offset, keys: m.filesDirSelectionKeys, wanted: &m.filesDirTab.wanted}
}

// syscallsTableSelection is the Syscalls table selection over the visible,
// sorted rows, keyed by syscall name.
func (m *Model) syscallsTableSelection() keyedSelection {
	return keyedSelection{offset: &m.syscallsTab.offset, wanted: &m.syscallsTab.wanted, keys: func() []string {
		return keysOf(m.sortedSyscallRows(), func(row statsengine.SyscallSnapshot) string { return row.Name })
	}}
}

// syscallsTreemapSelection is the Syscalls treemap selection. It is keyed
// by syscall name in every mode: the treemap reorders its items by metric
// value on every refresh and on every metric change, so a positional
// selection would land on whatever syscall moved into its slot.
func (m *Model) syscallsTreemapSelection() keyedSelection {
	return keyedSelection{offset: &m.syscallsTreemapOffset, keys: m.syscallsTreemapKeys, wanted: &m.syscallsTreemapWanted}
}

// syscallsTreemapKeys returns the syscall names of the treemap items in
// layout order, built the way tabRenderSyscalls builds them, so offset i
// here is tile i on screen.
func (m *Model) syscallsTreemapKeys() []string {
	return treemapItemKeys(buildSyscallTreemapItems(m.visibleSyscallRows(m.latest), m.syscallsTab.bubble.Metric()))
}

// keepSyscallsSelection is the Syscalls tab's KeepSelection hook. The
// metric key reorders the treemap, and a global filter change (Syscall and
// Family dimensions, see visibleSyscallRows) removes rows from both the
// table and the treemap; either way both selections follow their syscall.
// Changes that leave a list as it is leave its selection as it is.
func (m *Model) keepSyscallsSelection(change func()) {
	m.keepSnapshotSelections(change, m.syscallsTableSelection(), m.syscallsTreemapSelection())
}

// processesTableSelection is the Processes table selection over the sorted
// table rows, keyed by PID (processKey). Bubbles mode shares it: the bubble
// chart keeps its own selection, the offset still indexes the table rows.
func (m *Model) processesTableSelection() keyedSelection {
	return keyedSelection{offset: &m.processesTab.offset, wanted: &m.processesTab.wanted, keys: func() []string {
		return keysOf(m.sortedProcessTableRows(), processRowKey)
	}}
}

// processesTreemapSelection is the Processes treemap selection, keyed by
// PID in every mode for the same reason as syscallsTreemapSelection. Its
// keys are built the way renderProcessesTreemap builds its items, so offset
// i here is tile i on screen.
func (m *Model) processesTreemapSelection() keyedSelection {
	return keyedSelection{offset: &m.processesTreemapOffset, wanted: &m.processesTreemapWanted, keys: func() []string {
		return treemapItemKeys(buildProcessesTreemapItems(m.latest, m.processesTab.bubble.Metric()))
	}}
}

// keepProcessesSelection is the Processes tab's KeepSelection hook: the
// metric key reorders the treemap, so its selection follows the PID. The
// table selection is kept the same way; no current change reorders the
// table rows, so it is left where it is. A viz-mode change touches neither:
// each mode keeps its own selection.
func (m *Model) keepProcessesSelection(change func()) {
	m.keepSnapshotSelections(change, m.processesTableSelection(), m.processesTreemapSelection())
}

// keepSnapshotSelections is keepSelections for selections whose keys come
// from the stats snapshot. Without a snapshot (before the first tick, or
// after PrepareForTraceRestart until the new session's first tick) the key
// lists are empty for lack of data, not because the items are gone, so
// re-anchoring would find nothing to follow. The change is then applied
// as is and the offsets are left for the first tick to clamp, as a
// positional selection is. A snapshot with no rows is data and still
// re-anchors, but an empty list never resets an offset to 0: the selected
// key is remembered (stickyKey) and looked for again in the following
// snapshots, until the user moves the selection or the grace passes.
func (m *Model) keepSnapshotSelections(change func(), sels ...keyedSelection) {
	if m.latest == nil {
		change()
		return
	}
	keepSelections(change, sels...)
}

func (m *Model) processesRowCount() int {
	return m.snapshotOrZero().ProcessesCount()
}

func (m *Model) snapshotOrZero() statsengine.Snapshot {
	if m.latest == nil {
		return statsengine.Snapshot{}
	}
	return *m.latest
}

// resetBaselineCmd restarts the stats/flame baseline: the live trie and the
// stats engine are cleared so aggregates rebuild from zero. The stream ring
// buffer is intentionally NOT cleared here: the stream is a chronological
// event log rather than an aggregate, so its rows survive baseline resets
// (both the `r` key and auto-reset ticks) and are only cleared when a new
// PID/TID selection starts a fresh trace (runtime.resetStreamBuffer).
// This retention is locked by TestTUIIntegration_Global_ResetKeepsStreamRows.
// The engine is cleared and the generation bumped here on the UI goroutine
// (so every older in-flight tick is dropped on arrival), while the post-reset
// snapshot is built by the returned command like any other refresh.
func (m *Model) resetBaselineCmd() tea.Cmd {
	if m.liveTrie != nil {
		m.liveTrie.Reset()
	}
	m.beginStatsGeneration()
	return m.statsTickCmd()
}

// beginStatsGeneration resets the stats engine and starts a new stats
// generation, so every tick built before the reset is dropped on arrival.
func (m *Model) beginStatsGeneration() {
	m.statsGen++
	if m.engine != nil {
		m.engine.Reset()
	}
}

// resetStats resets the stats engine (beginStatsGeneration) and returns the
// post-reset snapshot as a tick of the new generation, built synchronously:
// the engine was just cleared, so there are no percentile reservoirs to
// select from and the build is cheap. A Snapshot failure travels as
// StatsTickMsg.Err, so the dashboard keeps displaying the last successful
// snapshot.
func (m *Model) resetStats() messages.StatsTickMsg {
	m.beginStatsGeneration()
	return m.statsTick()
}

// ResetStats restarts the stats baseline on behalf of the parent model (probe
// toggles and in-place filter swaps) and applies the post-reset snapshot
// straight away, so the tabs show the fresh baseline without waiting for the
// next refresh tick and no older in-flight tick can overwrite it. The live
// trie is left alone: callers that also need a fresh flame baseline reset it
// themselves.
func (m *Model) ResetStats() tea.Cmd {
	_, cmd := m.handleStatsTick(m.resetStats())
	return cmd
}

// LatestSnapshot returns the most recently received snapshot.
func (m *Model) LatestSnapshot() *statsengine.Snapshot {
	return m.latest
}

// ActiveTab returns the currently selected dashboard tab.
func (m *Model) ActiveTab() Tab {
	return m.activeTab
}

// ExportStreamCSVInputs captures the concrete inputs the stream CSV export
// needs, on the caller's goroutine. The export command (tui.runExportCmd)
// runs on a Bubble Tea command goroutine, and handing it the live Model
// pointer would race with Update/View mutating the model's plain fields -
// the pre-pointer-receiver value copy used to provide that isolation by
// accident. The Source the captured values carry is safe to read from any
// goroutine (Snapshot is RWMutex-guarded).
func (m *Model) ExportStreamCSVInputs() (eventstream.Source, eventstream.Filter, string) {
	return m.streamModel.ExportInputs()
}

// BlocksGlobalShortcuts reports whether the active tab should suppress a
// top-level shortcut for the given key press.
func (m *Model) BlocksGlobalShortcuts(msg tea.KeyPressMsg) bool {
	d := lookupTab(m.activeTab)
	return d.BlocksGlobalShortcut != nil && d.BlocksGlobalShortcut(m, msg)
}

// TextInputFocused reports whether the active tab has a text input open (the
// flamegraph search, the stream search or export-filename modal). While one is
// open, printable keys are text and the top-level model must not treat them as
// shortcuts (q quits, H opens help).
func (m *Model) TextInputFocused() bool {
	d := lookupTab(m.activeTab)
	return d.TextInputFocused != nil && d.TextInputFocused(m)
}

// SetStreamSource updates the live stream source used by the stream tab.
func (m *Model) SetStreamSource(source eventstream.Source) {
	m.streamModel.SetSource(source)
}

// SetGlobalFilter forwards the shared TUI filter into the stream tab so
// buffered rows can be re-filtered immediately.
func (m *Model) SetGlobalFilter(filter globalfilter.Filter) {
	// The Syscall and Family dimensions scope the Syscalls rows
	// (visibleSyscallRows), so the swap can drop rows from under a
	// selection: keep every tab's selected item across it.
	m.keepAllSelections(func() { m.globalFilter = filter.Clone() })
	m.streamModel.SetFilter(eventstream.Filter(filter))
}

// SetFilterStack forwards the shared global filter stack into dashboard views.
func (m *Model) SetFilterStack(stack []string) {
	m.filterStack = append(m.filterStack[:0], stack...)
	m.streamModel.SetFilterStack(stack)
}

// SetFilterNotice sets (or, with an empty string, clears) the chrome line
// explaining why a requested filter change was refused.
//
// The notice must never outlive the filter it describes, so the TUI model
// clears it on every path that changes the filter on screen - not only when a
// filter is accepted (refuseUnusableFilter) but also on undo and on a PID/TID
// pick, neither of which goes through the refusal check.
func (m *Model) SetFilterNotice(notice string) {
	m.filterNotice = notice
}

// SetFamilyHint sets (or, with an empty string, clears) the "family not
// traced" hint. It never touches the filter notice, so a pending refusal
// stays visible however often the hint is refreshed; both are rendered, the
// notice first (see filterSummary).
func (m *Model) SetFamilyHint(hint string) {
	m.familyHint = hint
}

// SetRecordingStatus updates the visible recording state summary rendered in the dashboard chrome.
func (m *Model) SetRecordingStatus(status string) {
	m.recordingStatus = status
}

// SetLiveTrie updates the live trie source used by the flamegraph tab.
func (m *Model) SetLiveTrie(liveTrie coreflamegraph.LiveTrieSource) {
	m.liveTrie = liveTrie
	m.flamegraphModel.SetLiveTrie(liveTrie)
	if m.width > 0 && m.height > 0 {
		// SetLiveTrie dropped every frame, so there is nothing to animate
		// and no tick to schedule.
		_ = m.syncFlameViewport()
	}
	m.flamegraphModel.RefreshFromLiveTrie()
}

// PrepareForTraceRestart clears aggregate state while keeping the current tab
// and retained stream rows intact for the next trace session.
func (m *Model) PrepareForTraceRestart() {
	// The next session brings a fresh engine: a tick from the old one that
	// is still in flight must not repopulate the cleared view.
	m.statsGen++
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
	m.forEachBubbleChart(func(chart *bubbleChart) { chart.SetDarkMode(isDark) })
}

// SnapshotCmd returns a command that fetches and emits a fresh dashboard
// snapshot. The snapshot is built when the command runs (off the UI
// goroutine), not when SnapshotCmd is called.
func (m *Model) SnapshotCmd() tea.Cmd {
	return m.statsTickCmd()
}

// SetPidFilter updates the active PID filter used by tab render hints.
func (m *Model) SetPidFilter(pid int) {
	m.pidFilter = pid
}

// View renders the tab bar, active tab scaffold, and help bar.
// This is a pure render pass: it reads model state but never mutates it.
// Sub-model state (stream footer visibility, flamegraph viewport dimensions)
// is kept in sync by the Update() handlers that trigger each state change,
// so no fixup is needed here.
func (m *Model) View() tea.View {
	width, height := common.EffectiveViewport(m.width, m.height)
	_, activeHeight := m.contentViewport(m.activeTab, width, height)

	var b strings.Builder
	b.WriteString(renderTabBar(m.activeTab, width))
	b.WriteString("\n")
	b.WriteString(m.renderActiveContent(width, activeHeight, &m.streamModel, m.flamegraphModel))
	b.WriteString("\n")
	if m.showHelp {
		b.WriteString(renderHelpBarWithStatus(m.keys, width, m.filterSummary()))
	} else {
		b.WriteString(renderHelpHintWithStatus(width, m.filterSummary()))
	}
	return tea.NewView(common.Current().ScreenStyle.Render(b.String()))
}

func (m *Model) filterSummary() string {
	// Use a Builder to avoid repeated string copies for the optional suffix segments
	// (filter stack, recording status, auto-reset label) on every render tick.
	var b strings.Builder
	// The refusal goes first: it is the newest thing that happened to the
	// filter, and appendStatusText trims this summary from the right. The
	// family hint follows it, so on a narrow row the hint - whose attach state
	// the probes modal's Families view also shows - is trimmed before the
	// refusal, which they cannot get back anywhere else.
	for _, notice := range []string{m.filterNotice, m.familyHint} {
		if notice != "" {
			b.WriteString(notice)
			b.WriteString(" | ")
		}
	}
	b.WriteString("filter: ")
	b.WriteString(presenter.FilterSummary(m.globalFilter))
	if len(m.filterStack) > 0 {
		b.WriteString(" | stack: ")
		b.WriteString(strings.Join(m.filterStack, " | "))
	}
	if m.recordingStatus != "" {
		b.WriteString(" | ")
		b.WriteString(m.recordingStatus)
	}
	b.WriteString(" | ")
	b.WriteString(m.autoResetStatus())
	// Filter patterns are often copied from traced comm/file values (push
	// filter from a selected row) and the notice/recording status can echo
	// paths, so the plain-text summary is sanitised before it is rendered.
	return common.Sanitize(b.String())
}

// renderActiveContent renders the active tab's body through its registered
// Render hook; each tab draws its own visualization modes and
// waiting-for-stats state.
func (m *Model) renderActiveContent(width, activeHeight int, streamModel *eventstream.Model, flameModel *flamegraphtui.Model) string {
	return renderActiveTabContent(
		m, m.activeTab, m.latest, streamModel, flameModel,
		width, activeHeight,
	)
}

// activeTableHeight is the active tab's content height, which bounds the
// table page step.
func (m *Model) activeTableHeight() int {
	_, activeHeight := m.contentViewport(m.activeTab, m.width, m.height)
	return activeHeight
}

// syncFlameViewport sizes the flamegraph sub-model to the Flame tab's
// content viewport and returns the command driving the resulting frame
// animation, which the caller must hand to the runtime: without it the
// frames stay at the first interpolated step. A hidden Flame tab snaps
// instead of animating, because handleActiveTabMsg drops animation ticks
// while another tab is active.
func (m *Model) syncFlameViewport() tea.Cmd {
	width, height := m.contentViewport(TabFlame, m.width, m.height)
	return m.flamegraphModel.SetViewport(width, height, m.activeTab == TabFlame)
}

// onTabEntered brings a tab whose content is only refreshed while it is
// visible up to date the moment it becomes active, so it never shows a
// stale frame while waiting for its first tick: the flame tab resumes its
// animation and resizes, and the stream (skipped by hidden stats ticks and
// stream ticks) takes a fresh snapshot of the ring buffer right away.
func (m *Model) onTabEntered(tab Tab) tea.Cmd {
	switch tab {
	case TabFlame:
		return m.enterFlameTab()
	case TabStream:
		m.streamModel.Refresh()
	}
	return nil
}

// enterFlameTab brings the flamegraph up to date when the Flame tab becomes
// active. An animation left running when the user switched away lost its
// tick (handleActiveTabMsg drops them off-tab), so the tick loop is restarted
// first; the viewport sync then reuses that loop, keeping it to one. The sync
// itself is normally a no-op, since hidden resizes already snapped the layout,
// and stays as a guard against a viewport that was never set.
func (m *Model) enterFlameTab() tea.Cmd {
	resume := m.flamegraphModel.ResumeAnimationCmd()
	return batchCmds(resume, m.syncFlameViewport())
}

// syncStreamViewport sizes the event-stream sub-model to the Stream tab's
// content viewport.
func (m *Model) syncStreamViewport() {
	m.streamModel.SetViewport(m.contentViewport(TabStream, m.width, m.height))
}

// setBubbleViewports sizes every table tab's bubble chart to that tab's
// content viewport, so any chart is ready before it becomes the active
// view.
func (m *Model) setBubbleViewports() {
	for _, tab := range orderedTabs() {
		if t := m.tableTabFor(tab); t != nil {
			t.bubbleChart().SetViewport(m.contentViewport(tab, m.width, m.height))
		}
	}
}

// refreshBubbleData pushes the latest snapshot data into EVERY registered
// bubble chart (through the registry RefreshBubble hooks) and returns
// whether the ACTIVE tab's chart is still animating, which drives the
// bubble tick loop. Feeding is deliberately not limited to the active tab:
// a tab left in bubbles mode renders the moment the user switches back to
// it, and the nil-snapshot feed is what clears the charts of non-active
// tabs after a trace restart (PrepareForTraceRestart resets only the
// active one) - lazily feeding only the active tab left both of those
// windows showing stale or previous-session data (review finding).
func (m *Model) refreshBubbleData() bool {
	m.setBubbleViewports()
	animating := false
	for _, tab := range orderedTabs() {
		if d := tabDescriptors[tab]; d.RefreshBubble != nil && d.RefreshBubble(m) && tab == m.activeTab {
			animating = true
		}
	}
	if !m.bubbleEnabledForTab(m.activeTab) {
		return false
	}
	return animating
}

// refreshFilesBubbleData updates the files bubble chart. When not in
// dir-grouped mode the chart is cleared with a status hint explaining why.
func (m *Model) refreshFilesBubbleData() bool {
	if m.filesDirGrouped {
		m.filesTab.bubble.SetStatusHint("")
		return m.filesTab.bubble.SetData(filesDirBubbleData(m.latest))
	}
	m.filesTab.bubble.SetStatusHint("Files bubble view requires directory mode (press d).")
	m.filesTab.bubble.SetData(nil)
	return false
}

// bubbleChartFor returns the bubble chart for the given tab, or nil when
// that tab has no bubble chart.
func (m *Model) bubbleChartFor(tab Tab) *bubbleChart {
	if t := m.tableTabFor(tab); t != nil {
		return t.bubbleChart()
	}
	return nil
}

// tabVizModeFor returns the current visualization mode for tab. Only the
// table tabs carry per-tab mode state; all other tabs implicitly use the
// table view.
func (m *Model) tabVizModeFor(tab Tab) tabVizMode {
	if t := m.tableTabFor(tab); t != nil {
		return t.currentVizMode()
	}
	return tabVizModeTable
}

// setTabVizMode updates the stored viz mode for tab.
func (m *Model) setTabVizMode(tab Tab, mode tabVizMode) {
	if t := m.tableTabFor(tab); t != nil {
		t.setVizMode(mode)
	}
}

// bubbleEnabledForTab reports whether the bubble chart is the active view for
// tab; never while the tab's alternative visualizations are unavailable (see
// tabDescriptor.AltVizReady).
func (m *Model) bubbleEnabledForTab(tab Tab) bool {
	return m.altVizReady(tab) && m.tabVizModeFor(tab) == tabVizModeBubbles
}

// tickActiveBubbleChart advances the animation frame for the active tab's
// bubble chart. Returns true while the chart is still animating; false when
// it has settled or bubbles are not active for the current tab, which is the
// signal for handleBubbleTick to let the tick chain die.
func (m *Model) tickActiveBubbleChart() bool {
	if !m.bubbleEnabledForTab(m.activeTab) {
		return false
	}
	ch := m.bubbleChartFor(m.activeTab)
	if ch == nil {
		return false
	}
	return ch.Tick(0)
}

// moveBubbleSelection shifts the bubble selection by delta for the active tab.
func (m *Model) moveBubbleSelection(delta int) bool {
	ch := m.bubbleChartFor(m.activeTab)
	if ch == nil {
		return false
	}
	return ch.MoveSelection(delta)
}

// activeBubbleChartHasNodes reports whether the active tab's bubble chart
// has any nodes to display.
func (m *Model) activeBubbleChartHasNodes() bool {
	ch := m.bubbleChartFor(m.activeTab)
	if ch == nil {
		return false
	}
	return ch.HasNodes()
}

func (m *Model) cycleVisualizationMode() tea.Cmd {
	allowed := m.allowedVizModes(m.activeTab)
	if len(allowed) < 2 {
		return nil
	}
	current := m.tabVizModeFor(m.activeTab)
	next := nextVizMode(current, allowed)
	// Each mode may order a different item list; the tab's KeepSelection
	// hook keeps the same item selected across the switch.
	m.keepSelection(m.activeTab, func() { m.setTabVizMode(m.activeTab, next) })

	if next == tabVizModeBubbles {
		m.refreshBubbleData()
		if m.activeBubbleChartHasNodes() {
			return m.ticks.startBubble()
		}
	}
	return nil
}

// toggleBubbleMetric cycles the bubble metric for the active tab's chart.
// The metric is fixed while the tab's alternative visualizations are
// unavailable (the Files tab outside dir-grouped mode).
func (m *Model) toggleBubbleMetric() tea.Cmd {
	if !m.altVizReady(m.activeTab) {
		return nil
	}
	ch := m.bubbleChartFor(m.activeTab)
	if ch == nil {
		return nil
	}
	// The treemap and icicle order their items by the metric; the tab's
	// KeepSelection hook keeps the same item selected.
	m.keepSelection(m.activeTab, func() { ch.SetMetric(nextBubbleMetric(ch.Metric())) })
	m.refreshBubbleData()
	if m.bubbleEnabledForTab(m.activeTab) && m.activeBubbleChartHasNodes() {
		return m.ticks.startBubble()
	}
	return nil
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

// renderActiveTabContent dispatches to the registered render function for
// tab. Each Render hook owns every state of its tab, including the
// waiting-for-stats placeholder (snap may be nil) and the absent stream or
// flame model, so there is no tab-specific guard here.
func renderActiveTabContent(m *Model, tab Tab, snap *statsengine.Snapshot, streamModel *eventstream.Model, flameModel *flamegraphtui.Model, width, height int) string {
	d := lookupTab(tab)
	if d.Render == nil {
		return common.Current().PanelStyle.Render("Unknown tab")
	}
	return d.Render(m, snap, streamModel, flameModel, width, height)
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
