package dashboard

import (
	"sort"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	flamegraphtui "ior/internal/tui/flamegraph"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

// tabRenderFn is a function that renders a tab's content area given the
// current model state and viewport dimensions. It returns the rendered string.
type tabRenderFn func(m *Model, snap *statsengine.Snapshot, stream *eventstream.Model, flame *flamegraphtui.Model, width, height int) string

// tabScrollFn handles scroll key presses for a specific tab. Returns whether
// the key was handled and an optional tea.Cmd. It is called only when bubbles
// are not active (bubble scroll is handled before tab dispatch).
type tabScrollFn func(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd)

// tabDescriptor is a tab's controller: its metadata plus every hook the
// tab-agnostic dispatches in model.go call for it. Registering a new tab
// requires a new entry in tabDescriptors plus the pieces that are genuinely
// tab-specific: a tableTabState field on Model for a table tab (exposed
// through TableState), its column definitions, row-count and sort-key
// mapping, a key-map binding for its numeric shortcut, and a Render
// function. The dispatches (rendering, navigation, Enter, sort, tab-local
// keys, viz-mode cycling, bubble feeding, snapshot re-anchoring, column
// clamping, init ticks, shortcut lookup) all hang off the registry and never
// need editing when a tab is added.
//
// Every hook is optional: a nil hook means the tab does not take part in
// that dispatch, and each dispatcher treats nil as "not handled" (or as the
// neutral default documented on the field), never as an error.
type tabDescriptor struct {
	// Name is the full display label shown in the tab bar (e.g. "Overview").
	Name string
	// ShortName is the abbreviated label used when the tab bar is narrow.
	ShortName string
	// Position controls the left-to-right order of tabs in the tab bar.
	// Lower values appear first. The existing tabs use positions 10–70 in
	// steps of 10 so new tabs can be inserted without renumbering.
	Position int
	// AllowedVizModes lists the visualization modes available for this tab.
	// Tabs that only support the plain table view contain a single entry.
	// AltVizReady can narrow the list to the table view at runtime.
	AllowedVizModes []tabVizMode
	// AltVizReady reports whether the tab's alternative visualizations
	// (every mode but the table, and bubble-metric cycling) are available
	// right now. While it reports false only the table view is allowed and
	// the bubble chart is never the active view. Nil means always available.
	// The Files tab uses it to require directory grouping.
	AltVizReady func(m *Model) bool
	// TableState returns the tab's table-tab state component; it is the
	// only place tab identity maps to a tableTabState, so the viz-mode and
	// bubble dispatches stay generic over the tableTab interface. Nil means
	// the tab has no table state (flame, overview, latency, stream).
	TableState func(m *Model) tableTab
	// KeepSelection runs change - a change that reorders or resizes the
	// tab's item list - so that the selected item survives it. It is run
	// for the active tab on its own viz-mode and metric changes, and for
	// every registered tab on global changes (terminal resize, help bar
	// toggle, global filter swap; see keepAllSelections), so it must call
	// change exactly once. Nil means the change is applied as is.
	KeepSelection func(m *Model, change func())
	// ContentViewport returns this tab's content viewport from the terminal
	// size. It is the single source of that size: View() lays the tab out in
	// it, and every piece of state sized to match the rendered content reads
	// it through contentViewport too - the flame and stream sub-models'
	// viewports, the tab's bubble chart viewport, the table page step
	// (activeTableHeight) and the Files icicle's selection keys. Nil means
	// the standard viewport (tab bar plus the help hint or expanded help
	// bar; see flameViewport).
	ContentViewport func(width, height int, showHelp bool) (int, int)
	// InitCmd starts this tab's own tick chain whenever the tab becomes the
	// active one: on entry and when Init's tickChainsStartMsg is handled,
	// alongside the global refresh chain. It runs on the Update path and
	// supersedes the chain already running (tickScheduler.start...). Tabs
	// that need their own high-frequency tick (stream, flame) set this;
	// others leave it nil. The model is passed so the closure can use the
	// configured fastRefreshEvery interval rather than a hardcoded constant.
	InitCmd func(*Model) tea.Cmd
	// Render draws the tab body in every state the tab can be in, including
	// the waiting-for-stats state before the first snapshot and, for a table
	// tab, each of its visualization modes. Nil renders "Unknown tab".
	Render tabRenderFn
	// HandleScroll handles direction keys for this tab when bubbles are off.
	// Nil means the tab does not process scroll/navigation keys.
	HandleScroll tabScrollFn
	// HandleEnter applies Enter-on-the-selected-row for this tab, returning
	// whether the key was handled plus an optional command (the standard
	// shape is requestSelectedFilter over the tab's selected-row filter).
	// Nil means Enter does nothing on this tab.
	HandleEnter func(m *Model) (bool, tea.Cmd)
	// HandleSort applies the sort / reverse-sort key for this tab to the
	// currently selected column, re-anchoring the selection. Nil means the
	// tab is not sortable.
	HandleSort func(m *Model, reverse bool) (bool, tea.Cmd)
	// HandleKey handles the tab's own key bindings (e.g. the Files tab's
	// directory-grouping toggle) while it is the active tab. It is consulted
	// after the dashboard-wide shortcuts and before the numeric tab
	// shortcuts. Nil means the tab has no keys of its own.
	HandleKey func(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd)
	// BlocksGlobalShortcut reports whether the tab, while active, needs the
	// key press for itself (an open modal, a key its sub-model consumes), so
	// the top-level model must not act on it. Nil means it never blocks.
	BlocksGlobalShortcut func(m *Model, msg tea.KeyPressMsg) bool
	// RefreshBubble feeds the tab's bubble chart from the latest snapshot and
	// reports whether the chart is still animating. Nil means the tab has no
	// bubble chart.
	RefreshBubble func(m *Model) bool
	// CaptureSelection is called on every stats tick BEFORE the new snapshot
	// replaces the old one, for every tab (not only the active one), so a
	// tab left in the background keeps its selection too. It records the
	// identity of the tab's selected item and returns the function that
	// re-anchors the selection onto that item once the new snapshot is in
	// place. Nil means the tab keeps no snapshot-dependent selection.
	CaptureSelection func(m *Model) (reanchor func())
	// ClampColumns clamps the tab's selected table column(s) against the
	// current column layout, after a resize or a stats tick. Nil means the
	// tab has no selectable columns.
	ClampColumns func(m *Model)
	// ShortcutKey extracts the numeric shortcut key binding for this tab from
	// a KeyMap. It is called at runtime against the model's configured key map
	// so that custom key maps (e.g. in tests) are respected. Nil means the tab
	// has no direct numeric shortcut; it is still reachable via tab/shift+tab.
	ShortcutKey func(keys common.KeyMap) key.Binding
}

// tabDescriptors is the central registry mapping every known Tab to its
// descriptor. Registering a new tab (an entry in registeredTabs) is all that
// is required to make it participate in the tab bar, keyboard navigation,
// and rendering dispatch.
//
// It is populated in init rather than by its declaration because the hooks
// legitimately reach back into the registry (a Files key toggles grouping,
// which refreshes every tab's bubble chart through the registry); as a
// package-level initializer that is a compile-time initialization cycle.
// Package-level var initializers run before init, so none of them may read
// the registry (directly or through orderedTabs, lookupTab,
// forEachBubbleChart and friends): they would see it empty.
var tabDescriptors map[Tab]tabDescriptor

func init() {
	tabDescriptors = registeredTabs()
}

// registeredTabs builds the tab registry; see tabDescriptors.
func registeredTabs() map[Tab]tabDescriptor {
	return map[Tab]tabDescriptor{
		TabFlame: {
			Name:            "Flame",
			ShortName:       "Flm",
			Position:        10,
			AllowedVizModes: []tabVizMode{tabVizModeTable},
			// Use the model's tick scheduler so the configured fast interval
			// is honoured on the very first tick, not just on subsequent ticks.
			InitCmd:     func(m *Model) tea.Cmd { return m.ticks.startFlame() },
			Render:      tabRenderFlame,
			ShortcutKey: func(k common.KeyMap) key.Binding { return k.One },
			BlocksGlobalShortcut: func(m *Model, msg tea.KeyPressMsg) bool {
				return m.flamegraphModel.ConsumesKey(msg)
			},
		},
		TabOverview: {
			Name:            "Overview",
			ShortName:       "Ovr",
			Position:        20,
			AllowedVizModes: []tabVizMode{tabVizModeTable},
			Render:          tabRenderOverview,
			ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Two },
		},
		TabSyscalls: {
			Name:            "Syscalls",
			ShortName:       "Sys",
			Position:        30,
			AllowedVizModes: []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap},
			TableState:      func(m *Model) tableTab { return &m.syscallsTab },
			Render:          tabRenderSyscalls,
			HandleScroll:    tabScrollSyscalls,
			HandleEnter:     handleSyscallsEnter,
			HandleSort:      func(m *Model, reverse bool) (bool, tea.Cmd) { return m.handleSyscallsSortKey(reverse) },
			RefreshBubble: func(m *Model) bool {
				return m.syscallsTab.bubble.SetData(syscallBubbleData(m.visibleSyscallRows(m.latest)))
			},
			KeepSelection:    (*Model).keepSyscallsSelection,
			CaptureSelection: captureSyscallsSelection,
			ClampColumns: func(m *Model) {
				m.syscallsTab.col = common.ClampTableCol(m.syscallsTab.col, len(syscallColumns(m.width)))
			},
			ShortcutKey: func(k common.KeyMap) key.Binding { return k.Three },
		},
		TabFiles: {
			Name:      "Files",
			ShortName: "Fil",
			Position:  40,
			// Only the table view is available until directory grouping is on
			// (AltVizReady): bubbles, treemap and icicle all chart directories.
			AllowedVizModes:  []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap, tabVizModeIcicle},
			AltVizReady:      func(m *Model) bool { return m.filesDirGrouped },
			TableState:       func(m *Model) tableTab { return &m.filesTab },
			KeepSelection:    (*Model).keepFilesDirSelection,
			Render:           tabRenderFiles,
			HandleScroll:     tabScrollFiles,
			HandleEnter:      handleFilesEnter,
			HandleSort:       func(m *Model, reverse bool) (bool, tea.Cmd) { return m.handleFilesSortKey(reverse) },
			HandleKey:        handleFilesKey,
			RefreshBubble:    func(m *Model) bool { return m.refreshFilesBubbleData() },
			CaptureSelection: captureFilesSelection,
			ClampColumns: func(m *Model) {
				m.filesTab.col = common.ClampTableCol(m.filesTab.col, len(fileColumns(m.width)))
				m.filesDirTab.col = common.ClampTableCol(m.filesDirTab.col, len(fileDirColumns(m.width)))
			},
			ShortcutKey: func(k common.KeyMap) key.Binding { return k.Four },
		},
		TabProcesses: {
			Name:             "Processes",
			ShortName:        "Pro",
			Position:         50,
			AllowedVizModes:  []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap},
			TableState:       func(m *Model) tableTab { return &m.processesTab },
			KeepSelection:    (*Model).keepProcessesSelection,
			Render:           tabRenderProcesses,
			HandleScroll:     tabScrollProcesses,
			HandleEnter:      handleProcessesEnter,
			HandleSort:       func(m *Model, reverse bool) (bool, tea.Cmd) { return m.handleProcessesSortKey(reverse) },
			RefreshBubble:    func(m *Model) bool { return m.processesTab.bubble.SetData(processBubbleData(m.latest)) },
			CaptureSelection: captureProcessesSelection,
			ClampColumns: func(m *Model) {
				m.processesTab.col = common.ClampTableCol(m.processesTab.col, len(processColumns()))
			},
			ShortcutKey: func(k common.KeyMap) key.Binding { return k.Five },
		},
		TabLatency: {
			Name:            "Latency+Gaps",
			ShortName:       "Lat",
			Position:        60,
			AllowedVizModes: []tabVizMode{tabVizModeTable},
			Render:          tabRenderLatency,
			ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Six },
		},
		TabStream: {
			Name:            "Stream",
			ShortName:       "Str",
			Position:        70,
			AllowedVizModes: []tabVizMode{tabVizModeTable},
			// Use the model's tick scheduler so the configured fast interval
			// is honoured on the very first tick, not just on subsequent ticks.
			InitCmd: func(m *Model) tea.Cmd { return m.ticks.startStream() },
			// The stream draws its own footer, so its viewport ignores the
			// dashboard help bar.
			ContentViewport: func(width, height int, _ bool) (int, int) { return streamViewport(width, height) },
			Render:          tabRenderStream,
			HandleScroll:    tabScrollStream,
			BlocksGlobalShortcut: func(m *Model, _ tea.KeyPressMsg) bool {
				return m.streamModel.ExportModalVisible() || m.streamModel.SearchModalVisible()
			},
			ShortcutKey: func(k common.KeyMap) key.Binding { return k.Seven },
		},
	}
}

// orderedTabs returns all registered tabs sorted by their Position field.
// This is the canonical tab order used for tab bar rendering and navigation.
// It replaces the hardcoded allTabs slice so new tabs registered in
// tabDescriptors automatically appear in the correct position.
func orderedTabs() []Tab {
	tabs := make([]Tab, 0, len(tabDescriptors))
	for tab := range tabDescriptors {
		tabs = append(tabs, tab)
	}
	sort.Slice(tabs, func(i, j int) bool {
		return tabDescriptors[tabs[i]].Position < tabDescriptors[tabs[j]].Position
	})
	return tabs
}

// lookupTab returns the descriptor for the given tab, falling back to a
// sensible default when the tab is not in the registry.
func lookupTab(tab Tab) tabDescriptor {
	if d, ok := tabDescriptors[tab]; ok {
		return d
	}
	return tabDescriptor{Name: "Unknown", ShortName: "Unk", AllowedVizModes: []tabVizMode{tabVizModeTable}}
}

// tabForShortcutKey searches the registry for the first tab whose ShortcutKey
// matches the given key press message. It returns the tab and true when a match
// is found; otherwise the zero Tab value and false. Using the registry here
// means adding a new tab with a shortcut only requires a new entry in
// tabDescriptors — handleShortcutKey in model.go never needs updating.
func tabForShortcutKey(msg tea.KeyPressMsg, keys common.KeyMap) (Tab, bool) {
	for _, tab := range orderedTabs() {
		d := tabDescriptors[tab]
		if d.ShortcutKey == nil {
			continue
		}
		if key.Matches(msg, d.ShortcutKey(keys)) {
			return tab, true
		}
	}
	return 0, false
}

// tableTabFor returns the table-tab state component for tab through its
// TableState hook, or nil for tabs without one (and for unknown tabs). The
// viz-mode and bubble dispatches go through it instead of switching on tab.
func (m *Model) tableTabFor(tab Tab) tableTab {
	d := lookupTab(tab)
	if d.TableState == nil {
		return nil
	}
	return d.TableState(m)
}

// altVizReady reports whether tab's alternative visualizations are
// available right now (see tabDescriptor.AltVizReady).
func (m *Model) altVizReady(tab Tab) bool {
	d := lookupTab(tab)
	return d.AltVizReady == nil || d.AltVizReady(m)
}

// allowedVizModes returns the visualization modes available for tab: the
// registered list, narrowed to the table view while the tab's alternative
// visualizations are unavailable (the Files tab outside dir grouping).
func (m *Model) allowedVizModes(tab Tab) []tabVizMode {
	if !m.altVizReady(tab) {
		return []tabVizMode{tabVizModeTable}
	}
	return lookupTab(tab).AllowedVizModes
}

// keepSelection applies change through tab's KeepSelection hook, or
// directly when the tab registers none.
func (m *Model) keepSelection(tab Tab, change func()) {
	if d := lookupTab(tab); d.KeepSelection != nil {
		d.KeepSelection(m, change)
		return
	}
	change()
}

// keepAllSelections applies change - a global change such as a terminal
// resize, the help bar toggle or a global filter swap - through every
// registered tab's
// KeepSelection hook, so each tab's selection survives it whether or not
// the tab is active. The hooks nest in orderedTabs order (the first tab's
// hook is outermost) and change runs exactly once, innermost.
func (m *Model) keepAllSelections(change func()) {
	tabs := orderedTabs()
	for i := len(tabs) - 1; i >= 0; i-- {
		hook := tabDescriptors[tabs[i]].KeepSelection
		if hook == nil {
			continue
		}
		inner := change
		change = func() { hook(m, inner) }
	}
	change()
}

// contentViewport returns the content viewport of tab for the given
// terminal size (see tabDescriptor.ContentViewport).
func (m *Model) contentViewport(tab Tab, width, height int) (int, int) {
	if d := lookupTab(tab); d.ContentViewport != nil {
		return d.ContentViewport(width, height, m.showHelp)
	}
	return flameViewport(width, height, m.showHelp)
}

// forEachBubbleChart calls fn with the bubble chart of every registered
// table tab, so chart-wide settings (construction, theme) reach every chart
// without listing the tabs. It reads the registry, which is populated in
// init: it must not be used from a package-level var initializer.
func (m *Model) forEachBubbleChart(fn func(*bubbleChart)) {
	for _, tab := range orderedTabs() {
		if t := m.tableTabFor(tab); t != nil {
			fn(t.bubbleChart())
		}
	}
}

// renderWaitingForStats is the placeholder a snapshot-driven tab shows
// before the first stats snapshot arrives.
func renderWaitingForStats(tab Tab) string {
	return common.Current().PanelStyle.Render(tab.String() + ": waiting for stats...")
}

// tabRenderFlame adapts the flame model's View to the tabRenderFn signature.
func tabRenderFlame(_ *Model, _ *statsengine.Snapshot, _ *eventstream.Model, flame *flamegraphtui.Model, _, _ int) string {
	if flame == nil {
		return common.Current().PanelStyle.Render("Flame: waiting for model...")
	}
	return flame.View().Content
}

// tabRenderOverview adapts renderOverview to the tabRenderFn signature.
func tabRenderOverview(_ *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderOverview(snap, width, height)
}

// tabRenderLatency adapts renderLatencyGapsTab to the tabRenderFn signature.
func tabRenderLatency(_ *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderLatencyGapsTab(snap, width, height)
}

// tabRenderStream adapts the stream model's View to the tabRenderFn signature.
func tabRenderStream(_ *Model, _ *statsengine.Snapshot, stream *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	if stream == nil {
		return common.Current().PanelStyle.Render("Stream: waiting for source...")
	}
	return stream.View(width, height)
}

// tabRenderSyscalls is the Syscalls tab's Render hook: the treemap or
// bubble chart in those viz modes (both render their own empty state), the
// sort-aware table otherwise.
func tabRenderSyscalls(m *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	switch m.syscallsTab.mode {
	case tabVizModeTreemap:
		return renderSyscallsTreemap(snap, m.visibleSyscallRows(snap), width, height, m.syscallsTab.bubble.Metric(), m.syscallsTreemapOffset, m.isDark)
	case tabVizModeBubbles:
		return m.syscallsTab.bubble.Render("Syscalls", width, height)
	}
	if snap == nil {
		return renderWaitingForStats(TabSyscalls)
	}
	return renderSyscallsWithSort(snap, m.visibleSyscallRows(snap), width, height, m.syscallsTab.offset, m.syscallsTab.col, m.syscallsTab.sort)
}

// tabRenderFiles is the Files tab's Render hook. The alternative views chart
// directories, so they apply only while dir grouping is on; otherwise (and
// in table mode) it draws the dir-grouped or the plain sort-aware table.
func tabRenderFiles(m *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	if m.filesDirGrouped {
		metric := m.filesTab.bubble.Metric()
		switch m.filesTab.mode {
		case tabVizModeTreemap:
			return renderFilesTreemap(snap, width, height, metric, m.filesDirTab.offset, m.isDark)
		case tabVizModeIcicle:
			return renderFilesIcicle(snap, width, height, metric, m.filesDirTab.offset, m.isDark)
		case tabVizModeBubbles:
			return m.filesTab.bubble.Render("Files/Dirs", width, height)
		}
	}
	if snap == nil {
		return renderWaitingForStats(TabFiles)
	}
	if m.filesDirGrouped {
		return renderFilesDirGroupedWithSort(snap, width, height, m.filesDirTab.offset, m.filesDirTab.col, m.filesDirTab.sort)
	}
	return renderFilesWithSort(snap, width, height, m.filesTab.offset, m.filesTab.col, m.filesTab.sort)
}

// tabRenderProcesses is the Processes tab's Render hook: the treemap or
// bubble chart in those viz modes, the sort-aware table otherwise.
func tabRenderProcesses(m *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	switch m.processesTab.mode {
	case tabVizModeTreemap:
		return renderProcessesTreemap(snap, width, height, m.processesTab.bubble.Metric(), m.processesTreemapOffset, m.isDark)
	case tabVizModeBubbles:
		return m.processesTab.bubble.Render("Processes", width, height)
	}
	if snap == nil {
		return renderWaitingForStats(TabProcesses)
	}
	return renderProcessesWithSort(snap, width, height, m.processesTab.offset, m.processesTab.col, m.pidFilter, m.processesTab.sort)
}

// captureSyscallsSelection is the Syscalls tab's CaptureSelection hook.
// Unsorted the table tracks the row position, so only a sorted table
// re-anchors by syscall name. The treemap reorders by metric value on every
// refresh, so its selection always follows the syscall name (see
// syscallsTreemapSelection). Either falls back to a clamp when its syscall
// is gone.
func captureSyscallsSelection(m *Model) func() {
	return captureSelections(
		m.syscallsTableSelection().capture(m.syscallsTab.sort.active),
		m.syscallsTreemapSelection().capture(true),
	)
}

// captureFilesSelection is the Files tab's CaptureSelection hook. The
// dir-grouped selection is anchored even while another tab is shown:
// skipping it would let the selection drift to a different item by the time
// the Files tab is shown again.
func captureFilesSelection(m *Model) func() {
	selectedFile := ""
	if !m.filesDirGrouped && m.filesTab.mode == tabVizModeTable && m.filesTab.sort.active {
		selectedFile = m.selectedFilePath()
		if selectedFile == "" {
			// Empty file list: follow the path remembered from before it emptied.
			selectedFile = m.filesTab.wanted.take(m.filesTab.offset)
		}
	}
	reanchorDir := m.filesDirSelection().capture(m.filesDirGrouped && m.filesDirAnchorsByKey())
	return func() {
		m.reanchorFilesOffset(selectedFile)
		reanchorDir()
	}
}

// captureProcessesSelection is the Processes tab's CaptureSelection hook,
// the Syscalls rule by PID: a sorted table (and bubbles mode, which shares
// the table offset) re-anchors by PID, an unsorted one keeps the position,
// and the treemap always follows the PID. Each has its own offset, so a
// PID without a treemap tile never moves the table selection.
func captureProcessesSelection(m *Model) func() {
	return captureSelections(
		m.processesTableSelection().capture(m.processesTab.sort.active),
		m.processesTreemapSelection().capture(true),
	)
}

// handleFilesKey is the Files tab's HandleKey hook: the directory-grouping
// toggle.
func handleFilesKey(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if !key.Matches(msg, m.keys.DirGroup) {
		return false, nil
	}
	return true, m.toggleFilesDirGrouping()
}

// tabScrollSyscalls handles navigation keys for the syscalls tab. When the
// treemap viz is active it uses offset-based navigation over the flattened
// treemap items; otherwise the generic table-tab navigation.
func tabScrollSyscalls(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	if m.syscallsTab.mode == tabVizModeTreemap {
		sel := m.syscallsTreemapSelection()
		return scrollOffset(keyStr, sel.offset, len(sel.keys())), nil
	}
	return m.syscallsTab.navigate(keyStr, m.syscallsRowCount(),
		len(syscallColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollFiles handles navigation keys for the files tab, selecting between
// the dir-grouped and plain navigation paths based on model state. Both are
// the generic table-tab navigation over the respective tableTabState.
func tabScrollFiles(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	if m.filesDirGrouped {
		return m.filesDirTab.navigate(keyStr, m.filesDirRowCountForMode(),
			len(fileDirColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
	}
	return m.filesTab.navigate(keyStr, m.filesPlainRowCount(),
		len(fileColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollProcesses handles navigation keys for the processes tab: the
// full table key set in every mode. In the treemap the row keys (j/k, g/G,
// pgup/pgdn) move the treemap's own selection, bounded by its tile count,
// while h/l still move the table column, which picks Enter's PID or Comm
// filter (selectedProcessFilter) there too.
func tabScrollProcesses(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	row, rows := &m.processesTab.offset, m.processesRowCount()
	if m.processesTab.mode == tabVizModeTreemap {
		sel := m.processesTreemapSelection()
		row, rows = sel.offset, len(sel.keys())
	}
	return m.processesTab.navigateRow(msg.String(), row, rows,
		len(processColumns()), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollStream handles navigation, filter, and editor-open keys for the
// stream tab. The stream model returns a command emitting typed messages for
// any filter or editor request: the global-filter messages go to the top-level
// model, messages.OpenEditorRequestedMsg comes back to Update here.
func tabScrollStream(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	m.syncStreamViewport()
	return m.streamModel.HandleTeaKey(msg)
}

// handleOpenEditorRequested opens an external editor for the requested path,
// recording any open error into the stream model's status message so the user
// sees feedback.
func (m *Model) handleOpenEditorRequested(msg messages.OpenEditorRequestedMsg) (tea.Model, tea.Cmd) {
	editorCmd, err := eventstream.EditorCommandForPath(msg.Path)
	if err != nil {
		m.streamModel.SetStatusMessage("Open failed: " + err.Error())
		return m, nil
	}
	return m, tea.ExecProcess(editorCmd, func(err error) tea.Msg {
		return streamEditorDoneMsg{err: err}
	})
}

// CancelOpenEditorRequest records on the stream status line that the editor
// request for msg.Path was not carried out, replacing the "Opening in editor"
// status the stream set when it emitted the request.
func (m *Model) CancelOpenEditorRequest(msg messages.OpenEditorRequestedMsg) {
	m.streamModel.SetStatusMessage("Open cancelled: " + msg.Path)
}
