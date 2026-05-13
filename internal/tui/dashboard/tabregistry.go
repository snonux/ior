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

// tabDescriptor captures all per-tab metadata and behaviour so that adding a
// new tab only requires registering a new entry — no switch statements need to
// be modified.
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
	AllowedVizModes []tabVizMode
	// InitCmd is an optional extra Bubble Tea command to start alongside the
	// global refresh tick when this tab is the active tab on Init. Tabs that
	// need their own high-frequency tick (stream, flame) set this; others leave
	// it nil.
	InitCmd func() tea.Cmd
	// Render draws the tab body. Nil means the tab has no registered renderer
	// (used for tabs that handle rendering via other paths).
	Render tabRenderFn
	// HandleScroll handles direction keys for this tab when bubbles are off.
	// Nil means the tab does not process scroll/navigation keys.
	HandleScroll tabScrollFn
	// ShortcutKey extracts the numeric shortcut key binding for this tab from
	// a KeyMap. It is called at runtime against the model's configured key map
	// so that custom key maps (e.g. in tests) are respected. Nil means the tab
	// has no direct numeric shortcut; it is still reachable via tab/shift+tab.
	ShortcutKey func(keys common.KeyMap) key.Binding
}

// tabDescriptors is the central registry mapping every known Tab to its
// descriptor. Registering a new tab here is all that is required to make it
// participate in the tab bar, keyboard navigation, and rendering dispatch.
var tabDescriptors = map[Tab]tabDescriptor{
	TabFlame: {
		Name:            "Flame",
		ShortName:       "Flm",
		Position:        10,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
		InitCmd:         flameTickCmd,
		Render:          tabRenderFlame,
		HandleScroll:    nil,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.One },
	},
	TabOverview: {
		Name:            "Overview",
		ShortName:       "Ovr",
		Position:        20,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
		Render:          tabRenderOverview,
		HandleScroll:    nil,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Two },
	},
	TabSyscalls: {
		Name:            "Syscalls",
		ShortName:       "Sys",
		Position:        30,
		AllowedVizModes: []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap},
		Render:          tabRenderSyscalls,
		HandleScroll:    tabScrollSyscalls,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Three },
	},
	TabFiles: {
		Name:            "Files",
		ShortName:       "Fil",
		Position:        40,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
		Render:          tabRenderFiles,
		HandleScroll:    tabScrollFiles,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Four },
	},
	TabProcesses: {
		Name:            "Processes",
		ShortName:       "Pro",
		Position:        50,
		AllowedVizModes: []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap},
		Render:          tabRenderProcesses,
		HandleScroll:    tabScrollProcesses,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Five },
	},
	TabLatency: {
		Name:            "Latency+Gaps",
		ShortName:       "Lat",
		Position:        60,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
		Render:          tabRenderLatency,
		HandleScroll:    nil,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Six },
	},
	TabStream: {
		Name:            "Stream",
		ShortName:       "Str",
		Position:        70,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
		InitCmd:         streamTickCmd,
		Render:          tabRenderStream,
		HandleScroll:    tabScrollStream,
		ShortcutKey:     func(k common.KeyMap) key.Binding { return k.Seven },
	},
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

// tabAllowedVizModes returns the visualisation modes allowed for tab,
// respecting any runtime conditions (e.g. Files requires dir-grouped mode for
// non-table views). This replaces the former allowedVizModes switch statement.
func tabAllowedVizModes(tab Tab, filesDirGrouped bool) []tabVizMode {
	if tab == TabFiles && filesDirGrouped {
		return []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap, tabVizModeIcicle}
	}
	return lookupTab(tab).AllowedVizModes
}

// tabRenderFlame adapts the flame model's View to the tabRenderFn signature.
func tabRenderFlame(_ *Model, _ *statsengine.Snapshot, _ *eventstream.Model, flame *flamegraphtui.Model, _, _ int) string {
	if flame == nil {
		return common.PanelStyle.Render("Flame: waiting for model...")
	}
	return flame.View().Content
}

// tabRenderOverview adapts renderOverview to the tabRenderFn signature.
func tabRenderOverview(_ *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderOverview(snap, width, height)
}

// tabRenderSyscalls adapts renderSyscalls to the tabRenderFn signature.
// Sort-state rendering is handled by renderActiveContentTable before this path.
func tabRenderSyscalls(_ *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderSyscalls(snap, width, height)
}

// tabRenderFiles adapts renderFiles to the tabRenderFn signature, choosing
// between the dir-grouped and plain view based on model state.
// Sort-state rendering is handled by renderActiveContentTable before this path.
func tabRenderFiles(m *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	if m.filesDirGrouped {
		return renderFilesDirGrouped(snap, width, height, m.filesDirOffset, m.filesDirCol)
	}
	return renderFilesWithOffset(snap, width, height, m.filesOffset, m.filesCol)
}

// tabRenderProcesses adapts renderProcessesWithOffset to the tabRenderFn signature.
func tabRenderProcesses(m *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderProcessesWithOffset(snap, width, height, m.processesOffset, m.processesCol, m.pidFilter)
}

// tabRenderLatency adapts renderLatencyGapsTab to the tabRenderFn signature.
func tabRenderLatency(_ *Model, snap *statsengine.Snapshot, _ *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	return renderLatencyGapsTab(snap, width, height)
}

// tabRenderStream adapts the stream model's View to the tabRenderFn signature.
func tabRenderStream(_ *Model, _ *statsengine.Snapshot, stream *eventstream.Model, _ *flamegraphtui.Model, width, height int) string {
	if stream == nil {
		return common.PanelStyle.Render("Stream: waiting for source...")
	}
	return stream.View(width, height)
}

// tabScrollSyscalls handles navigation keys for the syscalls tab. When the
// treemap viz is active it uses offset-based navigation; otherwise table nav.
func tabScrollSyscalls(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	if m.syscallsVizMode == tabVizModeTreemap {
		return scrollOffset(keyStr, &m.syscallsTreemapSelection, m.maxSyscallsRows()), nil
	}
	return common.HandleTableNavigationKey(keyStr, &m.syscallsOffset, &m.syscallsCol,
		m.maxSyscallsRows(), len(syscallColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollFiles handles navigation keys for the files tab, selecting between
// the dir-grouped and plain navigation paths based on model state.
func tabScrollFiles(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	if m.filesDirGrouped {
		return common.HandleTableNavigationKey(keyStr, &m.filesDirOffset, &m.filesDirCol,
			m.maxFilesDirRowsForMode(), len(fileDirColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
	}
	return common.HandleTableNavigationKey(keyStr, &m.filesOffset, &m.filesCol,
		m.maxFilesRows(), len(fileColumns(m.width)), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollProcesses handles navigation keys for the processes tab.
func tabScrollProcesses(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
	keyStr := msg.String()
	return common.HandleTableNavigationKey(keyStr, &m.processesOffset, &m.processesCol,
		m.maxProcessesRows(), len(processColumns()), tablePageStep(m.activeTableHeight())), nil
}

// tabScrollStream handles navigation, filter, and editor-open keys for the
// stream tab. It delegates to streamModel and then emits the appropriate
// Bubble Tea messages for any filter or editor requests.
func tabScrollStream(m *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
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
		return openStreamEditor(m, path)
	}
	return handled, nil
}

// openStreamEditor opens an external editor for the given path, recording any
// open error into the stream model's status message so the user sees feedback.
func openStreamEditor(m *Model, path string) (bool, tea.Cmd) {
	editorCmd, err := eventstream.EditorCommandForPath(path)
	if err != nil {
		m.streamModel.SetStatusMessage("Open failed: " + err.Error())
		return true, nil
	}
	return true, tea.ExecProcess(editorCmd, func(err error) tea.Msg {
		return streamEditorDoneMsg{err: err}
	})
}
