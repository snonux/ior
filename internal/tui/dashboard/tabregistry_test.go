package dashboard

import (
	"slices"
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	flamegraphtui "ior/internal/tui/flamegraph"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

// allTabs lists every Tab constant. A constant added without a registry
// entry fails TestTabRegistryCoversEveryTab; a registry entry added without
// extending this list fails its length check.
var allTabs = []Tab{TabOverview, TabSyscalls, TabFiles, TabProcesses, TabLatency, TabStream, TabFlame}

func TestTabRegistryCoversEveryTab(t *testing.T) {
	if len(tabDescriptors) != len(allTabs) {
		t.Fatalf("registry has %d tabs, allTabs lists %d", len(tabDescriptors), len(allTabs))
	}
	positions := make(map[int]Tab, len(allTabs))
	for _, tab := range allTabs {
		d, ok := tabDescriptors[tab]
		if !ok {
			t.Fatalf("tab %d has no registry entry", tab)
		}
		if d.Name == "" || d.ShortName == "" {
			t.Errorf("tab %d: empty name %q / short name %q", tab, d.Name, d.ShortName)
		}
		if other, dup := positions[d.Position]; dup {
			t.Errorf("tabs %v and %v share position %d", other, tab, d.Position)
		}
		positions[d.Position] = tab
		if d.Render == nil {
			t.Errorf("%v: no Render hook; the tab would render %q", tab, "Unknown tab")
		}
		if d.ShortcutKey == nil {
			t.Errorf("%v: no numeric shortcut", tab)
		}
		if len(d.AllowedVizModes) == 0 || d.AllowedVizModes[0] != tabVizModeTable {
			t.Errorf("%v: AllowedVizModes %v must start with the table view", tab, d.AllowedVizModes)
		}
		// A tab with more than the table view must have somewhere to store
		// its mode, or cycling silently does nothing.
		if len(d.AllowedVizModes) > 1 && d.TableState == nil {
			t.Errorf("%v: allows %d viz modes but has no TableState", tab, len(d.AllowedVizModes))
		}
	}
}

// TestTableTabControllersAreComplete pins that every table tab wires the
// full set of table hooks, and that each maps to its own state component.
func TestTableTabControllersAreComplete(t *testing.T) {
	m := NewModel(nil, nil)
	states := map[tableTab]Tab{}
	for _, tab := range allTabs {
		d := tabDescriptors[tab]
		if d.TableState == nil {
			continue
		}
		state := d.TableState(m)
		if state == nil {
			t.Fatalf("%v: TableState returned nil", tab)
		}
		if other, dup := states[state]; dup {
			t.Errorf("%v and %v share one table state", other, tab)
		}
		states[state] = tab
		hooks := map[string]bool{
			"HandleScroll":     d.HandleScroll != nil,
			"HandleEnter":      d.HandleEnter != nil,
			"HandleSort":       d.HandleSort != nil,
			"RefreshBubble":    d.RefreshBubble != nil,
			"CaptureSelection": d.CaptureSelection != nil,
			"ClampColumns":     d.ClampColumns != nil,
		}
		for name, set := range hooks {
			if !set {
				t.Errorf("%v: table tab without %s hook", tab, name)
			}
		}
	}
	if want := []Tab{TabSyscalls, TabFiles, TabProcesses}; len(states) != len(want) {
		t.Fatalf("expected %d table tabs, got %v", len(want), states)
	}
}

// hookCounts records which registry hooks a dispatcher reached.
type hookCounts map[string]int

// registerTestTab installs d under a tab id no real tab uses for the
// duration of the test. Tests using it must not run in parallel: the
// registry is package state.
func registerTestTab(t *testing.T, d tabDescriptor) Tab {
	t.Helper()
	const testTab Tab = 100
	if _, taken := tabDescriptors[testTab]; taken {
		t.Fatalf("test tab id %d is already registered", testTab)
	}
	tabDescriptors[testTab] = d
	t.Cleanup(func() { delete(tabDescriptors, testTab) })
	return testTab
}

// hookSentinelMsg is what the test tab's HandleKey command yields, so a test
// can tell that the hook's command - not some other command - came back.
type hookSentinelMsg struct{}

func hookSentinelCmd() tea.Msg { return hookSentinelMsg{} }

// cmdYields reports whether running cmd produces want, looking inside
// tea.Batch results.
func cmdYields(cmd tea.Cmd, want tea.Msg) bool {
	if cmd == nil {
		return false
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, sub := range batch {
			if cmdYields(sub, want) {
				return true
			}
		}
		return false
	}
	return msg == want
}

// countingDescriptor returns a descriptor whose every hook counts its calls.
// Its table state is state, so viz-mode dispatch can be observed.
func countingDescriptor(calls hookCounts, state *tableTabState[syscallSortKey]) tabDescriptor {
	return tabDescriptor{
		Name:            "Test",
		ShortName:       "Tst",
		Position:        1000,
		AllowedVizModes: []tabVizMode{tabVizModeTable, tabVizModeBubbles},
		AltVizReady: func(*Model) bool {
			calls["AltVizReady"]++
			return true
		},
		TableState: func(*Model) tableTab {
			calls["TableState"]++
			return state
		},
		KeepSelection: func(_ *Model, change func()) {
			calls["KeepSelection"]++
			change()
		},
		ContentViewport: func(width, height int, _ bool) (int, int) {
			calls["ContentViewport"]++
			return width, height
		},
		InitCmd: func(*Model) tea.Cmd {
			calls["InitCmd"]++
			return nil
		},
		Render: func(*Model, *statsengine.Snapshot, *eventstream.Model, *flamegraphtui.Model, int, int) string {
			calls["Render"]++
			return "test tab body"
		},
		HandleScroll: func(_ *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
			calls["HandleScroll"]++
			return msg.String() == "down", nil
		},
		HandleEnter: func(*Model) (bool, tea.Cmd) {
			calls["HandleEnter"]++
			return true, nil
		},
		HandleSort: func(*Model, bool) (bool, tea.Cmd) {
			calls["HandleSort"]++
			return true, nil
		},
		HandleKey: func(_ *Model, msg tea.KeyPressMsg) (bool, tea.Cmd) {
			calls["HandleKey"]++
			if msg.String() != "x" {
				return false, nil
			}
			return true, hookSentinelCmd
		},
		BlocksGlobalShortcut: func(*Model, tea.KeyPressMsg) bool {
			calls["BlocksGlobalShortcut"]++
			return true
		},
		RefreshBubble: func(*Model) bool {
			calls["RefreshBubble"]++
			return false
		},
		CaptureSelection: func(m *Model) func() {
			calls["CaptureSelection"]++
			captured := m.latest
			return func() {
				calls["reanchor"]++
				if m.latest == captured {
					calls["reanchorBeforeSwap"]++
				}
			}
		},
		ClampColumns: func(*Model) {
			calls["ClampColumns"]++
		},
		ShortcutKey: func(common.KeyMap) key.Binding {
			return key.NewBinding(key.WithKeys("0"))
		},
	}
}

func TestTabControllerHooksAreInvoked(t *testing.T) {
	calls := hookCounts{}
	state := &tableTabState[syscallSortKey]{bubble: newBubbleChart()}
	tab := registerTestTab(t, countingDescriptor(calls, state))

	m := NewModel(nil, nil)
	m.width, m.height = 120, 40

	// The numeric shortcut reaches the tab and its InitCmd fires on entry.
	m.Update(runeKey('0'))
	if m.activeTab != tab {
		t.Fatalf("shortcut did not activate the test tab, active = %v", m.activeTab)
	}
	m.Init()

	if !strings.Contains(m.View().Content, "test tab body") {
		t.Fatal("View did not render through the Render hook")
	}
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m.Update(runeKey('s'))
	// A key the tab handles returns the hook's command, both from
	// handleShortcutKey and from Update.
	if handled, cmd := m.handleShortcutKey(runeKey('x')); !handled || !cmdYields(cmd, hookSentinelMsg{}) {
		t.Errorf("handleShortcutKey(x) = handled %v, want the HandleKey hook's command", handled)
	}
	if _, cmd := m.Update(runeKey('x')); !cmdYields(cmd, hookSentinelMsg{}) {
		t.Error("Update(x) dropped the HandleKey hook's command")
	}
	if m.activeTab != tab {
		t.Fatalf("a key the tab handles switched tabs to %v", m.activeTab)
	}
	if !m.BlocksGlobalShortcuts(runeKey('q')) {
		t.Error("BlocksGlobalShortcuts ignored the hook's verdict")
	}
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.Update(messages.StatsTickMsg{Snap: &snap})

	// Viz cycling goes through AllowedVizModes, TableState and KeepSelection.
	m.Update(runeKey('v'))
	if state.mode != tabVizModeBubbles {
		t.Errorf("viz cycling did not reach the tab's state, mode = %v", state.mode)
	}
	// With the bubble view active, scroll keys move the bubble selection
	// instead of reaching HandleScroll.
	scrolls := calls["HandleScroll"]
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	if calls["HandleScroll"] != scrolls {
		t.Error("HandleScroll reached while the bubble chart is the active view")
	}
	m.Update(runeKey('b'))
	if state.bubble.Metric() == bubbleMetricCount {
		t.Error("metric toggle did not reach the tab's bubble chart")
	}
	// A key the hook declines still reaches the numeric tab shortcuts.
	keyCalls := calls["HandleKey"]
	m.Update(runeKey('2'))
	if calls["HandleKey"] == keyCalls {
		t.Error("HandleKey was not consulted before the numeric shortcuts")
	}
	if m.activeTab != TabOverview {
		t.Errorf("unhandled key did not fall through to the numeric shortcut, active = %v", m.activeTab)
	}

	for _, hook := range []string{
		"InitCmd", "Render", "ContentViewport", "HandleScroll", "HandleEnter",
		"HandleSort", "HandleKey", "BlocksGlobalShortcut", "RefreshBubble",
		"CaptureSelection", "reanchor", "ClampColumns", "TableState",
		"KeepSelection", "AltVizReady",
	} {
		if calls[hook] == 0 {
			t.Errorf("hook %s was never invoked", hook)
		}
	}
	if calls["reanchorBeforeSwap"] != 0 {
		t.Error("CaptureSelection's reanchor ran before the new snapshot was installed")
	}
}

// assertInertTab checks that every tab-agnostic dispatcher treats tab as
// having no behaviour of its own: nothing handled, no state, table only.
func assertInertTab(t *testing.T, tab Tab) {
	t.Helper()
	m := NewModel(nil, nil)
	m.width, m.height = 120, 40
	m.activeTab = tab

	if got := renderActiveTabContent(m, tab, nil, &m.streamModel, m.flamegraphModel, 80, 20); !strings.Contains(got, "Unknown tab") {
		t.Errorf("render = %q, want the Unknown tab placeholder", got)
	}
	if handled, _ := m.handleScrollKey(tea.KeyPressMsg{Code: tea.KeyDown}); handled {
		t.Error("scroll handled")
	}
	if handled, _ := m.handleEnterKey(tea.KeyPressMsg{Code: tea.KeyEnter}); handled {
		t.Error("enter handled")
	}
	if handled, _ := m.handleSortKey(runeKey('s')); handled {
		t.Error("sort handled")
	}
	if handled, _ := m.handleShortcutKey(runeKey('d')); handled {
		t.Error("tab-local key handled")
	}
	if m.BlocksGlobalShortcuts(runeKey('q')) {
		t.Error("global shortcuts blocked")
	}
	if m.tableTabFor(tab) != nil || m.bubbleChartFor(tab) != nil {
		t.Error("tab resolved to table state")
	}
	if got := m.allowedVizModes(tab); !slices.Equal(got, []tabVizMode{tabVizModeTable}) {
		t.Errorf("allowed viz modes = %v, want table only", got)
	}
	if m.bubbleEnabledForTab(tab) {
		t.Error("bubble view enabled")
	}
	if cmd := m.cycleVisualizationMode(); cmd != nil {
		t.Error("viz cycling produced a command")
	}
	if cmd := m.toggleBubbleMetric(); cmd != nil {
		t.Error("metric toggle produced a command")
	}
	wantW, wantH := flameViewport(80, 20, m.showHelp)
	if gotW, gotH := m.contentViewport(tab, 80, 20); gotW != wantW || gotH != wantH {
		t.Errorf("viewport = %dx%d, want the standard %dx%d", gotW, gotH, wantW, wantH)
	}
	ran := false
	m.keepSelection(tab, func() { ran = true })
	if !ran {
		t.Error("keepSelection dropped the change")
	}
	// Snapshot and resize dispatch iterate every registered tab; neither
	// may trip over a tab without hooks.
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.Update(messages.StatsTickMsg{Snap: &snap})
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
}

func TestUnknownTabIsInert(t *testing.T) {
	const unknown Tab = 99
	if _, ok := tabDescriptors[unknown]; ok {
		t.Fatalf("tab id %d is registered", unknown)
	}
	if got := lookupTab(unknown).Name; got != "Unknown" {
		t.Fatalf("lookupTab fallback name = %q", got)
	}
	assertInertTab(t, unknown)
}

func TestRegisteredTabWithNilHooksIsInert(t *testing.T) {
	tab := registerTestTab(t, tabDescriptor{
		Name:            "Bare",
		ShortName:       "Bar",
		Position:        1000,
		AllowedVizModes: []tabVizMode{tabVizModeTable},
	})
	assertInertTab(t, tab)
}

// TestFilesAltVizRequiresDirGrouping pins the Files controller's AltVizReady
// gate: outside dir grouping the tab is table-only and ignores the metric
// key; inside it all four views cycle.
func TestFilesAltVizRequiresDirGrouping(t *testing.T) {
	m := NewModel(nil, nil)
	m.activeTab = TabFiles
	if got := m.allowedVizModes(TabFiles); !slices.Equal(got, []tabVizMode{tabVizModeTable}) {
		t.Fatalf("ungrouped Files allows %v, want table only", got)
	}
	if cmd := m.toggleBubbleMetric(); cmd != nil || m.filesTab.bubble.Metric() != bubbleMetricCount {
		t.Fatal("ungrouped Files accepted a metric change")
	}
	m.Update(runeKey('d'))
	if !m.filesDirGrouped {
		t.Fatal("dir-group key did not reach the Files HandleKey hook")
	}
	want := []tabVizMode{tabVizModeTable, tabVizModeBubbles, tabVizModeTreemap, tabVizModeIcicle}
	if got := m.allowedVizModes(TabFiles); !slices.Equal(got, want) {
		t.Fatalf("grouped Files allows %v, want %v", got, want)
	}
	m.filesTab.mode = tabVizModeBubbles
	if !m.bubbleEnabledForTab(TabFiles) {
		t.Fatal("grouped Files in bubbles mode should show the bubble chart")
	}
	// Ungrouping falls back to the table view.
	m.Update(runeKey('d'))
	if m.filesDirGrouped || m.filesTab.mode != tabVizModeTable || m.bubbleEnabledForTab(TabFiles) {
		t.Fatalf("ungrouping left grouped=%v mode=%v", m.filesDirGrouped, m.filesTab.mode)
	}
}

// TestDirGroupKeyIsFilesOnly pins that the dir-group key is a Files-local
// binding: on every other tab it is left unhandled.
func TestDirGroupKeyIsFilesOnly(t *testing.T) {
	for _, tab := range allTabs {
		if tab == TabFiles {
			continue
		}
		m := NewModel(nil, nil)
		m.activeTab = tab
		if handled, _ := m.handleShortcutKey(runeKey('d')); handled || m.filesDirGrouped {
			t.Errorf("%v: dir-group key handled=%v grouped=%v", tab, handled, m.filesDirGrouped)
		}
	}
}

// TestTableTabsRenderWaitingBeforeFirstSnapshot pins the table tabs' Render
// hooks' nil-snapshot state in table mode.
func TestTableTabsRenderWaitingBeforeFirstSnapshot(t *testing.T) {
	for _, tab := range []Tab{TabSyscalls, TabFiles, TabProcesses, TabOverview, TabLatency} {
		m := NewModel(nil, nil)
		m.activeTab = tab
		got := m.renderActiveContent(120, 30, &m.streamModel, m.flamegraphModel)
		if !strings.Contains(got, tab.String()+": waiting for stats...") {
			t.Errorf("%v: render = %q, want the waiting placeholder", tab, got)
		}
	}
}

// TestUnhandledTabKeyFallsThroughToNumericShortcuts pins that a real tab's
// HandleKey hook (the Files dir-group toggle) declining a key leaves it to
// the numeric tab shortcuts.
func TestUnhandledTabKeyFallsThroughToNumericShortcuts(t *testing.T) {
	m := NewModel(nil, nil)
	m.activeTab = TabFiles
	m.Update(runeKey('3'))
	if m.activeTab != TabSyscalls {
		t.Fatalf("active tab = %v, want %v", m.activeTab, TabSyscalls)
	}
	if m.filesDirGrouped {
		t.Fatal("the numeric shortcut toggled Files dir grouping")
	}
}

// TestStreamContentViewportHook pins that the Stream tab uses the standard
// content viewport, which follows the help bar: that is exactly the body View
// gives the tab, so the stream's key handling (page step, scroll clamp) and
// its rendering agree on the rows, and the stream fits its own footer lines
// into them (eventstream.Model.View). A stream-specific viewport that also
// deducted the footer rows left them unused twice over (task dz2) and handed
// the stream fewer rows than it was drawn into (task ls2).
func TestStreamContentViewportHook(t *testing.T) {
	const width, height = 120, 40
	for _, showHelp := range []bool{false, true} {
		m := NewModel(nil, nil)
		m.showHelp = showHelp
		m.Update(tea.WindowSizeMsg{Width: width, Height: height})
		m.activeTab = TabStream

		wantW, wantH := flameViewport(width, height, showHelp)
		gotW, gotH := m.contentViewport(TabStream, width, height)
		if gotW != wantW || gotH != wantH {
			t.Errorf("showHelp=%v: stream viewport = %dx%d, want the standard %dx%d", showHelp, gotW, gotH, wantW, wantH)
		}
	}
}

// TestContentViewportSizesDependentState pins that the state sized to a
// tab's rendered content - its bubble chart and the table page step - is
// sized through the tab's ContentViewport hook, not a hard-coded viewport.
func TestContentViewportSizesDependentState(t *testing.T) {
	state := &tableTabState[syscallSortKey]{bubble: newBubbleChart()}
	tab := registerTestTab(t, tabDescriptor{
		Name:            "Viewport",
		ShortName:       "Vpt",
		Position:        1000,
		AllowedVizModes: []tabVizMode{tabVizModeTable, tabVizModeBubbles},
		TableState:      func(*Model) tableTab { return state },
		ContentViewport: func(width, height int, _ bool) (int, int) { return width - 7, height - 9 },
	})

	m := NewModel(nil, nil)
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if state.bubble.width != 113 || state.bubble.height != 31 {
		t.Errorf("resize: bubble viewport = %dx%d, want the hook's 113x31", state.bubble.width, state.bubble.height)
	}
	// The real table tabs keep the standard viewport.
	wantW, wantH := flameViewport(120, 40, m.showHelp)
	if b := m.syscallsTab.bubble; b.width != wantW || b.height != wantH {
		t.Errorf("syscalls bubble viewport = %dx%d, want %dx%d", b.width, b.height, wantW, wantH)
	}

	m.width, m.height = 100, 30
	m.refreshBubbleData()
	if state.bubble.width != 93 || state.bubble.height != 21 {
		t.Errorf("refresh: bubble viewport = %dx%d, want the hook's 93x21", state.bubble.width, state.bubble.height)
	}

	m.activeTab = tab
	if got := m.activeTableHeight(); got != 21 {
		t.Errorf("activeTableHeight = %d, want the hook's 21", got)
	}
}

// TestFilesIcicleSelectionUsesFilesContentViewport pins that the icicle's
// selection keys are laid out in the Files tab's content viewport - the size
// View() renders the icicle in - so a Files ContentViewport hook moves both.
func TestFilesIcicleSelectionUsesFilesContentViewport(t *testing.T) {
	m := newFilesVizModel(t, tabVizModeIcicle, deepIcicleSnapshot())
	metric := m.filesTab.bubble.Metric()
	stdW, stdH := flameViewport(m.width, m.height, m.showHelp)
	if got, want := m.filesDirSelectionKeys(), filesIcicleTileKeys(m.latest, stdW, stdH, metric); !slices.Equal(got, want) {
		t.Fatalf("standard viewport keys = %v, want %v", got, want)
	}

	orig := tabDescriptors[TabFiles]
	t.Cleanup(func() { tabDescriptors[TabFiles] = orig })
	d := orig
	d.ContentViewport = func(width, _ int, _ bool) (int, int) { return width, 6 }
	tabDescriptors[TabFiles] = d

	got := m.filesDirSelectionKeys()
	want := filesIcicleTileKeys(m.latest, m.width, 6, metric)
	if !slices.Equal(got, want) {
		t.Fatalf("hooked viewport keys = %v, want %v", got, want)
	}
	if slices.Equal(got, filesIcicleTileKeys(m.latest, stdW, stdH, metric)) {
		t.Fatal("test snapshot does not tell the two viewports apart")
	}
}

// TestKeepAllSelectionsRunsEveryTabHook pins the global-layout-change
// helper: every registered KeepSelection hook wraps the change, nested in
// tab order, the change runs once, and resize and the help toggle go
// through it whichever tab is active.
func TestKeepAllSelectionsRunsEveryTabHook(t *testing.T) {
	var trace []string
	register := func(id Tab, name string, position int) {
		if _, taken := tabDescriptors[id]; taken {
			t.Fatalf("test tab id %d is already registered", id)
		}
		tabDescriptors[id] = tabDescriptor{
			Name:            name,
			ShortName:       name,
			Position:        position,
			AllowedVizModes: []tabVizMode{tabVizModeTable},
			KeepSelection: func(_ *Model, change func()) {
				trace = append(trace, name+" before")
				change()
				trace = append(trace, name+" after")
			},
		}
		t.Cleanup(func() { delete(tabDescriptors, id) })
	}
	// Registered out of position order: the nesting follows Position.
	register(101, "second", 1001)
	register(100, "first", 1000)

	m := NewModel(nil, nil)
	m.keepAllSelections(func() { trace = append(trace, "change") })
	want := []string{"first before", "second before", "change", "second after", "first after"}
	if !slices.Equal(trace, want) {
		t.Fatalf("trace = %v, want %v", trace, want)
	}

	m.activeTab = TabOverview
	trace = nil
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	if !slices.Contains(trace, "first before") || !slices.Contains(trace, "second before") {
		t.Errorf("resize skipped a background tab's KeepSelection hook: %v", trace)
	}
	trace = nil
	m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
	if !slices.Contains(trace, "first before") || !slices.Contains(trace, "second before") {
		t.Errorf("help toggle skipped a background tab's KeepSelection hook: %v", trace)
	}
}
