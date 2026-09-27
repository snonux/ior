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
			return msg.String() == "x", nil
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
	m.Update(runeKey('x'))
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
