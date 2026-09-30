package dashboard

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// These tests cover the Syscalls and Processes treemap selections across
// stats ticks, stats resets, global filter changes and metric / viz-mode
// changes (task cc). The treemaps order
// their items by metric value, so every refresh can reorder them: the
// selection must follow the selected syscall name / PID, as the Files tab's
// dir-grouped selection does (filesselection_test.go), instead of staying on
// whatever item moved into its slot.

func syscallsSnapshot(rows ...statsengine.SyscallSnapshot) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, rows, nil, nil,
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return &snap
}

func processesSnapshot(rows ...statsengine.ProcessSnapshot) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, rows,
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return &snap
}

// newVizModel returns a focused, sized dashboard on tab in mode with snap
// delivered through a real stats tick.
func newVizModel(t *testing.T, tab Tab, mode tabVizMode, snap *statsengine.Snapshot) *Model {
	t.Helper()
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = tab
	m.setTabVizMode(tab, mode)
	m.width = 120
	m.height = 28
	return tickStats(t, m, messages.StatsTickMsg{Snap: snap})
}

// sysRanking yields read, write and close with the given event counts.
func sysRanking(read, write, closeCount uint64) *statsengine.Snapshot {
	return syscallsSnapshot(
		statsengine.SyscallSnapshot{Name: "read", Count: read, Bytes: 10},
		statsengine.SyscallSnapshot{Name: "write", Count: write, Bytes: 1000},
		statsengine.SyscallSnapshot{Name: "close", Count: closeCount},
	)
}

// procRanking yields PIDs 100, 200 and 300 with the given syscall counts.
func procRanking(p100, p200, p300 uint64) *statsengine.Snapshot {
	return processesSnapshot(
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: p100, Bytes: 10},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: p200, Bytes: 1000},
		statsengine.ProcessSnapshot{PID: 300, Comm: "gamma", Syscalls: p300},
	)
}

func assertSyscallsTreemapSelection(t *testing.T, m *Model, wantAt int, want string) {
	t.Helper()
	if got := m.syscallsTreemapSelection().selectedKey(); m.syscallsTreemapOffset != wantAt || got != want {
		t.Fatalf("selected %q at %d, want %q at %d", got, m.syscallsTreemapOffset, want, wantAt)
	}
}

// assertProcessesTreemapSelection checks the treemap offset and PID and,
// in treemap mode, that Enter's row (selectedProcessSnapshot) is the same
// process.
func assertProcessesTreemapSelection(t *testing.T, m *Model, wantAt int, wantPID uint32) {
	t.Helper()
	assertProcessSelection(t, m, "treemap", m.processesTreemapSelection(), tabVizModeTreemap, wantAt, wantPID)
}

// assertProcessesTableSelection is assertProcessesTreemapSelection for the
// table selection (shared by the table and bubbles modes).
func assertProcessesTableSelection(t *testing.T, m *Model, wantAt int, wantPID uint32) {
	t.Helper()
	assertProcessSelection(t, m, "table", m.processesTableSelection(), tabVizModeTable, wantAt, wantPID)
}

func assertProcessSelection(t *testing.T, m *Model, name string, sel keyedSelection, mode tabVizMode, wantAt int, wantPID uint32) {
	t.Helper()
	if got := sel.selectedKey(); *sel.offset != wantAt || got != processKey(wantPID, 0) {
		t.Fatalf("%s: selected PID %q at %d, want %d at %d", name, got, *sel.offset, wantPID, wantAt)
	}
	if m.processesTab.mode != mode {
		return
	}
	if row, ok := m.selectedProcessSnapshot(); !ok || row.PID != wantPID {
		t.Fatalf("%s: Enter targets PID %d (ok=%v), want %d", name, row.PID, ok, wantPID)
	}
}

// assertRenderedSelection checks the treemap status line, i.e. that the
// highlighted tile is the selected item.
func assertRenderedSelection(t *testing.T, m *Model, want string) {
	t.Helper()
	if view := stripANSIEscape(m.View().Content); !strings.Contains(view, want) {
		t.Fatalf("expected rendered %q, got:\n%s", want, view)
	}
}

func TestSyscallsTreemapSelectionFollowsNameAcrossStatsTick(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 2)
	assertSyscallsTreemapSelection(t, m, 2, "close")

	// close outgrows read and write, so it now leads the treemap. Two
	// ticks: the selection must hold, not drift tick by tick.
	for range 2 {
		m = tickStats(t, m, messages.StatsTickMsg{Snap: sysRanking(9, 5, 30)})
		assertSyscallsTreemapSelection(t, m, 0, "close")
	}
	assertRenderedSelection(t, m, "sel:1/3 close")
}

func TestSyscallsTreemapSelectionAnchoredWhileTabHidden(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 2)
	m.activeTab = TabOverview

	m = tickStats(t, m, messages.StatsTickMsg{Snap: sysRanking(9, 5, 30)})
	m.activeTab = TabSyscalls
	assertSyscallsTreemapSelection(t, m, 0, "close")
}

func TestSyscallsTreemapSelectionFallsBackWhenSyscallDisappears(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	// close is gone (and one of the survivors has no events, so the
	// treemap drops it too): the offset is clamped to the last surviving
	// tile instead of indexing past the end.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot(
		statsengine.SyscallSnapshot{Name: "read", Count: 9},
		statsengine.SyscallSnapshot{Name: "write", Count: 5},
		statsengine.SyscallSnapshot{Name: "idle"},
	)})
	assertSyscallsTreemapSelection(t, m, 1, "write")
	assertRenderedSelection(t, m, "sel:2/2 write")
}

func TestSyscallsTreemapSelectionResetsOnEmptySnapshot(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	assertSyscallsTreemapSelection(t, m, 0, "")
	assertRenderedSelection(t, m, "treemap: no data")

	m = tickStats(t, m, messages.StatsTickMsg{Snap: sysRanking(9, 5, 1)})
	assertSyscallsTreemapSelection(t, m, 0, "read")
}

func TestSyscallsTreemapSelectionSurvivesMetricToggle(t *testing.T) {
	// read leads by events, write by bytes, so b swaps their order.
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	m = pressJ(t, m, 1)
	assertSyscallsTreemapSelection(t, m, 1, "write")

	m = pressKey(m, 'b')
	if m.syscallsTab.bubble.Metric() != bubbleMetricBytes {
		t.Fatalf("expected b to switch to the bytes metric")
	}
	assertSyscallsTreemapSelection(t, m, 0, "write")
}

func TestSyscallsTreemapNavigationBoundedByTreemapItems(t *testing.T) {
	// idle has no events, so the treemap drops it: two tiles, three rows.
	m := newVizModel(t, TabSyscalls, tabVizModeTreemap, syscallsSnapshot(
		statsengine.SyscallSnapshot{Name: "read", Count: 9},
		statsengine.SyscallSnapshot{Name: "write", Count: 5},
		statsengine.SyscallSnapshot{Name: "idle"},
	))
	m = pressJ(t, m, 5)
	assertSyscallsTreemapSelection(t, m, 1, "write")
}

func TestProcessesTreemapSelectionFollowsPIDAcrossStatsTick(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)
	assertProcessesTreemapSelection(t, m, 2, 300)

	for range 2 {
		m = tickStats(t, m, messages.StatsTickMsg{Snap: procRanking(9, 5, 30)})
		assertProcessesTreemapSelection(t, m, 0, 300)
	}
	assertRenderedSelection(t, m, "sel:1/3 300:gamma")
}

func TestProcessesTreemapSelectionAnchoredWhileTabHidden(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)
	m.activeTab = TabOverview

	m = tickStats(t, m, messages.StatsTickMsg{Snap: procRanking(9, 5, 30)})
	m.activeTab = TabProcesses
	assertProcessesTreemapSelection(t, m, 0, 300)
}

func TestProcessesTreemapSelectionFallsBackWhenPIDDisappears(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	// PID 300 exited: the offset is clamped to the last surviving tile.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: 9},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: 5},
	)})
	assertProcessesTreemapSelection(t, m, 1, 200)
	assertRenderedSelection(t, m, "sel:2/2 200:beta")
}

func TestProcessesTreemapSelectionResetsOnEmptySnapshot(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	if key := m.processesTreemapSelection().selectedKey(); m.processesTreemapOffset != 0 || key != "" {
		t.Fatalf("expected no selection at 0, got %q at %d", key, m.processesTreemapOffset)
	}
	if _, ok := m.selectedProcessSnapshot(); ok {
		t.Fatalf("expected no Enter target on an empty snapshot")
	}
	assertRenderedSelection(t, m, "treemap: no data")

	m = tickStats(t, m, messages.StatsTickMsg{Snap: procRanking(9, 5, 1)})
	assertProcessesTreemapSelection(t, m, 0, 100)
}

func TestProcessesTreemapSelectionKeptOnFailedStatsTick(t *testing.T) {
	good := procRanking(9, 5, 1)
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, good)
	m = pressJ(t, m, 2)

	m = tickStats(t, m, messages.StatsTickMsg{Err: errors.New("snapshot build failed")})
	if m.latest != good {
		t.Fatalf("expected last good snapshot kept on failed tick")
	}
	assertProcessesTreemapSelection(t, m, 2, 300)
}

func TestProcessesTreemapNavigationAndEnterBoundedByTreemapItems(t *testing.T) {
	// PID 400 has no syscalls, so the treemap drops it: Enter must never
	// target a process the treemap does not show.
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, processesSnapshot(
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: 9},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: 5},
		statsengine.ProcessSnapshot{PID: 400, Comm: "idle"},
	))
	m = pressJ(t, m, 5)
	assertProcessesTreemapSelection(t, m, 1, 200)
}

func TestProcessesTreemapSelectionSurvivesMetricToggle(t *testing.T) {
	// 100 leads by syscalls, 200 by bytes, so b swaps their order.
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 1)
	assertProcessesTreemapSelection(t, m, 1, 200)

	m = pressKey(m, 'b')
	if m.processesTab.bubble.Metric() != bubbleMetricBytes {
		t.Fatalf("expected b to switch to the bytes metric")
	}
	assertProcessesTreemapSelection(t, m, 0, 200)
}

// manyProcesses yields n processes, PID i+1 with n-i syscalls, so the
// unsorted table lists them by PID and only PIDs 1-20 get a treemap tile.
func manyProcesses(n int) *statsengine.Snapshot {
	rows := make([]statsengine.ProcessSnapshot, 0, n)
	for i := range n {
		rows = append(rows, statsengine.ProcessSnapshot{PID: uint32(i + 1), Comm: "p", Syscalls: uint64(n - i)})
	}
	return processesSnapshot(rows...)
}

func TestProcessesModeCycleKeepsTableSelection(t *testing.T) {
	tests := []struct {
		name    string
		snap    *statsengine.Snapshot
		sort    tableSortState[processSortKey]
		presses int
		wantAt  int
		wantPID uint32
	}{
		// The review repro: PID 26 is outside the treemap's top 20, so a
		// shared offset got clamped to the last tile (PID 20).
		{name: "unsorted, PID outside the top tiles", snap: manyProcesses(30), presses: 25, wantAt: 25, wantPID: 26},
		// PID 300 has no syscalls: it is listed but has no tile.
		{name: "unsorted, PID with a zero metric value", snap: procRanking(9, 5, 0), presses: 2, wantAt: 2, wantPID: 300},
		{
			name:    "sorted by PID descending",
			snap:    procRanking(9, 5, 1),
			sort:    tableSortState[processSortKey]{active: true, key: processSortKeyPID, reverse: true},
			presses: 2, wantAt: 2, wantPID: 100,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newVizModel(t, TabProcesses, tabVizModeTable, tt.snap)
			m.processesTab.sort = tt.sort
			m = pressJ(t, m, tt.presses)
			assertProcessesTableSelection(t, m, tt.wantAt, tt.wantPID)

			// table -> bubbles -> treemap -> table: each mode keeps its
			// own selection, so the table's comes back untouched.
			for _, mode := range []tabVizMode{tabVizModeBubbles, tabVizModeTreemap, tabVizModeTable} {
				m = pressKey(m, 'v')
				if m.processesTab.mode != mode {
					t.Fatalf("expected mode %d after v, got %d", mode, m.processesTab.mode)
				}
				assertProcessesTableSelection(t, m, tt.wantAt, tt.wantPID)
			}
		})
	}
}

func TestProcessesTreemapSelectionIndependentOfTable(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 1)
	assertProcessesTreemapSelection(t, m, 1, 200)

	m = pressKey(m, 'v') // treemap -> table
	m = pressJ(t, m, 2)
	assertProcessesTableSelection(t, m, 2, 300)
	m = pressKey(m, 'v') // table -> bubbles
	m = pressKey(m, 'v') // bubbles -> treemap
	assertProcessesTreemapSelection(t, m, 1, 200)
}

func TestProcessesTableSelectionPolicyOnStatsTick(t *testing.T) {
	initial := procRanking(9, 5, 1)
	// PID 50 now leads the default (syscalls) order.
	refresh := processesSnapshot(
		statsengine.ProcessSnapshot{PID: 50, Comm: "new", Syscalls: 20},
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: 9},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: 5},
		statsengine.ProcessSnapshot{PID: 300, Comm: "gamma", Syscalls: 1},
	)
	bySyscalls := tableSortState[processSortKey]{active: true, key: processSortKeySyscalls}
	tests := []struct {
		name    string
		mode    tabVizMode
		sort    tableSortState[processSortKey]
		wantAt  int
		wantPID uint32
	}{
		// Unsorted, the table keeps its positional selection.
		{name: "table default order is positional", mode: tabVizModeTable, wantAt: 1, wantPID: 100},
		// Sorted, the selected PID 200 is followed to its new row.
		{name: "table sorted follows PID", mode: tabVizModeTable, sort: bySyscalls, wantAt: 2, wantPID: 200},
		// Bubbles mode shares the table offset and its rule.
		{name: "bubbles default order is positional", mode: tabVizModeBubbles, wantAt: 1, wantPID: 100},
		{name: "bubbles sorted follows PID", mode: tabVizModeBubbles, sort: bySyscalls, wantAt: 2, wantPID: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newVizModel(t, TabProcesses, tabVizModeTable, initial)
			m.processesTab.sort = tt.sort
			m = pressJ(t, m, 1)
			m.setTabVizMode(TabProcesses, tt.mode)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: refresh})
			m.setTabVizMode(TabProcesses, tabVizModeTable)
			assertProcessesTableSelection(t, m, tt.wantAt, tt.wantPID)
		})
	}
}

// TestTreemapSelectionsAcrossResetStats: the post-reset snapshot is applied
// through the normal stats tick, so both treemaps follow their item into it,
// and a tick built before the reset is dropped without moving them.
func TestTreemapSelectionsAcrossResetStats(t *testing.T) {
	src := &fakeSnapshotSource{snap: syscallsAndProcesses(sysRanking(9, 5, 1), procRanking(9, 5, 1))}
	m := NewModelWithConfig(src, nil, 250, 200, common.DefaultKeyMap())
	m.width, m.height = 120, 28
	m.setTabVizMode(TabSyscalls, tabVizModeTreemap)
	m.setTabVizMode(TabProcesses, tabVizModeTreemap)
	stale := m.statsTick()
	m = tickStats(t, m, stale)

	m.activeTab = TabSyscalls
	m = pressJ(t, m, 2)
	m.activeTab = TabProcesses
	m = pressJ(t, m, 2)
	assertSyscallsTreemapSelection(t, m, 2, "close")
	assertProcessesTreemapSelection(t, m, 2, 300)

	// After the reset close and PID 300 lead their treemaps.
	src.resetSnap = syscallsAndProcesses(sysRanking(9, 5, 30), procRanking(9, 5, 30))
	m.ResetStats()
	if m.latest != src.resetSnap {
		t.Fatalf("precondition: expected the post-reset snapshot on screen")
	}
	assertSyscallsTreemapSelection(t, m, 0, "close")
	assertProcessesTreemapSelection(t, m, 0, 300)

	m = tickStats(t, m, stale)
	if m.latest != src.resetSnap {
		t.Fatalf("a tick built before the reset was applied")
	}
	assertSyscallsTreemapSelection(t, m, 0, "close")
	assertProcessesTreemapSelection(t, m, 0, 300)
}

// syscallsAndProcesses merges the syscall rows of sys and the process rows
// of procs into one snapshot.
func syscallsAndProcesses(sys, procs *statsengine.Snapshot) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, sys.Syscalls(), nil, procs.Processes(),
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return &snap
}

func TestSyscallsSelectionsSurviveGlobalFilterChange(t *testing.T) {
	// The filter keeps the syscalls ending in "e": read is dropped, which
	// shifts write from row / tile 1 to 0.
	filter := globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "e$"}}
	t.Run("treemap", func(t *testing.T) {
		m := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
		m = pressJ(t, m, 1)
		assertSyscallsTreemapSelection(t, m, 1, "write")

		m.SetGlobalFilter(filter)
		assertSyscallsTreemapSelection(t, m, 0, "write")
		assertRenderedSelection(t, m, "sel:1/2 write")
	})
	t.Run("table", func(t *testing.T) {
		m := newVizModel(t, TabSyscalls, tabVizModeTable, sysRanking(9, 5, 1))
		m = pressJ(t, m, 1)
		if row, _ := m.selectedSyscallSnapshot(); row.Name != "write" {
			t.Fatalf("precondition: selected %q, want write", row.Name)
		}

		m.SetGlobalFilter(filter)
		if row, _ := m.selectedSyscallSnapshot(); m.syscallsTab.offset != 0 || row.Name != "write" {
			t.Fatalf("selected %q at %d, want write at 0", row.Name, m.syscallsTab.offset)
		}
	})
}

// manySyscalls yields n syscalls, sys0 with n events down to one, so the
// table and the treemap both list them in index order.
func manySyscalls(n int) *statsengine.Snapshot {
	rows := make([]statsengine.SyscallSnapshot, 0, n)
	for i := range n {
		rows = append(rows, statsengine.SyscallSnapshot{Name: fmt.Sprintf("sys%d", i), Count: uint64(n - i)})
	}
	return syscallsSnapshot(rows...)
}

// TestSelectionsSurviveTraceRestart: PrepareForTraceRestart drops the
// snapshot, then handleTracingStarted swaps the filter and resizes before
// the new session's first tick. Without a snapshot the keep hooks have no
// keys to follow, so they must leave every offset alone (not reset it to
// 0); the first tick then keeps it, clamped to the new rows as before.
func TestSelectionsSurviveTraceRestart(t *testing.T) {
	tests := []struct {
		name   string
		tab    Tab
		mode   tabVizMode
		snap   func(n int) *statsengine.Snapshot
		offset func(m *Model) int
	}{
		{"syscalls table", TabSyscalls, tabVizModeTable, manySyscalls, func(m *Model) int { return m.syscallsTab.offset }},
		{"syscalls treemap", TabSyscalls, tabVizModeTreemap, manySyscalls, func(m *Model) int { return m.syscallsTreemapOffset }},
		{"processes table", TabProcesses, tabVizModeTable, manyProcesses, func(m *Model) int { return m.processesTab.offset }},
		{"processes treemap", TabProcesses, tabVizModeTreemap, manyProcesses, func(m *Model) int { return m.processesTreemapOffset }},
	}
	for _, tt := range tests {
		for _, restart := range []struct {
			name   string
			rows   int
			wantAt int
		}{
			{"preserved", 5, 3},
			{"clamped", 2, 1},
		} {
			t.Run(tt.name+" "+restart.name, func(t *testing.T) {
				m := newVizModel(t, tt.tab, tt.mode, tt.snap(5))
				m = pressJ(t, m, 3)
				if got := tt.offset(m); got != 3 {
					t.Fatalf("precondition: offset %d, want 3", got)
				}

				m.PrepareForTraceRestart()
				m.SetGlobalFilter(globalfilter.Filter{})
				next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 28})
				m = next.(*Model)
				if got := tt.offset(m); got != 3 {
					t.Fatalf("restart without a snapshot moved the offset to %d, want 3", got)
				}

				m = tickStats(t, m, messages.StatsTickMsg{Snap: tt.snap(restart.rows), Generation: m.statsGen})
				if got := tt.offset(m); got != restart.wantAt {
					t.Fatalf("first tick: offset %d, want %d", got, restart.wantAt)
				}
			})
		}
	}
}

// pressTreemapKey sends one key press to the dashboard.
func pressTreemapKey(t *testing.T, m *Model, msg tea.KeyPressMsg) *Model {
	t.Helper()
	next, _ := m.Update(msg)
	return next.(*Model)
}

// enterFilter presses Enter and returns the global filter request it emits.
func enterFilter(t *testing.T, m *Model) messages.GlobalFilterRequestedMsg {
	t.Helper()
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		t.Fatalf("expected Enter to emit a filter request")
	}
	req, ok := cmd().(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg")
	}
	return req
}

func TestProcessesTreemapColumnKeysPickEnterFilter(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 1)
	assertProcessesTreemapSelection(t, m, 1, 200)

	// l selects the Comm column: Enter filters by the tile's command name.
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: 'l', Text: "l"})
	if m.processesTab.col != processCommColumn {
		t.Fatalf("expected l to select the Comm column, got column %d", m.processesTab.col)
	}
	assertProcessesTreemapSelection(t, m, 1, 200)
	if req := enterFilter(t, m); req.Filter.Comm == nil || req.Filter.Comm.Pattern != "beta" || req.Filter.PID != nil {
		t.Fatalf("expected a Comm=beta filter, got comm %+v pid %+v", req.Filter.Comm, req.Filter.PID)
	}

	// h goes back to the PID column.
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: 'h', Text: "h"})
	if req := enterFilter(t, m); req.Filter.PID == nil || req.Filter.PID.Value != 200 || req.Filter.Comm != nil {
		t.Fatalf("expected a PID=200 filter, got comm %+v pid %+v", req.Filter.Comm, req.Filter.PID)
	}
}

func TestProcessesTreemapJumpAndPageKeys(t *testing.T) {
	// 30 processes, of which PIDs 1-20 get a tile (tile i is PID i+1).
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, manyProcesses(30))
	m.height = 16 // a page step well below the tile count
	step := tablePageStep(m.activeTableHeight())
	if step < 2 || 3*step <= 19 {
		t.Fatalf("precondition: page step %d must page within, and past, the 20 tiles", step)
	}

	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: 'G', Text: "G"})
	assertProcessesTreemapSelection(t, m, 19, 20) // last tile, not the last table row
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: 'g', Text: "g"})
	assertProcessesTreemapSelection(t, m, 0, 1)

	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	assertProcessesTreemapSelection(t, m, step, uint32(step+1))
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgDown})
	assertProcessesTreemapSelection(t, m, 19, 20) // clamped to the last tile
	m = pressTreemapKey(t, m, tea.KeyPressMsg{Code: tea.KeyPgUp})
	assertProcessesTreemapSelection(t, m, 19-step, uint32(20-step))

	// None of it touched the table selection.
	if m.processesTab.offset != 0 {
		t.Fatalf("treemap navigation moved the table offset to %d", m.processesTab.offset)
	}
}

func TestKeyedSelection(t *testing.T) {
	keys := []string{"a", "b", "c"}
	offset := 1
	sel := keyedSelection{offset: &offset, keys: func() []string { return keys }}

	if got := sel.selectedKey(); got != "b" {
		t.Fatalf("selectedKey = %q, want b", got)
	}

	// capture(false) is positional: it only clamps.
	reanchor := sel.capture(false)
	keys = []string{"b", "x"}
	reanchor()
	if offset != 1 {
		t.Fatalf("positional capture moved the offset to %d", offset)
	}

	// keep follows the key and clamps when it is gone.
	offset = 0
	sel.keep(func() { keys = []string{"x", "y", "b"} })
	if offset != 2 {
		t.Fatalf("keep: offset %d, want 2", offset)
	}
	sel.keep(func() { keys = []string{"x"} })
	if offset != 0 {
		t.Fatalf("keep with vanished key: offset %d, want 0", offset)
	}
	sel.keep(func() { keys = nil })
	if offset != 0 || sel.selectedKey() != "" {
		t.Fatalf("keep with empty list: offset %d, key %q", offset, sel.selectedKey())
	}
	if got := processKey(4294967295, 0); got != "4294967295" {
		t.Fatalf("processKey = %q", got)
	}
}

// TestProcessKeyTellsRecycledPIDLifetimesApart checks that the rows of two
// processes that shared a PID (task ro2) get distinct selection keys, so the
// sort re-anchor and the treemap selection stay on the chosen lifetime, while
// the first lifetime keeps the bare-PID key.
func TestProcessKeyTellsRecycledPIDLifetimesApart(t *testing.T) {
	old := statsengine.ProcessSnapshot{PID: 2000, Lifetime: 0, Comm: "a", Syscalls: 1}
	successor := statsengine.ProcessSnapshot{PID: 2000, Lifetime: 1, Comm: "b", Syscalls: 9}
	if got := processRowKey(old); got != "2000" {
		t.Fatalf("first lifetime key = %q, want %q", got, "2000")
	}
	if got := processRowKey(successor); got != "2000#1" {
		t.Fatalf("second lifetime key = %q, want %q", got, "2000#1")
	}
	rows := []statsengine.ProcessSnapshot{successor, old}
	if idx, ok := findProcessOffset(rows, processRowKey(old)); !ok || idx != 1 {
		t.Fatalf("findProcessOffset(old) = %d, %v; want 1, true", idx, ok)
	}
	if _, ok := findProcessOffset(rows, processKey(2000, 2)); ok {
		t.Fatalf("findProcessOffset matched a lifetime that has no row")
	}
}
