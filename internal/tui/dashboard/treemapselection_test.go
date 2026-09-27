package dashboard

import (
	"errors"
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
)

// These tests cover the Syscalls and Processes treemap selections across
// stats ticks and metric / viz-mode changes (task cc). The treemaps order
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

// assertProcessesSelection checks the selection offset and PID, and that
// Enter's row (selectedProcessSnapshot) is the same process.
func assertProcessesSelection(t *testing.T, m *Model, wantAt int, wantPID uint32) {
	t.Helper()
	got := m.processesSelection().selectedKey()
	if m.processesTab.offset != wantAt || got != processKey(wantPID) {
		t.Fatalf("selected PID %q at %d, want %d at %d", got, m.processesTab.offset, wantPID, wantAt)
	}
	if pid := m.selectedProcessPID(); pid != wantPID {
		t.Fatalf("Enter targets PID %d, want %d", pid, wantPID)
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
	assertProcessesSelection(t, m, 2, 300)

	for range 2 {
		m = tickStats(t, m, messages.StatsTickMsg{Snap: procRanking(9, 5, 30)})
		assertProcessesSelection(t, m, 0, 300)
	}
	assertRenderedSelection(t, m, "sel:1/3 300:gamma")
}

func TestProcessesTreemapSelectionFallsBackWhenPIDDisappears(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	// PID 300 exited: the offset is clamped to the last surviving tile.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: 9},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: 5},
	)})
	assertProcessesSelection(t, m, 1, 200)
	assertRenderedSelection(t, m, "sel:2/2 200:beta")
}

func TestProcessesTreemapSelectionResetsOnEmptySnapshot(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 2)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	if m.processesTab.offset != 0 || m.processesSelection().selectedKey() != "" {
		t.Fatalf("expected no selection at 0, got %q at %d",
			m.processesSelection().selectedKey(), m.processesTab.offset)
	}
	if _, ok := m.selectedProcessSnapshot(); ok {
		t.Fatalf("expected no Enter target on an empty snapshot")
	}
	assertRenderedSelection(t, m, "treemap: no data")

	m = tickStats(t, m, messages.StatsTickMsg{Snap: procRanking(9, 5, 1)})
	assertProcessesSelection(t, m, 0, 100)
}

func TestProcessesTreemapSelectionKeptOnFailedStatsTick(t *testing.T) {
	good := procRanking(9, 5, 1)
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, good)
	m = pressJ(t, m, 2)

	m = tickStats(t, m, messages.StatsTickMsg{Err: errors.New("snapshot build failed")})
	if m.latest != good {
		t.Fatalf("expected last good snapshot kept on failed tick")
	}
	assertProcessesSelection(t, m, 2, 300)
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
	assertProcessesSelection(t, m, 1, 200)
}

func TestProcessesSelectionSurvivesMetricToggle(t *testing.T) {
	// 100 leads by syscalls, 200 by bytes, so b swaps their order.
	m := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	m = pressJ(t, m, 1)
	assertProcessesSelection(t, m, 1, 200)

	m = pressKey(m, 'b')
	if m.processesTab.bubble.Metric() != bubbleMetricBytes {
		t.Fatalf("expected b to switch to the bytes metric")
	}
	assertProcessesSelection(t, m, 0, 200)
}

func TestProcessesSelectionSurvivesModeCycle(t *testing.T) {
	// Sorted by PID descending the table (and bubbles mode, whose offset
	// indexes the table) lists 300, 200, 100; the treemap orders by
	// syscalls (100, 200, 300), so PID 100 moves in every mode.
	m := newVizModel(t, TabProcesses, tabVizModeTable, procRanking(9, 5, 1))
	m.processesTab.sort = tableSortState[processSortKey]{active: true, key: processSortKeyPID, reverse: true}
	m = pressJ(t, m, 2)
	assertProcessesSelection(t, m, 2, 100)

	steps := []struct {
		mode   tabVizMode
		wantAt int
	}{
		{tabVizModeBubbles, 2},
		{tabVizModeTreemap, 0},
		{tabVizModeTable, 2},
	}
	for _, step := range steps {
		m = pressKey(m, 'v')
		if m.processesTab.mode != step.mode {
			t.Fatalf("expected mode %d after v, got %d", step.mode, m.processesTab.mode)
		}
		if m.processesTab.offset != step.wantAt || m.processesSelection().selectedKey() != processKey(100) {
			t.Fatalf("mode %d: selected %q at %d, want PID 100 at %d", step.mode,
				m.processesSelection().selectedKey(), m.processesTab.offset, step.wantAt)
		}
	}
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
	tests := []struct {
		name    string
		sort    tableSortState[processSortKey]
		wantAt  int
		wantPID uint32
	}{
		// Unsorted, the table keeps its positional selection.
		{name: "default order is positional", wantAt: 1, wantPID: 100},
		// Sorted by syscalls, the selected PID 200 is followed to its new row.
		{name: "sorted follows PID", sort: tableSortState[processSortKey]{active: true, key: processSortKeySyscalls}, wantAt: 2, wantPID: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newVizModel(t, TabProcesses, tabVizModeTable, initial)
			m.processesTab.sort = tt.sort
			m = pressJ(t, m, 1)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: refresh})
			assertProcessesSelection(t, m, tt.wantAt, tt.wantPID)
		})
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
	if got := processKey(4294967295); got != "4294967295" {
		t.Fatalf("processKey = %q", got)
	}
}
