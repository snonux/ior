package dashboard

import (
	"fmt"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
)

// These tests cover the selection across the snapshot the auto-reset leaves
// behind (task zq2). Every reset empties the stats for a tick; a selection
// that follows its row by key used to fall to row 0 there and then stay on the
// first row when the data refilled. The selected key is now remembered across
// the empty snapshot and looked for again when rows return.

// resetPIDs is n processes with PIDs 1..n, so sorting by PID keeps them in
// PID order while their syscall counts run the other way.
func resetPIDs(n int) *statsengine.Snapshot {
	return manyProcesses(n)
}

func assertProcessTableAt(t *testing.T, m *Model, wantAt int, wantPID uint32) {
	t.Helper()
	assertProcessesTableSelection(t, m, wantAt, wantPID)
}

func newSortedProcessesModel(t *testing.T, snap *statsengine.Snapshot) *Model {
	t.Helper()
	m := newVizModel(t, TabProcesses, tabVizModeTable, snap)
	m.processesTab.sort = tableSortState[processSortKey]{active: true, key: processSortKeyPID}
	return m
}

func TestSortedProcessesTableSelectionSurvivesReset(t *testing.T) {
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	// Two empty ticks (the reset snapshot and the next one), then a refill in
	// which a new PID 0 sorts ahead of the old rows: the selection follows PID 8.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	if _, ok := m.selectedProcessSnapshot(); ok {
		t.Fatalf("an empty snapshot must offer no Enter target")
	}
	refill := append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, resetPIDs(12).Processes()...)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(refill...)})
	assertProcessTableAt(t, m, 8, 8)

	// The memory is single-shot: it does not linger and move the selection later.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 7, 8)
}

func TestUnsortedProcessesTableKeepsPositionAcrossReset(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTable, resetPIDs(12))
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 7, 8)

	// A refill shorter than the old offset still clamps into the list.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
	assertProcessTableAt(t, m, 2, 3)
}

// TestSelectionAfterResetIsNotForcedOntoAGoneKey: what is remembered is a
// wish, not a pin. If the row never comes back the selection clamps, and a
// later reappearance does not pull it away from where the user is.
func TestSelectionAfterResetIsNotForcedOntoAGoneKey(t *testing.T) {
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	// PID 8 is missing from the refill; three rows remain.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
	assertProcessTableAt(t, m, 2, 3)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 2, 3)
}

// TestSelectionMovedWhileEmptyIsNotOverridden: a navigation key pressed on the
// empty table is a decision by the user; the remembered row must not undo it.
func TestSelectionMovedWhileEmptyIsNotOverridden(t *testing.T) {
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)

	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
	m = pressJ(t, m, 1) // clamps the offset to 0 on the empty list
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 0, 1)
}

func TestSortedSyscallsTableSelectionSurvivesReset(t *testing.T) {
	m := newVizModel(t, TabSyscalls, tabVizModeTable, manySyscalls(12))
	m.syscallsTab.sort = tableSortState[syscallSortKey]{active: true, key: syscallSortKeyName}
	m = pressJ(t, m, 7)
	want := m.syscallsTableSelection().selectedKey()
	if want == "" {
		t.Fatalf("no syscall selected before the reset")
	}

	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: manySyscalls(12)})
	if got := m.syscallsTableSelection().selectedKey(); got != want || m.syscallsTab.offset != 7 {
		t.Fatalf("selected %q at %d after reset, want %q at 7", got, m.syscallsTab.offset, want)
	}
}

func TestSortedFilesTableSelectionSurvivesReset(t *testing.T) {
	files := func() []statsengine.FileSnapshot {
		rows := make([]statsengine.FileSnapshot, 0, 12)
		for i := range 12 {
			rows = append(rows, statsengine.FileSnapshot{Path: fmt.Sprintf("/d/f%02d", i), Accesses: 1})
		}
		return rows
	}
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.width, m.height = 120, 28
	m.filesTab.sort = tableSortState[fileSortKey]{active: true, key: fileSortKeyPath}
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(files()...)})
	m = pressJ(t, m, 7)
	if got := m.selectedFilePath(); got != "/d/f07" {
		t.Fatalf("precondition: selected %q, want /d/f07", got)
	}

	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(files()...)})
	if got := m.selectedFilePath(); got != "/d/f07" || m.filesTab.offset != 7 {
		t.Fatalf("selected %q at %d after reset, want /d/f07 at 7", got, m.filesTab.offset)
	}
}

// TestSelectionSurvivesRealResetStats drives the reset the way the auto-reset
// and the r key do: the engine is reset, the post-reset snapshot is empty and
// is applied straight away, and the data returns through later ticks.
func TestSelectionSurvivesRealResetStats(t *testing.T) {
	src := &fakeSnapshotSource{snap: resetPIDs(12), resetSnap: processesSnapshot()}
	m := NewModelWithConfig(src, nil, 250, 200, common.DefaultKeyMap())
	m.width, m.height = 120, 28
	m.activeTab = TabProcesses
	m.processesTab.sort = tableSortState[processSortKey]{active: true, key: processSortKeyPID}
	m = tickStats(t, m, m.statsTick())
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	m.ResetStats()
	if got := len(m.latest.Processes()); got != 0 {
		t.Fatalf("precondition: post-reset snapshot has %d processes", got)
	}
	src.snap = resetPIDs(12)
	m = tickStats(t, m, m.statsTick())
	assertProcessTableAt(t, m, 7, 8)
}

func TestStickyKeyTakeRequiresUnmovedOffset(t *testing.T) {
	var k stickyKey
	k.remember("a", 4)
	if got := k.take(4); got != "a" {
		t.Fatalf("take at the remembered offset = %q, want a", got)
	}
	if got := k.take(4); got != "" {
		t.Fatalf("second take = %q, want empty (single-shot)", got)
	}
	k.remember("a", 4)
	if got := k.take(0); got != "" {
		t.Fatalf("take at a moved offset = %q, want empty", got)
	}
	if got := takeWanted(nil, 0); got != "" {
		t.Fatalf("takeWanted(nil) = %q, want empty", got)
	}
}

func TestKeyedSelectionKeepsItsKeyThroughAnEmptyList(t *testing.T) {
	keys := []string{"a", "b", "c"}
	offset := 1
	var wanted stickyKey
	sel := keyedSelection{offset: &offset, keys: func() []string { return keys }, wanted: &wanted}

	sel.keep(func() { keys = nil })
	if offset != 1 {
		t.Fatalf("empty list moved the offset to %d", offset)
	}
	sel.keep(func() { keys = nil }) // still empty: the memory carries over
	sel.keep(func() { keys = []string{"x", "y", "b"} })
	if offset != 2 || sel.selectedKey() != "b" {
		t.Fatalf("refill: selected %q at %d, want b at 2", sel.selectedKey(), offset)
	}
}
