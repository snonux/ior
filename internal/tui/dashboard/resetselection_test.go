package dashboard

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
)

// These tests cover the selection across the snapshot the auto-reset leaves
// behind (task zq2). Every reset empties the stats for a tick; a selection
// that follows its row by key used to fall to row 0 there and then stay on the
// first row when the data refilled. The selected key is now a wish (stickyKey):
// it is remembered across the empty snapshot and across non-empty snapshots
// that lack the item (idle in the first window after the reset), and is
// looked for again until the item returns, the user moves, or the grace ends.
//
// Every refill below deliberately orders its rows differently from the
// pre-reset list. Keeping the offset alone would then select another item, so
// a test only passes when the selection really follows the key.

// fakeStickyClock replaces the wish clock with one the test advances by hand.
func fakeStickyClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Unix(1_000_000, 0)
	old := stickyClock
	stickyClock = func() time.Time { return now }
	t.Cleanup(func() { stickyClock = old })
	return &now
}

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

// pidsFrom is n process rows with PIDs first..first+n-1 in PID order.
func pidsFrom(first uint32, n int) []statsengine.ProcessSnapshot {
	rows := make([]statsengine.ProcessSnapshot, 0, n)
	for i := range n {
		rows = append(rows, statsengine.ProcessSnapshot{PID: first + uint32(i), Comm: "p", Syscalls: uint64(n - i)})
	}
	return rows
}

func emptyTick(t *testing.T, m *Model) *Model {
	t.Helper()
	return tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot()})
}

func TestSortedProcessesTableSelectionSurvivesReset(t *testing.T) {
	fakeStickyClock(t)
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	// Two empty ticks (the reset snapshot and the next one), then a refill in
	// which a new PID 0 sorts ahead of the old rows: the selection follows PID 8.
	m = emptyTick(t, m)
	m = emptyTick(t, m)
	if _, ok := m.selectedProcessSnapshot(); ok {
		t.Fatalf("an empty snapshot must offer no Enter target")
	}
	refill := append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, pidsFrom(1, 12)...)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(refill...)})
	assertProcessTableAt(t, m, 8, 8)

	// Found means done: a later reordering is followed by the ordinary
	// selected-row rule, not by a wish that is still pending.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 7, 8)
	if m.processesTab.wanted.key != "" {
		t.Fatalf("wish still pending after the item was found: %q", m.processesTab.wanted.key)
	}
}

// TestIdleFirstTickAfterResetKeepsSelection is the review repro: the snapshot
// right after a reset holds only the processes active in its first window, so
// PID 8 - selected, but idle for that tick - is missing from the first
// non-empty snapshot. The wish must survive it.
func TestIdleFirstTickAfterResetKeepsSelection(t *testing.T) {
	fakeStickyClock(t)
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	m = emptyTick(t, m)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)}) // PIDs 1..3, PID 8 idle
	assertProcessTableAt(t, m, 2, 3)                               // clamped placeholder
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 7, 8)
}

func TestIdleFirstTickKeepsTreemapSelections(t *testing.T) {
	fakeStickyClock(t)
	partialProcs := processesSnapshot(
		statsengine.ProcessSnapshot{PID: 100, Comm: "alpha", Syscalls: 4},
		statsengine.ProcessSnapshot{PID: 200, Comm: "beta", Syscalls: 3},
	)
	partialSys := syscallsSnapshot(
		statsengine.SyscallSnapshot{Name: "read", Count: 4},
		statsengine.SyscallSnapshot{Name: "write", Count: 3},
	)

	pm := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	pm = pressJ(t, pm, 2)
	pm = emptyTick(t, pm)
	pm = tickStats(t, pm, messages.StatsTickMsg{Snap: partialProcs})
	assertProcessesTreemapSelection(t, pm, 1, 200) // placeholder; 300 is idle
	pm = tickStats(t, pm, messages.StatsTickMsg{Snap: procRanking(1, 5, 9)})
	assertProcessesTreemapSelection(t, pm, 0, 300)

	sm := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	sm = pressJ(t, sm, 2)
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: partialSys})
	assertSyscallsTreemapSelection(t, sm, 1, "write")
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: sysRanking(1, 5, 9)})
	assertSyscallsTreemapSelection(t, sm, 0, "close")
}

func TestUnsortedProcessesTableKeepsPositionAcrossReset(t *testing.T) {
	m := newVizModel(t, TabProcesses, tabVizModeTable, resetPIDs(12))
	m = pressJ(t, m, 7)
	assertProcessTableAt(t, m, 7, 8)

	m = emptyTick(t, m)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 7, 8)

	// A refill shorter than the old offset still clamps into the list.
	m = emptyTick(t, m)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
	assertProcessTableAt(t, m, 2, 3)
}

// TestSelectionAfterResetIsNotForcedOntoAGoneKey: what is remembered is a
// wish, not a pin. While it is pending the selection sits on a placeholder;
// once the user moves, a later reappearance does not pull it away.
func TestSelectionAfterResetIsNotForcedOntoAGoneKey(t *testing.T) {
	fakeStickyClock(t)
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)

	m = emptyTick(t, m)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
	assertProcessTableAt(t, m, 2, 3)

	m = pressKey(m, 'k') // the user picks PID 2 themselves
	assertProcessTableAt(t, m, 1, 2)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(12)})
	assertProcessTableAt(t, m, 1, 2)
}

// TestSelectionMovedWhileEmptyIsNotOverridden: a navigation key pressed on the
// empty table is a decision by the user, even when it clamps to the offset the
// selection already had; the remembered row must not undo it.
func TestSelectionMovedWhileEmptyIsNotOverridden(t *testing.T) {
	fakeStickyClock(t)
	for _, tc := range []struct {
		name    string
		presses int
		key     rune
	}{
		{"offset 7, j clamps to 0", 7, 'j'},
		{"offset 0, j clamps to 0 (no change at all)", 0, 'j'},
		{"offset 0, k clamps to 0 (no change at all)", 0, 'k'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newSortedProcessesModel(t, resetPIDs(12))
			m = pressJ(t, m, tc.presses)
			want := m.processesTableSelection().selectedKey()

			m = emptyTick(t, m)
			m = pressKey(m, tc.key)
			// Refill with a PID 0 first, so a surviving wish would pick the
			// remembered PID at index+1 while the offset alone stays at 0.
			refill := append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, pidsFrom(1, 12)...)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(refill...)})
			if got := m.processesTableSelection().selectedKey(); m.processesTab.offset != 0 || got != "0" {
				t.Fatalf("selected %q at %d (remembered %q), want the user's row 0 (PID 0)",
					got, m.processesTab.offset, want)
			}
		})
	}
}

// TestColumnKeysLeaveTheWishAlone: only row moves and re-sorting are
// decisions about the selected row.
func TestColumnKeysLeaveTheWishAlone(t *testing.T) {
	fakeStickyClock(t)
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)
	m = emptyTick(t, m)
	m = pressKey(m, 'l')
	m = pressKey(m, 'h')
	refill := append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, pidsFrom(1, 12)...)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(refill...)})
	assertProcessTableAt(t, m, 8, 8)
}

func TestSortingCancelsTheWish(t *testing.T) {
	fakeStickyClock(t)
	m := newSortedProcessesModel(t, resetPIDs(12))
	m = pressJ(t, m, 7)
	m = emptyTick(t, m)
	m = pressKey(m, 's') // re-sort the empty table by the selected column
	if m.processesTab.wanted.key != "" {
		t.Fatalf("sorting must cancel the wish, still %q", m.processesTab.wanted.key)
	}
}

func TestTreemapNavigationCancelsTheWish(t *testing.T) {
	fakeStickyClock(t)
	pm := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	pm = pressJ(t, pm, 2)
	pm = emptyTick(t, pm)
	pm = pressJ(t, pm, 1) // the table keys clamp an empty list to row 0
	// PID 300 stays third here: a surviving wish would select it at 2 instead
	// of the user's row 0.
	pm = tickStats(t, pm, messages.StatsTickMsg{Snap: procRanking(5, 9, 1)})
	assertProcessesTreemapSelection(t, pm, 0, 200)

	sm := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	sm = pressJ(t, sm, 2)
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	sm = pressJ(t, sm, 1) // scrollOffset leaves the offset at 2; still a move
	// A surviving wish would select close at 0.
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: sysRanking(1, 5, 9)})
	assertSyscallsTreemapSelection(t, sm, 2, "read")
}

// TestWishExpiresAfterGrace: a table the filter empties for good must not pull
// the selection back to the old row when it is unfiltered much later.
func TestWishExpiresAfterGrace(t *testing.T) {
	now := fakeStickyClock(t)
	refill := func() *statsengine.Snapshot {
		return processesSnapshot(append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, pidsFrom(1, 12)...)...)
	}

	t.Run("within the grace the item is found", func(t *testing.T) {
		m := newSortedProcessesModel(t, resetPIDs(12))
		m = pressJ(t, m, 7)
		m = emptyTick(t, m)
		*now = now.Add(stickyKeyGrace - time.Second)
		m = tickStats(t, m, messages.StatsTickMsg{Snap: refill()})
		assertProcessTableAt(t, m, 8, 8)
	})

	t.Run("after the grace the offset just clamps", func(t *testing.T) {
		m := newSortedProcessesModel(t, resetPIDs(12))
		m = pressJ(t, m, 7)
		m = emptyTick(t, m)
		*now = now.Add(stickyKeyGrace + time.Second)
		m = tickStats(t, m, messages.StatsTickMsg{Snap: refill()})
		assertProcessTableAt(t, m, 7, 7)
	})

	t.Run("a list empty for hours does not renew the wish", func(t *testing.T) {
		m := newSortedProcessesModel(t, resetPIDs(12))
		m = pressJ(t, m, 7)
		for range 5 { // every empty tick re-remembers the key
			m = emptyTick(t, m)
			*now = now.Add(stickyKeyGrace / 3)
		}
		m = tickStats(t, m, messages.StatsTickMsg{Snap: refill()})
		assertProcessTableAt(t, m, 7, 7)
	})

	t.Run("partial snapshots keep the wish until the grace", func(t *testing.T) {
		m := newSortedProcessesModel(t, resetPIDs(12))
		m = pressJ(t, m, 7)
		m = emptyTick(t, m)
		for range 3 {
			*now = now.Add(stickyKeyGrace / 4)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
		}
		m = tickStats(t, m, messages.StatsTickMsg{Snap: refill()})
		assertProcessTableAt(t, m, 8, 8)

	})

	t.Run("partial snapshots past the grace lose the wish", func(t *testing.T) {
		m := newSortedProcessesModel(t, resetPIDs(12))
		m = pressJ(t, m, 7)
		m = emptyTick(t, m)
		for range 5 {
			*now = now.Add(stickyKeyGrace / 4)
			m = tickStats(t, m, messages.StatsTickMsg{Snap: resetPIDs(3)})
		}
		// The placeholder row (PID 3) is what the ordinary rule follows now.
		m = tickStats(t, m, messages.StatsTickMsg{Snap: refill()})
		assertProcessTableAt(t, m, 3, 3)
	})
}

// TestRecycledPIDDoesNotMatchAStaleKey: a process row's key carries its
// lifetime ordinal (processKey), so the wish for the recycled PID's second
// lifetime "8#1" is not satisfied by another process' row for PID 8 (its
// first lifetime, "8"). The engine keeps the ordinals stable across
// Engine.Reset (see statsengine carryOver), so the same process comes back as
// "8#1" and satisfies the wish - the two end-to-end tests in
// resetidentity_test.go run that against the real engine; this one pins the
// key matching on its own with hand-built snapshots.
func TestRecycledPIDDoesNotMatchAStaleKey(t *testing.T) {
	fakeStickyClock(t)
	rows := append(pidsFrom(1, 7), statsengine.ProcessSnapshot{PID: 8, Lifetime: 1, Comm: "second", Syscalls: 1})
	m := newSortedProcessesModel(t, processesSnapshot(rows...))
	m = pressJ(t, m, 7)
	if got := m.processesTableSelection().selectedKey(); got != processKey(8, 1) {
		t.Fatalf("precondition: selected %q, want %q", got, processKey(8, 1))
	}

	m = emptyTick(t, m)
	next := append(pidsFrom(0, 1), pidsFrom(1, 7)...)
	next = append(next, statsengine.ProcessSnapshot{PID: 8, Lifetime: 0, Comm: "other", Syscalls: 1})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(next...)})
	if got := m.processesTableSelection().selectedKey(); got == processKey(8, 0) {
		t.Fatalf("the wish for PID 8 lifetime 1 selected the lifetime 0 row")
	}

	// The matching lifetime does satisfy it.
	next = append(next, statsengine.ProcessSnapshot{PID: 8, Lifetime: 1, Comm: "second", Syscalls: 1})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: processesSnapshot(next...)})
	if got := m.processesTableSelection().selectedKey(); got != processKey(8, 1) {
		t.Fatalf("selected %q after the lifetime returned, want %q", got, processKey(8, 1))
	}
}

func TestSortedSyscallsTableSelectionSurvivesReset(t *testing.T) {
	fakeStickyClock(t)
	m := newVizModel(t, TabSyscalls, tabVizModeTable, manySyscalls(12))
	m.syscallsTab.sort = tableSortState[syscallSortKey]{active: true, key: syscallSortKeyName}
	m = pressJ(t, m, 7)
	want := m.syscallsTableSelection().selectedKey()
	if want == "" {
		t.Fatalf("no syscall selected before the reset")
	}

	// The refill has a syscall sorting ahead of every old one, so the row moves
	// from index 7 to 8: only key-following ends on it.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	refill := append([]statsengine.SyscallSnapshot{{Name: "aaa", Count: 1}}, manySyscalls(12).Syscalls()...)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: syscallsSnapshot(refill...)})
	if got := m.syscallsTableSelection().selectedKey(); got != want || m.syscallsTab.offset != 8 {
		t.Fatalf("selected %q at %d after reset, want %q at 8", got, m.syscallsTab.offset, want)
	}
}

func TestSyscallsAndProcessesTreemapsFollowKeyAcrossReset(t *testing.T) {
	fakeStickyClock(t)
	sm := newVizModel(t, TabSyscalls, tabVizModeTreemap, sysRanking(9, 5, 1))
	sm = pressJ(t, sm, 2)
	assertSyscallsTreemapSelection(t, sm, 2, "close")
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: syscallsSnapshot()})
	sm = tickStats(t, sm, messages.StatsTickMsg{Snap: sysRanking(1, 5, 9)})
	assertSyscallsTreemapSelection(t, sm, 0, "close")

	pm := newVizModel(t, TabProcesses, tabVizModeTreemap, procRanking(9, 5, 1))
	pm = pressJ(t, pm, 2)
	assertProcessesTreemapSelection(t, pm, 2, 300)
	pm = emptyTick(t, pm)
	pm = tickStats(t, pm, messages.StatsTickMsg{Snap: procRanking(1, 5, 9)})
	assertProcessesTreemapSelection(t, pm, 0, 300)
}

// TestFilesDirSelectionFollowsKeyAcrossReset: the icicle and treemap of the
// dir-grouped Files tab reorder their tiles by weight, so after the reset the
// selected directory sits at a different offset.
func TestFilesDirSelectionFollowsKeyAcrossReset(t *testing.T) {
	fakeStickyClock(t)
	for _, mode := range []tabVizMode{tabVizModeTreemap, tabVizModeIcicle} {
		m := newFilesVizModel(t, mode, icicleSnapshot(9, 7))
		m = pressJ(t, m, 1)
		want, was := m.filesDirSelection().selectedKey(), m.filesDirTab.offset
		if mode == tabVizModeIcicle { // /a, /a/b, /a/b/c, /a/d, /a/d/e: pick the last tile
			m = pressJ(t, m, 3)
			want, was = m.filesDirSelection().selectedKey(), m.filesDirTab.offset
		}

		ref := newFilesVizModel(t, mode, icicleSnapshot(1, 7))
		wantAt := slices.Index(ref.filesDirSelection().keys(), want)
		if wantAt < 0 || wantAt == was {
			t.Fatalf("mode %d: test setup: %q sits at %d before and %d after; the refill must reorder it", mode, want, was, wantAt)
		}

		m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
		m = tickStats(t, m, messages.StatsTickMsg{Snap: icicleSnapshot(1, 7)})
		if got := m.filesDirSelection().selectedKey(); got != want || m.filesDirTab.offset != wantAt {
			t.Fatalf("mode %d: selected %q at %d, want %q at %d", mode, got, m.filesDirTab.offset, want, wantAt)
		}
	}
}

func TestSortedFilesTableSelectionSurvivesReset(t *testing.T) {
	fakeStickyClock(t)
	files := func(extra ...string) []statsengine.FileSnapshot {
		rows := make([]statsengine.FileSnapshot, 0, 12)
		for _, p := range extra {
			rows = append(rows, statsengine.FileSnapshot{Path: p, Accesses: 1})
		}
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

	// Two empty ticks, then a refill with a path sorting ahead of every old
	// one: /d/f07 moves to index 8, so only the path decides.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(files("/a/new")...)})
	if got := m.selectedFilePath(); got != "/d/f07" || m.filesTab.offset != 8 {
		t.Fatalf("selected %q at %d after reset, want /d/f07 at 8", got, m.filesTab.offset)
	}

	// The idle-first-tick case for the Files table: /d/f07 is missing from the
	// first refill and comes back with the next one.
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(files()[:3]...)})
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot(files("/a/new")...)})
	if got := m.selectedFilePath(); got != "/d/f07" || m.filesTab.offset != 8 {
		t.Fatalf("selected %q at %d after the idle tick, want /d/f07 at 8", got, m.filesTab.offset)
	}
}

// TestSelectionSurvivesRealResetStats drives the reset the way the auto-reset
// and the r key do: the engine is reset, the post-reset snapshot is empty and
// is applied straight away, and the data returns through later ticks.
func TestSelectionSurvivesRealResetStats(t *testing.T) {
	fakeStickyClock(t)
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
	src.snap = processesSnapshot(append([]statsengine.ProcessSnapshot{{PID: 0, Comm: "new", Syscalls: 1}}, pidsFrom(1, 12)...)...)
	m = tickStats(t, m, m.statsTick())
	assertProcessTableAt(t, m, 8, 8)
}

// TestStickyKeyStateMachine pins the wish lifecycle on its own, so a wish that
// lingers after it was resolved cannot hide behind identical selections.
func TestStickyKeyStateMachine(t *testing.T) {
	now := fakeStickyClock(t)
	find := func(rows []string, key string) (int, bool) { return findKeyOffset(rows, key) }
	var k stickyKey

	// Empty list: remembered, offset kept, original start kept on repeat.
	if got := reanchorSticky(4, &k, []string(nil), "a", find); got != 4 || k.key != "a" {
		t.Fatalf("empty list: offset %d, wish %q; want 4, a", got, k.key)
	}
	started := k.since
	*now = now.Add(time.Second)
	reanchorSticky(4, &k, []string(nil), "a", find)
	if !k.since.Equal(started) {
		t.Fatalf("repeating the wish restarted its grace")
	}

	// Rows without the key: the wish stays, the offset clamps.
	if got := reanchorSticky(4, &k, []string{"x", "y"}, "a", find); got != 1 || k.key != "a" {
		t.Fatalf("missing key: offset %d, wish %q; want 1, a", got, k.key)
	}
	// Rows with it: found, so resolved.
	if got := reanchorSticky(1, &k, []string{"x", "a"}, "a", find); got != 1 || k.key != "" {
		t.Fatalf("found key: offset %d, wish %q; want 1, none", got, k.key)
	}
	// A wish that is not what the re-anchor was for does not linger.
	k.remember("a")
	reanchorSticky(0, &k, []string{"x", "y"}, "y", find)
	if k.key != "" {
		t.Fatalf("a re-anchor onto another key left the wish %q", k.key)
	}
	// An empty selected (the capture that skipped the wish) ends it as well,
	// as does a selected that is neither the wish nor listed.
	for _, other := range []string{"", "gone"} {
		k.remember("a")
		reanchorSticky(0, &k, []string{"x", "y"}, other, find)
		if k.key != "" {
			t.Fatalf("a re-anchor for %q left the wish %q", other, k.key)
		}
	}
	// nil storage is allowed.
	if got := reanchorSticky(3, nil, []string(nil), "a", find); got != 3 {
		t.Fatalf("nil wanted, empty list: offset %d, want 3", got)
	}
	var none *stickyKey
	none.forget()
	if none.peek() != "" {
		t.Fatalf("nil stickyKey has a wish")
	}
}

func TestKeyedSelectionKeepsItsKeyThroughEmptyAndPartialLists(t *testing.T) {
	fakeStickyClock(t)
	keys := []string{"a", "b", "c"}
	offset := 1
	var wanted stickyKey
	sel := keyedSelection{offset: &offset, keys: func() []string { return keys }, wanted: &wanted}

	sel.keep(func() { keys = nil })
	if offset != 1 {
		t.Fatalf("empty list moved the offset to %d", offset)
	}
	sel.keep(func() { keys = nil }) // still empty: the memory carries over
	sel.keep(func() { keys = []string{"x"} })
	if offset != 0 {
		t.Fatalf("partial list: offset %d, want it clamped to 0", offset)
	}
	sel.keep(func() { keys = []string{"x", "y", "b"} })
	if offset != 2 || sel.selectedKey() != "b" {
		t.Fatalf("refill: selected %q at %d, want b at 2", sel.selectedKey(), offset)
	}
}

// TestFilesWishDoesNotOutliveTheTableView: the sorted Files table's wish (its
// capture is the path) is dropped by a refresh that ran while the table was
// not what the tab showed (the directory view), where the capture yields no
// path. Switching back must not have the stale wish yank the selection off
// the row the user is on.
func TestFilesWishDoesNotOutliveTheTableView(t *testing.T) {
	fakeStickyClock(t)
	files := func(n int) *statsengine.Snapshot {
		rows := make([]statsengine.FileSnapshot, 0, n)
		for i := range n {
			rows = append(rows, statsengine.FileSnapshot{Path: fmt.Sprintf("/d/f%02d", i), Accesses: 1})
		}
		return filesSnapshot(rows...)
	}
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.width, m.height = 120, 28
	m.filesTab.sort = tableSortState[fileSortKey]{active: true, key: fileSortKeyPath}
	m = tickStats(t, m, messages.StatsTickMsg{Snap: files(12)})
	m = pressJ(t, m, 7)
	m = tickStats(t, m, messages.StatsTickMsg{Snap: filesSnapshot()}) // reset: wish for /d/f07
	if m.filesTab.wanted.key == "" {
		t.Fatalf("precondition: no wish pending after the empty snapshot")
	}

	m.filesDirGrouped = true // the user switched to the directory view ...
	m = tickStats(t, m, messages.StatsTickMsg{Snap: files(3)})
	if m.filesTab.wanted.key != "" {
		t.Fatalf("a refresh that skipped the table left the wish %q", m.filesTab.wanted.key)
	}
	m.filesDirGrouped = false // ... and back, with the row the wish named listed again
	m = tickStats(t, m, messages.StatsTickMsg{Snap: files(12)})
	if m.filesTab.offset == 7 {
		t.Fatalf("the stale wish pulled the selection onto /d/f07 (offset %d)", m.filesTab.offset)
	}
}
