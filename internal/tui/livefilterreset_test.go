package tui

import (
	"errors"
	"testing"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/tui/messages"
)

// countingLiveTrie is a real LiveTrie that also counts its resets, so a test
// can tell a baseline reset apart from a trie that merely happens to be empty.
type countingLiveTrie struct {
	*coreflamegraph.LiveTrie
	resets int
}

func (c *countingLiveTrie) Reset() {
	c.resets++
	c.LiveTrie.Reset()
}

func newCountingLiveTrie() *countingLiveTrie {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestFlameData(trie)
	return &countingLiveTrie{LiveTrie: trie}
}

// trieTotal is the number of samples the trie currently aggregates.
func trieTotal(t *testing.T, trie *countingLiveTrie) uint64 {
	t.Helper()
	root, _ := trie.SnapshotTree()
	if root == nil {
		return 0
	}
	return root.Total
}

// liveSwapFixture is a dashboard on the in-place swap path with a stats engine
// and a live trie that both already hold pre-swap data.
type liveSwapFixture struct {
	m               *Model
	src             *fakeDashboardSource
	trie            *countingLiveTrie
	applied         []globalfilter.Filter
	preSwap         *statsengine.Snapshot
	resetBeforeSwap bool
}

func newLiveSwapFixture(t *testing.T) *liveSwapFixture {
	t.Helper()
	m, _ := newLiveSwapModel(t)
	f := &liveSwapFixture{
		m:       m,
		src:     &fakeDashboardSource{},
		trie:    newCountingLiveTrie(),
		preSwap: &statsengine.Snapshot{TotalSyscalls: 99},
	}
	f.src.snap = f.preSwap
	// Re-register the setter so it can see whether a reset ran before the
	// swap: resetting first would let old-filter events into the new
	// baseline in the window between the reset and the swap.
	m.runtime.setLiveFilterSetter(func(filter globalfilter.Filter) {
		// Each earlier swap reset once; any more means this swap's
		// reset already ran.
		swaps := len(f.applied)
		if f.src.resetCalls != swaps || f.trie.resets != swaps {
			f.resetBeforeSwap = true
		}
		f.applied = append(f.applied, filter)
	})
	m.runtime.setDashboardSnapshotSource(f.src)
	m.runtime.setLiveTrie(f.trie)
	m.dashboard.SetLiveTrie(f.trie)

	next, _ := m.Update(messages.StatsTickMsg{Snap: f.preSwap})
	f.m = next.(*Model)
	if got := f.m.dashboard.LatestSnapshot(); got != f.preSwap {
		t.Fatalf("precondition: expected the pre-swap snapshot on screen, got %+v", got)
	}
	if trieTotal(t, f.trie) == 0 {
		t.Fatal("precondition: expected the live trie to hold pre-swap samples")
	}
	return f
}

func (f *liveSwapFixture) apply(t *testing.T, filter globalfilter.Filter) {
	t.Helper()
	next, _ := f.m.Update(messages.GlobalFilterRequestedMsg{Filter: filter})
	f.m = next.(*Model)
}

func commFilter(pattern string) globalfilter.Filter {
	return globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: pattern}}
}

// assertFreshBaseline checks that the stats engine and the live trie were
// each reset `want` times and that the dashboard now shows the post-reset
// snapshot rather than the pre-swap aggregates.
func (f *liveSwapFixture) assertFreshBaseline(t *testing.T, want int) {
	t.Helper()
	if f.src.resetCalls != want {
		t.Errorf("stats engine resets = %d, want %d", f.src.resetCalls, want)
	}
	if f.trie.resets != want {
		t.Errorf("live trie resets = %d, want %d", f.trie.resets, want)
	}
	if got := trieTotal(t, f.trie); got != 0 {
		t.Errorf("live trie still aggregates %d pre-swap samples", got)
	}
	snap := f.m.dashboard.LatestSnapshot()
	if snap == nil || snap == f.preSwap || snap.TotalSyscalls != 0 {
		t.Errorf("expected the dashboard to show the post-reset snapshot, got %+v", snap)
	}
	if f.resetBeforeSwap {
		t.Error("aggregates were reset before the filter reached the pipeline")
	}
	if f.m.attaching {
		t.Error("an in-place swap must not restart the trace")
	}
}

// TestLiveFilterSwapResetsStatsAndLiveTrie is the rb regression: the in-place
// swap handed the new filter to the running eventloop but kept the stats
// engine and live trie, so every tab mixed pre-filter counts with the
// filtered events that followed.
func TestLiveFilterSwapResetsStatsAndLiveTrie(t *testing.T) {
	f := newLiveSwapFixture(t)

	f.apply(t, commFilter("foo"))

	if len(f.applied) != 1 {
		t.Fatalf("expected the filter to reach the running pipeline once, got %d", len(f.applied))
	}
	f.assertFreshBaseline(t, 1)
}

// TestLiveFilterUndoResetsStatsAndLiveTrie covers the undo route, which
// swaps the filter in place through the same tail.
func TestLiveFilterUndoResetsStatsAndLiveTrie(t *testing.T) {
	f := newLiveSwapFixture(t)
	f.apply(t, commFilter("foo"))

	next, _ := f.m.Update(messages.StatsTickMsg{Snap: f.preSwap})
	f.m = next.(*Model)
	coreflamegraph.SeedTestFlameData(f.trie.LiveTrie)

	next, _ = f.m.Update(messages.GlobalFilterUndoRequestedMsg{})
	f.m = next.(*Model)

	if len(f.applied) != 2 {
		t.Fatalf("expected the undo to reach the running pipeline, got %d swaps", len(f.applied))
	}
	if got := f.applied[1]; got.Comm != nil {
		t.Fatalf("expected the undo to restore the unfiltered view, got comm %+v", got.Comm)
	}
	f.assertFreshBaseline(t, 2)
}

// TestLiveFilterFamilyCycleResetsStatsAndLiveTrie covers replaceGlobalFilter,
// the third route onto the in-place swap.
func TestLiveFilterFamilyCycleResetsStatsAndLiveTrie(t *testing.T) {
	f := newLiveSwapFixture(t)

	next, _ := f.m.replaceGlobalFilter(commFilter("bar"))
	f.m = next.(*Model)

	if len(f.applied) != 1 {
		t.Fatalf("expected the re-scope to reach the running pipeline once, got %d", len(f.applied))
	}
	f.assertFreshBaseline(t, 1)
}

// TestLiveFilterSwapWithIdenticalFilterKeepsAggregates: re-applying the
// filter already in effect changes nothing in the pipeline, so wiping the
// user's accumulated view would be pure loss.
func TestLiveFilterSwapWithIdenticalFilterKeepsAggregates(t *testing.T) {
	f := newLiveSwapFixture(t)
	f.apply(t, commFilter("foo"))

	next, _ := f.m.Update(messages.StatsTickMsg{Snap: f.preSwap})
	f.m = next.(*Model)
	coreflamegraph.SeedTestFlameData(f.trie.LiveTrie)
	before := trieTotal(t, f.trie)

	f.apply(t, commFilter("foo"))

	if len(f.applied) != 1 {
		t.Fatalf("an identical filter must not reach the pipeline again, got %d swaps", len(f.applied))
	}
	if f.src.resetCalls != 1 || f.trie.resets != 1 {
		t.Fatalf("an identical filter reset the aggregates: engine=%d trie=%d, want 1 each",
			f.src.resetCalls, f.trie.resets)
	}
	if got := f.m.dashboard.LatestSnapshot(); got != f.preSwap {
		t.Errorf("an identical filter replaced the snapshot on screen, got %+v", got)
	}
	if got := trieTotal(t, f.trie); got != before {
		t.Errorf("an identical filter changed the trie total from %d to %d", before, got)
	}
}

// TestFilterChangeWithoutLiveSetterRestartsInsteadOfResetting: with no trace
// running there is no setter, so the change takes the restart path, whose new
// session brings its own engine and trie. Resetting the stale ones there
// would be meaningless work on objects about to be replaced.
func TestFilterChangeWithoutLiveSetterRestartsInsteadOfResetting(t *testing.T) {
	f := newLiveSwapFixture(t)
	// Register and immediately release a setter: the release clears the
	// fixture's setter too, exactly as a finished trace session leaves it.
	f.m.runtime.setLiveFilterSetter(func(globalfilter.Filter) {})()

	f.apply(t, commFilter("foo"))

	if len(f.applied) != 0 {
		t.Fatalf("expected no in-place swap without a setter, got %d", len(f.applied))
	}
	if !f.m.attaching {
		t.Fatal("expected the filter change to fall back to a trace restart")
	}
	if f.src.resetCalls != 0 || f.trie.resets != 0 {
		t.Errorf("restart path reset the old session's aggregates: engine=%d trie=%d",
			f.src.resetCalls, f.trie.resets)
	}
}

// TestLiveFilterSwapWithoutWiredSourcesIsSafe: a setter can be registered
// before the stats engine or trie are published. The swap must still go
// through, with nothing to reset and no nil dereference.
func TestLiveFilterSwapWithoutWiredSourcesIsSafe(t *testing.T) {
	m, recorder := newLiveSwapModel(t)

	next, cmd := m.Update(messages.GlobalFilterRequestedMsg{Filter: commFilter("foo")})
	m = next.(*Model)

	if len(recorder.applied) != 1 {
		t.Fatalf("expected the filter to reach the running pipeline once, got %d", len(recorder.applied))
	}
	if m.attaching {
		t.Fatal("an in-place swap must not restart the trace")
	}
	if cmd != nil {
		t.Errorf("expected no follow-up command with nothing to reset, got %T", cmd)
	}
	if got := m.dashboard.LatestSnapshot(); got != nil {
		t.Errorf("expected no snapshot without an engine, got %+v", got)
	}
}

// TestLiveFilterSwapKeepsLastGoodSnapshotWhenPostResetSnapshotFails pins mb's
// semantics on this path: the engine and trie are still reset, but a failed
// post-reset Snapshot must not blank the dashboard. The next refresh tick
// replaces the kept snapshot with the fresh baseline.
func TestLiveFilterSwapKeepsLastGoodSnapshotWhenPostResetSnapshotFails(t *testing.T) {
	f := newLiveSwapFixture(t)
	f.src.err = errors.New("snapshot build failed")

	f.apply(t, commFilter("foo"))

	if f.src.resetCalls != 1 || f.trie.resets != 1 {
		t.Fatalf("expected the engine and trie to be reset once each, got engine=%d trie=%d",
			f.src.resetCalls, f.trie.resets)
	}
	if got := f.m.dashboard.LatestSnapshot(); got != f.preSwap {
		t.Errorf("expected the last good snapshot to survive a failed post-reset snapshot, got %+v", got)
	}
}

func TestRuntimeBindingsResetLiveTrieWithoutTrie(t *testing.T) {
	if got := newRuntimeBindings().resetLiveTrie(); got != nil {
		t.Fatalf("expected nil with no trie wired, got %T", got)
	}
}

// TestUndoAfterFamilyCycleBackToAllKeepsAggregates: Apply family=Network
// pushes an undo level; '[' re-scopes back to all without pushing; the undo
// then pops a level equal to the active filter. It must still consume the
// level, but must not re-apply an unchanged filter and wipe the stats, the
// trie and the flame zoom for nothing.
func TestUndoAfterFamilyCycleBackToAllKeepsAggregates(t *testing.T) {
	f := newLiveSwapFixture(t)
	f.apply(t, globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "Network"}})

	next, _ := f.m.cycleFamilyScope(-1)
	f.m = next.(*Model)
	if got := f.m.filters.current(); got.Family != nil {
		t.Fatalf("precondition: expected '[' to cycle Network back to all, got family %q", got.Family.Pattern)
	}
	if len(f.applied) != 2 || f.src.resetCalls != 2 || f.trie.resets != 2 {
		t.Fatalf("precondition: expected apply and cycle to swap and reset twice, got swaps=%d engine=%d trie=%d",
			len(f.applied), f.src.resetCalls, f.trie.resets)
	}
	next, _ = f.m.Update(messages.StatsTickMsg{Snap: f.preSwap})
	f.m = next.(*Model)
	coreflamegraph.SeedTestFlameData(f.trie.LiveTrie)
	before := trieTotal(t, f.trie)

	next, _ = f.m.Update(messages.GlobalFilterUndoRequestedMsg{})
	f.m = next.(*Model)

	if got := len(f.m.filters.stack); got != 0 {
		t.Errorf("expected the undo to consume the Network level, %d level(s) left", got)
	}
	if len(f.applied) != 2 {
		t.Errorf("an undo to the filter already in effect reached the pipeline: %d swaps", len(f.applied))
	}
	if f.src.resetCalls != 2 || f.trie.resets != 2 {
		t.Errorf("an undo to the filter already in effect reset the aggregates: engine=%d trie=%d",
			f.src.resetCalls, f.trie.resets)
	}
	if got := f.m.dashboard.LatestSnapshot(); got != f.preSwap {
		t.Errorf("an undo to the filter already in effect replaced the snapshot on screen: %+v", got)
	}
	if got := trieTotal(t, f.trie); got != before {
		t.Errorf("an undo to the filter already in effect changed the trie total from %d to %d", before, got)
	}
}

// TestLiveFilterSwapDropsRefreshTickBuiltBeforeTheSwap: a refresh tick built
// from the pre-swap engine and delivered after the swap must not put the
// unfiltered numbers back on screen.
func TestLiveFilterSwapDropsRefreshTickBuiltBeforeTheSwap(t *testing.T) {
	f := newLiveSwapFixture(t)
	stale, ok := f.m.dashboard.SnapshotCmd()().(messages.StatsTickMsg)
	if !ok || stale.Snap != f.preSwap {
		t.Fatalf("precondition: expected a pre-swap refresh tick, got %+v", stale)
	}

	f.apply(t, commFilter("foo"))
	next, _ := f.m.Update(stale)
	f.m = next.(*Model)

	f.assertFreshBaseline(t, 1)
}
