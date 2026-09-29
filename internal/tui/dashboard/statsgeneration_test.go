package dashboard

import (
	"errors"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// newGenerationModel returns a dashboard showing the pre-reset snapshot and a
// refresh tick built from it before any reset: the one a reset must outrun.
func newGenerationModel(t *testing.T) (*Model, *fakeSnapshotSource, messages.StatsTickMsg) {
	t.Helper()
	src := &fakeSnapshotSource{
		snap:      &statsengine.Snapshot{TotalSyscalls: 99},
		resetSnap: &statsengine.Snapshot{TotalSyscalls: 0},
	}
	m := NewModelWithConfig(src, nil, 250, 200, common.DefaultKeyMap())
	// The Flame tab claims `r` for itself; the stats tabs route it to the
	// baseline reset.
	m.activeTab = TabOverview
	stale := m.statsTick()
	if stale.Generation == 0 {
		t.Fatal("precondition: ticks built by the dashboard must be versioned")
	}
	m.Update(stale)
	if got := m.LatestSnapshot(); got != src.snap {
		t.Fatalf("precondition: expected the pre-reset snapshot on screen, got %+v", got)
	}
	return m, src, stale
}

func assertPostReset(t *testing.T, m *Model, src *fakeSnapshotSource) {
	t.Helper()
	if got := m.LatestSnapshot(); got != src.resetSnap {
		t.Fatalf("a tick built before the reset restored the old numbers: got %+v", got)
	}
}

// TestResetStatsDropsTickBuiltBeforeTheReset: a refresh tick built just before
// a reset can be delivered after the post-reset snapshot was applied. It must
// not put the pre-reset numbers back for a whole refresh interval.
func TestResetStatsDropsTickBuiltBeforeTheReset(t *testing.T) {
	m, src, stale := newGenerationModel(t)

	m.ResetStats()
	assertPostReset(t, m, src)
	if src.resetCount != 1 {
		t.Fatalf("expected one engine reset, got %d", src.resetCount)
	}

	m.Update(stale)
	assertPostReset(t, m, src)
}

// TestBaselineResetKeyDropsTickBuiltBeforeTheReset covers the `r` key (and
// with it auto-reset, which shares resetBaselineCmd).
func TestBaselineResetKeyDropsTickBuiltBeforeTheReset(t *testing.T) {
	m, src, stale := newGenerationModel(t)

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	if cmd == nil {
		t.Fatal("expected the reset key to return the post-reset tick")
	}
	fresh, ok := cmd().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected a StatsTickMsg from the reset key")
	}
	// Worst case ordering: the stale tick lands after the fresh one.
	m.Update(fresh)
	m.Update(stale)
	assertPostReset(t, m, src)
}

// TestTraceRestartDropsTickFromThePreviousSession: a tick from the old engine
// still in flight across a restart must not repopulate the cleared view.
func TestTraceRestartDropsTickFromThePreviousSession(t *testing.T) {
	m, _, stale := newGenerationModel(t)

	m.PrepareForTraceRestart()
	m.Update(stale)
	if got := m.LatestSnapshot(); got != nil {
		t.Fatalf("a tick from the previous trace session repopulated the view: %+v", got)
	}
}

// TestCurrentGenerationAndUnversionedTicksStillApply guards the other side:
// the generation check must drop only stale ticks, never the regular refresh
// of the current generation or a tick built outside the dashboard.
func TestCurrentGenerationAndUnversionedTicksStillApply(t *testing.T) {
	m, src, _ := newGenerationModel(t)
	m.ResetStats()

	src.snap = &statsengine.Snapshot{TotalSyscalls: 7}
	current := m.statsTick()
	m.Update(current)
	if got := m.LatestSnapshot(); got != src.snap {
		t.Fatalf("a current-generation tick was dropped: got %+v", got)
	}

	external := &statsengine.Snapshot{TotalSyscalls: 11}
	m.Update(messages.StatsTickMsg{Snap: external})
	if got := m.LatestSnapshot(); got != external {
		t.Fatalf("an unversioned tick was dropped: got %+v", got)
	}
}

// TestResetStatsKeepsLastGoodSnapshotOnFailure: the generation still
// advances on a failed post-reset snapshot, so the stale tick is dropped, but
// the failure itself keeps the last good snapshot on screen.
func TestResetStatsKeepsLastGoodSnapshotOnFailure(t *testing.T) {
	m, src, stale := newGenerationModel(t)
	good := src.snap
	src.err = errors.New("snapshot build failed")

	m.ResetStats()
	if got := m.LatestSnapshot(); got != good {
		t.Fatalf("a failed post-reset snapshot replaced the last good one: got %+v", got)
	}
	if src.resetCount != 1 {
		t.Fatalf("expected the engine to be reset even when the snapshot fails, got %d", src.resetCount)
	}

	stale.Snap = &statsengine.Snapshot{TotalSyscalls: 12345}
	m.Update(stale)
	if got := m.LatestSnapshot(); got != good {
		t.Fatalf("a pre-reset tick was applied after a failed reset: got %+v", got)
	}
}
