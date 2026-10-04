package dashboard

import (
	"sync/atomic"

	tea "charm.land/bubbletea/v2"

	"ior/internal/tui/messages"
)

// Building the stats snapshot is not free: with stale latency reservoirs
// (startup, and after every auto-reset) the percentile selection costs about
// 3ms at 20 active syscalls, 9ms at 60 and 22ms at 150. Update runs on the
// Bubble Tea event loop, so doing that inline stalls every key press and
// redraw behind it. The refresh path therefore only captures the engine and
// the stats generation in Update and lets a tea.Cmd (which Bubble Tea runs on
// its own goroutine) call Snapshot; the result comes back as a StatsTickMsg
// whose generation check (handleStatsTick) already drops a snapshot built
// before a reset. Snapshot is safe to call off the UI goroutine: the engine
// captures its state under its own lock and resolves the percentiles outside
// it (exporters call it from other goroutines as well).
//
// Known and accepted: a refresh command and a SnapshotCmd/reset command run on
// separate goroutines and can deliver out of order within one generation, so
// an older snapshot may be shown in place of a newer one for at most one
// refresh interval, until the next refresh replaces it. Only a reset needs
// strict ordering, and the generation check provides that.

// buildStatsTick asks engine for a snapshot and wraps the outcome as the
// StatsTickMsg of stats generation gen. Without an engine it carries a nil
// snapshot and no error; a failed Snapshot is reported through Err so
// handleStatsTick keeps the last successful snapshot. It touches no Model
// state, so it may run on any goroutine.
func buildStatsTick(engine SnapshotSource, gen uint64) messages.StatsTickMsg {
	if engine == nil {
		return messages.StatsTickMsg{Generation: gen}
	}
	snap, err := engine.Snapshot()
	if err != nil {
		return messages.StatsTickMsg{Err: err, Generation: gen}
	}
	return messages.StatsTickMsg{Snap: snap, Generation: gen}
}

// statsTick builds the snapshot synchronously, on the caller's goroutine. It
// is for the paths that must have the post-reset snapshot in hand before they
// return (ResetStats, whose engine was just cleared so the build is cheap)
// and for tests; the periodic refresh uses statsTickCmd instead.
func (m *Model) statsTick() messages.StatsTickMsg {
	return buildStatsTick(m.engine, m.statsGen)
}

// statsTickCmd returns a command that builds the snapshot off the UI
// goroutine. The engine and the generation are captured now, on the UI
// goroutine, so the message is versioned with the generation the request was
// made in even when a reset happens before the command runs: the reset bumps
// the model's generation and the stale message is dropped on arrival.
func (m *Model) statsTickCmd() tea.Cmd {
	engine, gen := m.engine, m.statsGen
	return func() tea.Msg { return buildStatsTick(engine, gen) }
}

// refreshStatsCmd is the periodic refresh's snapshot request. It returns nil
// while the previous refresh is still building: a build slower than the
// refresh cadence (heavy load, a huge syscall set) must not pile up
// overlapping builds that all recompute the same reservoirs, and a skipped
// tick just makes the next one carry the fresher data. The busy flag is
// released by the command itself, when its build ends, and not when the
// message is delivered: a result the router never hands to the dashboard
// (another screen owns the routing) can then not leave the refresh disabled
// for good.
func (m *Model) refreshStatsCmd() tea.Cmd {
	if m.refreshBuilding == nil {
		m.refreshBuilding = new(atomic.Bool)
	}
	busy, engine, gen := m.refreshBuilding, m.engine, m.statsGen
	if !busy.CompareAndSwap(false, true) {
		return nil
	}
	return func() tea.Msg {
		defer busy.Store(false)
		return buildStatsTick(engine, gen)
	}
}
