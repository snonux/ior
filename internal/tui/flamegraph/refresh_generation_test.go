package flamegraph

import (
	"errors"
	"testing"

	coreflamegraph "ior/internal/flamegraph"

	tea "charm.land/bubbletea/v2"
)

// newGenerationTestModel returns a model bound to a seeded live trie whose
// fields match a built-in preset, so the order key cycles cleanly.
func newGenerationTestModel(t *testing.T) (*Model, *coreflamegraph.LiveTrie) {
	t.Helper()
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "")
	coreflamegraph.SeedTestLiveFlameData(trie, 0)
	m := NewModel(trie)
	m.width = 120
	m.height = 30
	return m, trie
}

// dispatchAndCompute starts a background refresh through the production
// command and runs the job to completion, returning its undelivered result.
// Computing before the caller changes model state reproduces a job that
// snapshotted the trie before that change.
func dispatchAndCompute(t *testing.T, m *Model) flameSnapshotReadyMsg {
	t.Helper()
	cmd := m.RefreshFromLiveTrieCmd()
	if cmd == nil {
		t.Fatal("expected a background refresh to dispatch")
	}
	ready, ok := cmd().(flameSnapshotReadyMsg)
	if !ok {
		t.Fatal("refresh command did not return a flameSnapshotReadyMsg")
	}
	if ready.snapshot == nil {
		t.Fatal("refresh job returned no snapshot")
	}
	return ready
}

// deliver routes msg through the real Update loop.
func deliver(t *testing.T, m *Model, msg tea.Msg) *Model {
	t.Helper()
	next, _ := m.Update(msg)
	return next.(*Model)
}

func runeKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: r, Text: string(r)}
}

// TestStateChangeDropsInFlightRefreshResult covers every key that starts a
// new baseline: a result computed for the previous state must never be
// applied, the job must still release its slot, and the next refresh must
// load the new state.
func TestStateChangeDropsInFlightRefreshResult(t *testing.T) {
	cases := []struct {
		name string
		key  rune
	}{
		{name: "reset baseline", key: 'r'},
		{name: "cycle field order", key: 'o'},
		{name: "cycle count metric", key: 'b'},
		{name: "toggle height metric", key: 'v'},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, trie := newGenerationTestModel(t)
			stale := dispatchAndCompute(t, m)

			m = deliver(t, m, runeKey(tc.key))
			if m.statusMessage == "" {
				t.Fatalf("key %q did not change snapshot state", tc.key)
			}
			if stale.generation == m.refreshGeneration {
				t.Fatalf("key %q did not invalidate the in-flight refresh", tc.key)
			}
			// The stale job still owns the slot: no overlapping refresh.
			if cmd := m.RefreshFromLiveTrieCmd(); cmd != nil {
				t.Fatal("a second refresh dispatched while the stale job was still running")
			}

			m = deliver(t, m, stale)
			if m.HasSnapshot() {
				t.Fatal("stale refresh result was applied after the state change")
			}
			if len(m.frames) != 0 {
				t.Fatalf("stale refresh result laid out %d frames", len(m.frames))
			}
			if got := m.LastVersion(); got != 0 {
				t.Fatalf("stale refresh result applied version %d", got)
			}
			if m.refreshInFlight {
				t.Fatal("stale completion did not release its in-flight slot")
			}

			coreflamegraph.SeedTestLiveFlameData(trie, 1)
			fresh := dispatchAndCompute(t, m)
			m = deliver(t, m, fresh)
			if m.snapshot != fresh.snapshot {
				t.Fatal("fresh refresh result for the new state was not applied")
			}
			if got, want := m.LastVersion(), fresh.version; got != want {
				t.Fatalf("LastVersion = %d, want %d", got, want)
			}
			if m.refreshInFlight {
				t.Fatal("fresh completion did not release its in-flight slot")
			}
		})
	}
}

// TestPausedResetDoesNotFreezeStaleRefresh is the paused variant: before the
// fix the pre-reset result was applied and then frozen by the pause guard,
// because the guard only engages once a snapshot exists.
func TestPausedResetDoesNotFreezeStaleRefresh(t *testing.T) {
	m, trie := newGenerationTestModel(t)
	stale := dispatchAndCompute(t, m)

	m = deliver(t, m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if !m.Paused() {
		t.Fatal("space did not pause the flamegraph")
	}
	m = deliver(t, m, runeKey('r'))

	m = deliver(t, m, stale)
	if m.HasSnapshot() {
		t.Fatal("pre-reset refresh result was applied while paused")
	}

	coreflamegraph.SeedTestLiveFlameData(trie, 2)
	fresh := dispatchAndCompute(t, m)
	m = deliver(t, m, fresh)
	if m.snapshot != fresh.snapshot {
		t.Fatal("paused model did not load the post-reset baseline")
	}

	// Once the new baseline exists, pause freezes it again.
	coreflamegraph.SeedTestLiveFlameData(trie, 3)
	if cmd := m.RefreshFromLiveTrieCmd(); cmd != nil {
		t.Fatal("paused model dispatched a refresh after loading the new baseline")
	}
}

// TestLateStaleCompletionCannotReleaseNewerRefresh redelivers a superseded
// result out of order, both while the newer job is running and after it
// landed. Neither delivery may free the newer job's slot or replace its data.
func TestLateStaleCompletionCannotReleaseNewerRefresh(t *testing.T) {
	m, trie := newGenerationTestModel(t)
	stale := dispatchAndCompute(t, m)
	m = deliver(t, m, runeKey('r'))
	m = deliver(t, m, stale)

	coreflamegraph.SeedTestLiveFlameData(trie, 1)
	fresh := dispatchAndCompute(t, m)

	m = deliver(t, m, stale)
	if !m.refreshInFlight {
		t.Fatal("late stale completion released the newer job's in-flight slot")
	}
	if cmd := m.RefreshFromLiveTrieCmd(); cmd != nil {
		t.Fatal("late stale completion let a refresh overlap the running job")
	}
	if m.HasSnapshot() {
		t.Fatal("late stale completion applied its result")
	}

	m = deliver(t, m, fresh)
	if m.snapshot != fresh.snapshot {
		t.Fatal("newer job's result was not applied")
	}

	m = deliver(t, m, stale)
	if m.snapshot != fresh.snapshot {
		t.Fatal("stale completion delivered after the newer result replaced it")
	}
	if got, want := m.LastVersion(), fresh.version; got != want {
		t.Fatalf("LastVersion = %d after stale redelivery, want %d", got, want)
	}
}

// TestDashboardCompletionDropsStaleRefresh drives the dashboard entry point:
// applied or discarded (hidden tab), a superseded result is never shown and
// its job always frees the slot.
func TestDashboardCompletionDropsStaleRefresh(t *testing.T) {
	for _, apply := range []bool{true, false} {
		m, _ := newGenerationTestModel(t)
		stale := dispatchAndCompute(t, m)
		m = deliver(t, m, runeKey('o'))

		handled, cmd := m.HandleRefreshCompletion(stale, apply)
		if !handled {
			t.Fatalf("apply=%v: stale completion was not recognized", apply)
		}
		if cmd != nil {
			t.Fatalf("apply=%v: stale completion scheduled a command", apply)
		}
		if m.HasSnapshot() {
			t.Fatalf("apply=%v: stale completion applied its result", apply)
		}
		if m.refreshInFlight {
			t.Fatalf("apply=%v: stale completion did not release its slot", apply)
		}
	}
}

// TestFailedStateChangeKeepsInFlightRefreshCurrent is the negative case: a
// metric toggle the trie rejects leaves the state untouched, so the running
// job's result is still valid and must be applied.
func TestFailedStateChangeKeepsInFlightRefreshCurrent(t *testing.T) {
	base := coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", "")
	coreflamegraph.SeedTestLiveFlameData(base, 0)
	m := NewModel(&setHeightErrorTrie{LiveTrie: base, err: errors.New("set-height failed")})
	m.width = 120
	m.height = 30

	ready := dispatchAndCompute(t, m)
	generation := m.refreshGeneration
	m = deliver(t, m, runeKey('v'))
	if m.refreshGeneration != generation {
		t.Fatal("rejected height toggle invalidated the in-flight refresh")
	}

	m = deliver(t, m, ready)
	if m.snapshot != ready.snapshot {
		t.Fatal("in-flight result was dropped although the state did not change")
	}
	if m.refreshInFlight {
		t.Fatal("completion did not release its in-flight slot")
	}
}
