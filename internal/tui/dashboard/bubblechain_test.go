package dashboard

import (
	"testing"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// These tests pin every path that restarts the bubble tick chain after it has
// gone quiet. The chain ends by itself once the chart settles (see
// handleBubbleTick), so each trigger that changes what the chart shows must
// start it again or the picture freezes. Every test drives the real
// Model.Update with the real message or key and looks at the returned command,
// so removing a startBubble call from a handler fails exactly one of them.

// msgsOf runs cmd and returns the messages it produces, flattening batches.
// Each command runs in its own goroutine and stragglers are abandoned after a
// second, so a command that blocks (a tick with a long cadence) cannot hang
// the test.
func msgsOf(cmd tea.Cmd) []tea.Msg {
	if cmd == nil {
		return nil
	}
	out := make(chan tea.Msg, 1)
	go func() { out <- cmd() }()
	select {
	case msg := <-out:
		if batch, ok := msg.(tea.BatchMsg); ok {
			var all []tea.Msg
			for _, c := range batch {
				all = append(all, msgsOf(c)...)
			}
			return all
		}
		return []tea.Msg{msg}
	case <-time.After(time.Second):
		return nil
	}
}

// startsBubbleChain reports whether cmd schedules a bubble animation frame of
// the model's live chain generation (a tick of an older generation would be
// dropped, so it does not count as a restart).
func startsBubbleChain(m *Model, cmd tea.Cmd) bool {
	for _, msg := range msgsOf(cmd) {
		if tick, ok := msg.(bubbleTickMsg); ok && m.ticks.bubble.isCurrent(tick.generation) {
			return true
		}
	}
	return false
}

func syscallSnap(read, write uint64, readBytes, writeBytes uint64) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: read, Bytes: readBytes},
		{Name: "write", Count: write, Bytes: writeBytes},
		{Name: "openat", Count: 5, Bytes: 0},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return &snap
}

func updateModel(m *Model, msg tea.Msg) (*Model, tea.Cmd) {
	next, cmd := m.Update(msg)
	return next.(*Model), cmd
}

// settleBubbleChain feeds the live chain's ticks through Update until the
// handler stops re-arming it, failing when it never does.
func settleBubbleChain(t *testing.T, m *Model) {
	t.Helper()
	for range 30 * 30 {
		if _, cmd := m.Update(bubbleTickMsg{generation: m.ticks.bubble.gen}); cmd == nil {
			return
		}
	}
	t.Fatal("bubble tick chain never ended")
}

// settledSyscallBubbles returns a model on the Syscalls tab in bubbles mode
// whose chart holds snap and whose tick chain has ended.
func settledSyscallBubbles(t *testing.T, snap *statsengine.Snapshot) *Model {
	t.Helper()
	m := NewModelWithConfig(nil, nil, 1, 1, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsTab.mode = tabVizModeBubbles
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	m, cmd := updateModel(m, messages.StatsTickMsg{Snap: snap})
	if !startsBubbleChain(m, cmd) {
		t.Fatal("first data must start the chain")
	}
	settleBubbleChain(t, m)
	return m
}

func TestStatsTickRestartsSettledBubbleChainOnlyOnChange(t *testing.T) {
	base := syscallSnap(90, 30, 10, 10)
	m := settledSyscallBubbles(t, base)

	if _, cmd := m.Update(messages.StatsTickMsg{Snap: base}); startsBubbleChain(m, cmd) {
		t.Fatal("an unchanged snapshot restarted the chain")
	}
	m, cmd := updateModel(m, messages.StatsTickMsg{Snap: syscallSnap(30, 90, 10, 10)})
	if !startsBubbleChain(m, cmd) {
		t.Fatal("a snapshot that reshapes the bubbles must restart the chain")
	}
	settleBubbleChain(t, m)
	// A hidden tab's data changing must not run the active tab's animation.
	m.activeTab = TabOverview
	if _, cmd := m.Update(messages.StatsTickMsg{Snap: syscallSnap(90, 30, 10, 10)}); startsBubbleChain(m, cmd) {
		t.Fatal("stats tick on a tab without bubbles started the chain")
	}
}

func TestWindowSizeRestartsSettledBubbleChainOnlyOnChange(t *testing.T) {
	m := settledSyscallBubbles(t, syscallSnap(90, 30, 10, 10))

	if _, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40}); startsBubbleChain(m, cmd) {
		t.Fatal("a resize to the same size restarted the chain")
	}
	m, cmd := updateModel(m, tea.WindowSizeMsg{Width: 80, Height: 30})
	if !startsBubbleChain(m, cmd) {
		t.Fatal("a real resize must restart the chain")
	}
}

func TestVisualizeKeyStartsBubbleChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1, 1, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 40})

	// No snapshot: nothing to animate, so entering bubbles mode starts no chain.
	if m, cmd := updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"}); startsBubbleChain(m, cmd) {
		t.Fatal("entering bubbles mode without data started the chain")
	}
	m, _ = updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"}) // treemap
	m, _ = updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"}) // table
	m, _ = updateModel(m, messages.StatsTickMsg{Snap: syscallSnap(90, 30, 10, 10)})

	m, cmd := updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"})
	if m.syscallsTab.mode != tabVizModeBubbles || !startsBubbleChain(m, cmd) {
		t.Fatalf("v into bubbles mode: mode %v, chain started %v", m.syscallsTab.mode, startsBubbleChain(m, cmd))
	}
	settleBubbleChain(t, m)
	m, cmd = updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"})
	if m.syscallsTab.mode == tabVizModeBubbles || startsBubbleChain(m, cmd) {
		t.Fatal("leaving bubbles mode must not start the bubble chain")
	}
}

func TestMetricKeyRestartsSettledBubbleChain(t *testing.T) {
	// Count and bytes rank the syscalls differently, so the bubbles move.
	m := settledSyscallBubbles(t, syscallSnap(90, 30, 10, 5000))

	m, cmd := updateModel(m, tea.KeyPressMsg{Code: 'b', Text: "b"})
	if m.syscallsTab.bubble.Metric() == bubbleMetricCount {
		t.Fatal("the metric key did not change the metric")
	}
	if !startsBubbleChain(m, cmd) {
		t.Fatal("changing the bubble metric must restart the chain")
	}
}

func TestMetricKeyWithoutBubblesStartsNoChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1, 1, common.DefaultKeyMap())
	m.activeTab = TabFiles // dir grouping off: the alternative views are unavailable
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	if _, cmd := m.Update(tea.KeyPressMsg{Code: 'b', Text: "b"}); startsBubbleChain(m, cmd) {
		t.Fatal("metric key on an unavailable view started the chain")
	}
}

// TestDirGroupingToggleNeverNeedsABubbleChain documents why toggling the Files
// directory grouping has no bubble-restart trigger: bubbles mode exists only
// while grouped, and leaving grouped mode resets the mode to the table, so the
// toggle can never land on a visible bubble chart. (The chart is fed by the
// next stats tick and by entering bubbles mode, both covered above.)
func TestDirGroupingToggleNeverNeedsABubbleChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1, 1, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m, _ = updateModel(m, tea.WindowSizeMsg{Width: 120, Height: 40})
	for range 2 {
		m, cmd := updateModel(m, tea.KeyPressMsg{Code: 'd', Text: "d"})
		if m.filesTab.mode != tabVizModeTable || startsBubbleChain(m, cmd) {
			t.Fatalf("after d: mode %v, chain started %v", m.filesTab.mode, startsBubbleChain(m, cmd))
		}
		if m.filesDirGrouped {
			m, _ = updateModel(m, tea.KeyPressMsg{Code: 'v', Text: "v"})
			if m.filesTab.mode != tabVizModeBubbles {
				t.Fatalf("grouped v did not reach bubbles: mode %v", m.filesTab.mode)
			}
		}
	}
	if m.filesDirGrouped || m.filesTab.mode != tabVizModeTable {
		t.Fatalf("leaving directory mode must reset to the table (grouped %v mode %v)", m.filesDirGrouped, m.filesTab.mode)
	}
}

// TestFocusRegainRestartsSettledBubbleChain: a blurred dashboard drops its
// ticks, so the chain is dead when focus returns; the parent then calls Init,
// whose tickChainsStartMsg must start the bubble chain again.
func TestFocusRegainRestartsSettledBubbleChain(t *testing.T) {
	m := settledSyscallBubbles(t, syscallSnap(90, 30, 10, 10))
	oldGen := m.ticks.bubble.gen

	m.SetFocused(false)
	if _, cmd := m.Update(tickChainsStartMsg{}); startsBubbleChain(m, cmd) {
		t.Fatal("a blurred dashboard started the bubble chain")
	}
	m.SetFocused(true)
	restarted := false
	for _, msg := range msgsOf(m.Init()) {
		if _, ok := msg.(tickChainsStartMsg); !ok {
			continue
		}
		_, cmd := m.Update(msg)
		restarted = startsBubbleChain(m, cmd)
	}
	if !restarted {
		t.Fatal("Init after a focus regain must restart the bubble chain")
	}
	if m.ticks.bubble.gen == oldGen {
		t.Fatal("restart must supersede the old chain's generation")
	}
	// The pre-blur tick is stale now: it must not run alongside the new chain.
	if _, cmd := m.Update(bubbleTickMsg{generation: oldGen}); cmd != nil {
		t.Fatal("a tick of the superseded chain re-armed itself")
	}
}

// TestBubbleChainRunsWhileDataKeepsChangingThenSettles pins the documented
// limit of the idle saving: every real change (a bubble moved or resized past
// bubbleRetargetEpsilon, or a bubble added/removed) restarts the drift wobble
// for bubbleDriftSeconds, so a workload whose counters reshuffle the bubbles on
// every 1s stats tick keeps the 30fps chain alive. Only a quiet workload
// settles. (The per-frame cost, not the frame rate, is what shrank: see
// BenchmarkBubbleTickAndView.)
func TestBubbleChainRunsWhileDataKeepsChangingThenSettles(t *testing.T) {
	a, b := syscallSnap(90, 30, 10, 10), syscallSnap(30, 90, 10, 10)
	m := settledSyscallBubbles(t, a)

	const framesPerStatsTick = bubbleFPS // one stats tick per second
	for round := range 20 {
		snap := a
		if round%2 == 0 {
			snap = b
		}
		var cmd tea.Cmd
		m, cmd = updateModel(m, messages.StatsTickMsg{Snap: snap})
		if !startsBubbleChain(m, cmd) {
			t.Fatalf("round %d: a reshuffled snapshot did not restart the chain", round)
		}
		for frame := range framesPerStatsTick {
			if _, cmd := m.Update(bubbleTickMsg{generation: m.ticks.bubble.gen}); cmd == nil {
				t.Fatalf("round %d frame %d: chain ended while data keeps changing every second", round, frame)
			}
		}
	}
	// The same data from now on: the chain ends within the drift window plus
	// the spring settle time, and stays ended.
	frames := 0
	for ; frames < 12*bubbleFPS; frames++ {
		if _, cmd := m.Update(bubbleTickMsg{generation: m.ticks.bubble.gen}); cmd == nil {
			break
		}
	}
	if frames == 12*bubbleFPS {
		t.Fatal("chain still running 12s after the data stopped changing")
	}
	// The last round fed a; feeding it again changes nothing.
	if _, cmd := m.Update(messages.StatsTickMsg{Snap: a}); startsBubbleChain(m, cmd) {
		t.Fatal("re-sending the settled snapshot restarted the chain")
	}
}
