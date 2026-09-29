package dashboard

import (
	"testing"
	"time"

	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
)

func TestNewTickSchedulerCadences(t *testing.T) {
	cases := []struct {
		name                  string
		refreshMs, fastMs     int
		wantRefresh, wantFast time.Duration
		wantStream, wantFlame time.Duration
	}{
		{"defaults", 0, 0, time.Second, 0, streamRefreshMs * time.Millisecond, flameRefreshMs * time.Millisecond},
		{"negative refresh", -5, 0, time.Second, 0, streamRefreshMs * time.Millisecond, flameRefreshMs * time.Millisecond},
		{"explicit", 250, 150, 250 * time.Millisecond, 150 * time.Millisecond, 150 * time.Millisecond, 150 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTickScheduler(tc.refreshMs, tc.fastMs)
			if s.refreshEvery != tc.wantRefresh {
				t.Errorf("refreshEvery = %v, want %v", s.refreshEvery, tc.wantRefresh)
			}
			if s.fastRefreshEvery != tc.wantFast {
				t.Errorf("fastRefreshEvery = %v, want %v", s.fastRefreshEvery, tc.wantFast)
			}
			if got := s.streamInterval(); got != tc.wantStream {
				t.Errorf("streamInterval = %v, want %v", got, tc.wantStream)
			}
			if got := s.flameInterval(); got != tc.wantFlame {
				t.Errorf("flameInterval = %v, want %v", got, tc.wantFlame)
			}
		})
	}
}

func TestTickSchedulerSetFastIntervalClampsNegative(t *testing.T) {
	s := newTickScheduler(1000, 200)
	s.setFastInterval(500 * time.Millisecond)
	if s.streamInterval() != 500*time.Millisecond || s.flameInterval() != 500*time.Millisecond {
		t.Fatalf("fast cadence not applied: stream %v flame %v", s.streamInterval(), s.flameInterval())
	}
	s.setFastInterval(-time.Millisecond)
	if s.fastRefreshEvery != 0 {
		t.Fatalf("negative fast cadence = %v, want 0", s.fastRefreshEvery)
	}
	if s.streamInterval() != streamRefreshMs*time.Millisecond {
		t.Fatalf("zero fast cadence must fall back to the stream constant, got %v", s.streamInterval())
	}
}

func TestTickSchedulerCommandsEmitTheirChainsMessage(t *testing.T) {
	s := newTickScheduler(1, 1)
	if _, ok := runCmd(s.refreshCmd()).(refreshTickMsg); !ok {
		t.Error("refreshCmd must emit refreshTickMsg")
	}
	if _, ok := runCmd(s.streamCmd()).(streamTickMsg); !ok {
		t.Error("streamCmd must emit streamTickMsg")
	}
	if _, ok := runCmd(s.flameCmd()).(flameTickMsg); !ok {
		t.Error("flameCmd must emit flameTickMsg")
	}
	if _, ok := runCmd(s.bubbleCmd()).(bubbleTickMsg); !ok {
		t.Error("bubbleCmd must emit bubbleTickMsg")
	}
}

func TestTabEntryTickCmdStartsTheTabsChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 1, common.DefaultKeyMap())
	if _, ok := runCmd(m.tabEntryTickCmd(TabFlame)).(flameTickMsg); !ok {
		t.Error("entering Flame must start the flame tick")
	}
	if _, ok := runCmd(m.tabEntryTickCmd(TabStream)).(streamTickMsg); !ok {
		t.Error("entering Stream must start the stream tick")
	}
	if cmd := m.tabEntryTickCmd(TabSyscalls); cmd != nil {
		t.Error("a table tab in table mode has no chain of its own")
	}
	m.syscallsTab.mode = tabVizModeBubbles
	if _, ok := runCmd(m.tabEntryTickCmd(TabSyscalls)).(bubbleTickMsg); !ok {
		t.Error("a table tab in bubbles mode must start the bubble animation")
	}
}

// TestTickHandlersLetUnwantedChainsDie pins the chain-ending side of the
// scheduler: a tick that arrives while blurred or for a tab that is no
// longer active is dropped without re-arming, so no chain outlives its use.
func TestTickHandlersLetUnwantedChainsDie(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 1, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	if _, cmd := m.Update(streamTickMsg{}); cmd != nil {
		t.Error("a stream tick off the Stream tab must not re-arm")
	}
	if _, cmd := m.Update(flameTickMsg{}); cmd != nil {
		t.Error("a flame tick off the Flame tab must not re-arm")
	}
	if _, cmd := m.Update(bubbleTickMsg{}); cmd != nil {
		t.Error("a bubble tick without an active bubble chart must not re-arm")
	}
	m.SetFocused(false)
	if _, cmd := m.Update(refreshTickMsg{}); cmd != nil {
		t.Error("a refresh tick while blurred must not re-arm")
	}
}

// TestStaleAutoResetTickAfterIntervalChangeIsDropped pins the generation
// guard at the model level: the tick scheduled under the previous cadence
// arrives after the change and must neither reset nor re-arm.
func TestStaleAutoResetTickAfterIntervalChangeIsDropped(t *testing.T) {
	engine := &fakeSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 1000, 200, common.DefaultKeyMap())
	m.SetAutoResetInterval(30 * time.Second)
	stale := m.autoReset.gen
	m.SetAutoResetInterval(time.Minute)

	if _, cmd := m.Update(autoResetTickMsg{generation: stale}); cmd != nil {
		t.Fatal("a stale auto-reset tick must not re-arm")
	}
	if engine.resetCount != 0 {
		t.Fatalf("a stale auto-reset tick reset the engine %d times", engine.resetCount)
	}
}

// startChains delivers Init's tick chain start and returns the commands it
// scheduled, without running them.
func startChains(t *testing.T, m *Model) tea.BatchMsg {
	t.Helper()
	_, cmd := m.Update(tickChainsStartMsg{})
	// tea.Batch yields its member list without running the members, so
	// this never waits on a timer.
	batch, ok := runCmd(cmd).(tea.BatchMsg)
	if !ok {
		t.Fatal("a focused chain start must schedule a batch of ticks")
	}
	return batch
}

// TestDoubleInitLeavesOneChainOfEachKind covers two Inits whose chain starts
// are both handled (a focus regain followed by a trace start): the second
// start supersedes the first, so the first chains' ticks are dropped without
// rescheduling and only the second chains keep running.
func TestDoubleInitLeavesOneChainOfEachKind(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	first := startChains(t, m)
	firstRefresh, firstFast := m.ticks.refresh.gen, m.ticks.fast.gen
	second := startChains(t, m)
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("chain starts scheduled %d and %d commands, want refresh and flame", len(first), len(second))
	}
	if m.ticks.refresh.gen == firstRefresh || m.ticks.fast.gen == firstFast {
		t.Fatal("the second start must supersede the first chains")
	}

	for _, stale := range []tea.Msg{
		refreshTickMsg{generation: firstRefresh},
		flameTickMsg{generation: firstFast},
	} {
		if _, cmd := m.Update(stale); cmd != nil {
			t.Errorf("stale %T was rescheduled", stale)
		}
	}
	for _, live := range []tea.Msg{
		refreshTickMsg{generation: m.ticks.refresh.gen},
		flameTickMsg{generation: m.ticks.fast.gen},
	} {
		if _, cmd := m.Update(live); cmd == nil {
			t.Errorf("live %T was not re-armed", live)
		}
	}
	// The first start's own flame tick carries the superseded generation.
	if msg, ok := runCmd(first[1]).(flameTickMsg); !ok || msg.generation != firstFast {
		t.Fatalf("first start's flame tick = %#v, want generation %d", runCmd(first[1]), firstFast)
	}
}

// TestChainStartWhileBlurredSchedulesNothing: a blurred dashboard still
// supersedes the running chains (their ticks would be dropped anyway) but
// starts none; focus regain requests a fresh start.
func TestChainStartWhileBlurredSchedulesNothing(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	m.SetFocused(false)
	gen := m.ticks.refresh.gen
	if _, cmd := m.Update(tickChainsStartMsg{}); cmd != nil {
		t.Fatal("a blurred chain start must schedule nothing")
	}
	if m.ticks.refresh.gen == gen {
		t.Fatal("a blurred chain start must still supersede the running chains")
	}
}

// TestTabReentrySupersedesFastChain covers leaving the Flame tab and coming
// back before its in-flight tick arrives: the re-entry starts a new chain,
// so the old tick is dropped instead of running a second chain.
func TestTabReentrySupersedesFastChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	old := m.ticks.fast.gen
	m = pressKey(m, '2')
	m = pressKey(m, '1')
	if m.activeTab != TabFlame {
		t.Fatalf("active tab = %v, want Flame", m.activeTab)
	}
	if _, cmd := m.Update(flameTickMsg{generation: old}); cmd != nil {
		t.Fatal("the pre-switch flame tick must be dropped")
	}
	if _, cmd := m.Update(flameTickMsg{generation: m.ticks.fast.gen}); cmd == nil {
		t.Fatal("the re-entry chain's tick must re-arm")
	}
}

// TestStreamResumeSupersedesFastChain: the stream chain keeps ticking while
// paused, so resuming restarts it rather than adding a second chain.
func TestStreamResumeSupersedesFastChain(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	m.activeTab = TabStream
	space := tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	m.Update(space) // pause
	old := m.ticks.fast.gen
	if _, cmd := m.Update(streamTickMsg{generation: old}); cmd == nil {
		t.Fatal("the stream chain must keep ticking while paused")
	}
	m.Update(space) // resume
	if m.ticks.fast.gen == old {
		t.Fatal("resuming must start a new stream chain")
	}
	if _, cmd := m.Update(streamTickMsg{generation: old}); cmd != nil {
		t.Fatal("the pre-resume stream tick must be dropped")
	}
}

// TestBubbleRestartDropsStaleFrames: every bubble chain start (a stats
// tick, a viz or metric change) supersedes the running animation chain.
func TestBubbleRestartDropsStaleFrames(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsTab.mode = tabVizModeBubbles
	old := m.ticks.bubble.gen
	if cmd := m.ticks.startBubble(); cmd == nil {
		t.Fatal("startBubble must schedule a frame")
	}
	if m.ticks.bubble.gen == old {
		t.Fatal("startBubble must supersede the running chain")
	}
	if _, cmd := m.Update(bubbleTickMsg{generation: old}); cmd != nil {
		t.Fatal("a frame of the superseded bubble chain must be dropped")
	}
}
