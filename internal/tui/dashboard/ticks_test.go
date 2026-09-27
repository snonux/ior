package dashboard

import (
	"testing"
	"time"

	common "ior/internal/tui/common"
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
