package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
	"ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

// countingStreamSource is a stream Source that records how often the stream
// model re-snapshots it. It deliberately implements only the plain Source
// contract (no AppendSnapshot), so every Refresh goes through Snapshot and
// is counted.
type countingStreamSource struct {
	rb        *eventstream.RingBuffer
	snapshots int
}

func (s *countingStreamSource) Len() int { return s.rb.Len() }

func (s *countingStreamSource) Snapshot() []eventstream.StreamEvent {
	s.snapshots++
	return s.rb.Snapshot()
}

func newStreamRefreshModel(t *testing.T, tab Tab) (*Model, *countingStreamSource) {
	t.Helper()
	src := &countingStreamSource{rb: eventstream.NewRingBuffer()}
	src.rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "early"})
	m := NewModelWithConfig(nil, src, 250, 200, common.DefaultKeyMap())
	m.activeTab = tab
	next, _ := m.Update(tea.WindowSizeMsg{Width: 140, Height: 30})
	return next.(*Model), src
}

func sendStatsTick(t *testing.T, m *Model) *Model {
	t.Helper()
	next, _ := m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{TotalSyscalls: 1}})
	return next.(*Model)
}

// TestStatsTickSkipsHiddenStreamRefresh pins the perf fix: a stats tick must
// not re-snapshot and re-filter the stream ring buffer while the Stream tab
// is hidden, but still does so while it is the active tab.
func TestStatsTickSkipsHiddenStreamRefresh(t *testing.T) {
	m, src := newStreamRefreshModel(t, TabOverview)
	before := src.snapshots
	for range 3 {
		m = sendStatsTick(t, m)
	}
	if got := src.snapshots - before; got != 0 {
		t.Fatalf("hidden Stream tab was refreshed %d times by stats ticks, want 0", got)
	}

	m.activeTab = TabStream
	before = src.snapshots
	sendStatsTick(t, m)
	if got := src.snapshots - before; got != 1 {
		t.Fatalf("active Stream tab refreshed %d times by one stats tick, want 1", got)
	}
}

// TestEnteringStreamTabRefreshesImmediately verifies that skipping hidden
// refreshes never leaves the stream stale: events pushed while another tab
// was active are visible as soon as the Stream tab is entered, both via its
// numeric shortcut and via tab cycling, without waiting for a tick.
func TestEnteringStreamTabRefreshesImmediately(t *testing.T) {
	for _, tc := range []struct {
		name  string
		start Tab
		key   tea.KeyPressMsg
	}{
		{name: "numeric shortcut", start: TabOverview, key: tea.KeyPressMsg{Code: '7', Text: "7"}},
		{name: "tab cycling", start: prevTab(TabStream), key: tea.KeyPressMsg{Code: tea.KeyTab}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, src := newStreamRefreshModel(t, tc.start)
			m = sendStatsTick(t, m)
			src.rb.Push(eventstream.StreamEvent{Seq: 2, Syscall: "write", Comm: "latecomer"})

			before := src.snapshots
			next, _ := m.Update(tc.key)
			m = next.(*Model)
			if m.activeTab != TabStream {
				t.Fatalf("active tab = %v, want Stream", m.activeTab)
			}
			if got := src.snapshots - before; got != 1 {
				t.Fatalf("entering the Stream tab refreshed %d times, want 1", got)
			}
			if out := m.View().Content; !strings.Contains(out, "latecomer") {
				t.Fatalf("stream is stale after entering the tab: event pushed while hidden is missing:\n%s", out)
			}
		})
	}
}

// TestLeavingStreamTabDoesNotRefresh is the negative case: switching away
// from the Stream tab (or between two other tabs) takes no stream snapshot.
func TestLeavingStreamTabDoesNotRefresh(t *testing.T) {
	m, src := newStreamRefreshModel(t, TabStream)
	before := src.snapshots
	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	m = next.(*Model)
	if m.activeTab == TabStream {
		t.Fatal("tab key did not leave the Stream tab")
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	m = next.(*Model)
	if m.activeTab == TabStream {
		t.Fatal("tab key cycled straight back into the Stream tab")
	}
	if got := src.snapshots - before; got != 0 {
		t.Fatalf("leaving the Stream tab refreshed the stream %d times, want 0", got)
	}
}
