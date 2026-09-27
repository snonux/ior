package dashboard

import (
	"testing"

	coreflamegraph "ior/internal/flamegraph"
	common "ior/internal/tui/common"
	flamegraphtui "ior/internal/tui/flamegraph"

	tea "charm.land/bubbletea/v2"
)

// newPausedFlameDashboard returns a dashboard sized width x height on the
// Flame tab, with a laid-out flamegraph at rest and live refresh paused, so
// no snapshot arrives to restart an animation behind the test's back.
func newPausedFlameDashboard(t *testing.T, width, height int) *Model {
	t.Helper()
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 0)
	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m = next.(*Model)
	m.SetLiveTrie(liveTrie)
	if m.activeTab != TabFlame || !m.flamegraphModel.HasSnapshot() {
		t.Fatal("expected a laid-out flamegraph on the Flame tab")
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)
	if !m.flamegraphModel.Paused() {
		t.Fatal("space did not pause the flamegraph")
	}
	if m.flamegraphModel.Animating() {
		t.Fatal("expected the initial layout at rest")
	}
	return m
}

// flameAnimationTicks runs cmd as the runtime would and returns the
// flamegraph animation ticks it emits. The dashboard's own tick chains are
// skipped; any other message fails the test, so an unexpected command cannot
// pass for an animation tick.
func flameAnimationTicks(t *testing.T, cmd tea.Cmd) []tea.Msg {
	t.Helper()
	if cmd == nil {
		return nil
	}
	msg := cmd()
	if flamegraphtui.IsAnimationTick(msg) {
		return []tea.Msg{msg}
	}
	var ticks []tea.Msg
	switch msg := msg.(type) {
	case tea.BatchMsg:
		for _, sub := range msg {
			ticks = append(ticks, flameAnimationTicks(t, sub)...)
		}
	case flameTickMsg, refreshTickMsg, streamTickMsg, bubbleTickMsg, nil:
	default:
		t.Fatalf("unexpected message %T from a flame viewport command", msg)
	}
	return ticks
}

// requireOneFlameTick runs cmd and requires it to schedule exactly one
// animation tick: none leaves the frames frozen, two would be duplicate loops.
func requireOneFlameTick(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	ticks := flameAnimationTicks(t, cmd)
	if len(ticks) != 1 {
		t.Fatalf("got %d flame animation ticks, want exactly 1", len(ticks))
	}
	return ticks[0]
}

// settleFlameThroughDashboard delivers tick through the dashboard, as the
// runtime would, until the flamegraph stops scheduling ticks. A live loop
// keeps its generation from tick to tick, so the loop's first tick stands in
// for its successors and the test need not sleep through each interval.
func settleFlameThroughDashboard(t *testing.T, m *Model, tick tea.Msg) *Model {
	t.Helper()
	for i := 0; ; i++ {
		if i == 240 {
			t.Fatal("flame animation did not settle within 240 ticks")
		}
		next, cmd := m.Update(tick)
		m = next.(*Model)
		if cmd == nil {
			break
		}
	}
	if m.flamegraphModel.Animating() {
		t.Fatal("the flame tick loop ended while still animating")
	}
	return m
}

// requireFlameAtTarget compares the settled flamegraph with one laid out
// directly at the same size, which never animated.
func requireFlameAtTarget(t *testing.T, m *Model, showHelp bool) {
	t.Helper()
	want := newPausedFlameDashboard(t, m.width, m.height)
	if showHelp {
		next, cmd := want.Update(tea.KeyPressMsg{Code: tea.KeyF1})
		want = next.(*Model)
		if cmd != nil || want.flamegraphModel.Animating() {
			t.Fatal("the reference help toggle animated a layout at rest")
		}
	}
	if got, exp := m.flamegraphModel.View().Content, want.flamegraphModel.View().Content; got != exp {
		t.Fatalf("settled flamegraph differs from the target layout:\n got:\n%s\nwant:\n%s", got, exp)
	}
}

// TestPausedFlameResizeSchedulesAnimationTick is the task kc regression: a
// resize on a paused Flame tab starts a frame animation, and the dashboard
// must hand its tick to the runtime, or the frames stay at the first
// interpolated step.
func TestPausedFlameResizeSchedulesAnimationTick(t *testing.T) {
	m := newPausedFlameDashboard(t, 120, 30)
	next, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	m = next.(*Model)
	if !m.flamegraphModel.Animating() {
		t.Fatal("the resize did not start a flame animation")
	}
	m = settleFlameThroughDashboard(t, m, requireOneFlameTick(t, cmd))
	requireFlameAtTarget(t, m, false)
}

// TestPausedFlameHelpToggleSchedulesAnimationTick covers the help toggle. It
// only changes the flame viewport's height, which moves no frame, so on its
// own it starts no animation; what it must not do is swallow the tick that
// restarts a running animation whose loop was lost (its tick dropped while
// the dashboard was not receiving messages, long enough ago to count as
// lost; ForceTickLost stands in for the wait). Before task kc that restart
// was discarded along with the command.
func TestPausedFlameHelpToggleSchedulesAnimationTick(t *testing.T) {
	m := newPausedFlameDashboard(t, 120, 30)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
	m = next.(*Model)
	if cmd != nil || m.flamegraphModel.Animating() {
		t.Fatal("a help toggle at rest started a flame animation")
	}

	next, lost := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	m = next.(*Model)
	if lost == nil || !m.flamegraphModel.Animating() {
		t.Fatal("the resize did not start a flame animation")
	}
	m.flamegraphModel.ForceTickLost()

	next, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
	m = next.(*Model)
	if !m.flamegraphModel.Animating() {
		t.Fatal("the help toggle stopped the running animation")
	}
	m = settleFlameThroughDashboard(t, m, requireOneFlameTick(t, cmd))
	requireFlameAtTarget(t, m, false)
}

// TestFlameAnimationResumesOnReturnToTab covers an animation left running
// when the user switches tabs: its pending tick is dropped off-tab, which
// leaves the loop marked live with a tick not yet overdue, so returning to
// the Flame tab must restart the loop rather than wait for lost-tick
// recovery. The dropped tick, delivered late, must not become a second loop.
func TestFlameAnimationResumesOnReturnToTab(t *testing.T) {
	m := newPausedFlameDashboard(t, 120, 30)
	next, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	m = next.(*Model)
	tick := requireOneFlameTick(t, cmd)
	next, cmd = m.Update(tick)
	m = next.(*Model)
	if cmd == nil || !m.flamegraphModel.Animating() {
		t.Fatal("expected the animation mid-way after its first tick")
	}
	midway := m.flamegraphModel.View().Content

	m = pressKey(m, '2')
	if m.activeTab != TabOverview {
		t.Fatalf("expected the Overview tab, got %v", m.activeTab)
	}
	dropped := requireOneFlameTick(t, cmd)
	next, cmd = m.Update(dropped)
	m = next.(*Model)
	if cmd != nil {
		t.Fatal("an off-tab flame tick scheduled a command")
	}
	if !m.flamegraphModel.Animating() || m.flamegraphModel.View().Content != midway {
		t.Fatal("expected the off-tab animation frozen mid-way")
	}
	// However long the test takes, the loop must still count as live, so
	// lost-tick recovery cannot be what restarts it.
	m.flamegraphModel.KeepTickLoopFresh()

	next, cmd = m.Update(tea.KeyPressMsg{Code: '1', Text: "1"})
	m = next.(*Model)
	if m.activeTab != TabFlame {
		t.Fatalf("expected the Flame tab, got %v", m.activeTab)
	}
	resumed := requireOneFlameTick(t, cmd)

	next, cmd = m.Update(dropped)
	m = next.(*Model)
	if cmd != nil {
		t.Fatal("the dropped tick continued its retired loop next to the resumed one")
	}
	m = settleFlameThroughDashboard(t, m, resumed)
	requireFlameAtTarget(t, m, false)
}

// TestFlameViewportChangesScheduleNoExtraTicks pins the negative side: a
// viewport change while a loop is live, an unchanged viewport, a hidden-tab
// resize and entering the tab at rest schedule no animation tick.
func TestFlameViewportChangesScheduleNoExtraTicks(t *testing.T) {
	t.Run("live loop", func(t *testing.T) {
		m := newPausedFlameDashboard(t, 120, 30)
		next, first := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
		m = next.(*Model)
		if first == nil {
			t.Fatal("the resize scheduled no tick")
		}
		// The loop's tick is pending, not lost, however long the test takes.
		m.flamegraphModel.KeepTickLoopFresh()
		next, cmd := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
		m = next.(*Model)
		if cmd != nil {
			t.Fatal("a resize during a live loop scheduled a second loop")
		}
		next, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
		m = next.(*Model)
		if cmd != nil {
			t.Fatal("a help toggle during a live loop scheduled a second loop")
		}
		m = settleFlameThroughDashboard(t, m, requireOneFlameTick(t, first))
		requireFlameAtTarget(t, m, true)
	})
	t.Run("unchanged viewport", func(t *testing.T) {
		m := newPausedFlameDashboard(t, 120, 30)
		if _, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30}); cmd != nil {
			t.Fatal("an unchanged window size scheduled a command")
		}
	})
	t.Run("hidden tab", func(t *testing.T) {
		m := newPausedFlameDashboard(t, 120, 30)
		m = pressKey(m, '2')
		next, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
		m = next.(*Model)
		if ticks := flameAnimationTicks(t, cmd); len(ticks) != 0 {
			t.Fatal("a hidden-tab resize scheduled a flame animation tick")
		}
		if m.flamegraphModel.Animating() {
			t.Fatal("a hidden-tab resize started an animation nobody sees")
		}
		next, cmd = m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
		m = next.(*Model)
		if cmd != nil || m.flamegraphModel.Animating() {
			t.Fatal("a hidden-tab help toggle started a flame animation")
		}
		next, cmd = m.Update(tea.KeyPressMsg{Code: '1', Text: "1"})
		m = next.(*Model)
		if ticks := flameAnimationTicks(t, cmd); len(ticks) != 0 {
			t.Fatal("entering the Flame tab at rest scheduled an animation tick")
		}
		requireFlameAtTarget(t, m, true)
	})
}

// leaveFlameMidAnimation starts a resize animation on the Flame tab, lets one
// tick through, switches to Overview and delivers the next tick there, where
// the dashboard drops it. The flamegraph is left frozen mid-way with its loop
// still marked live (and kept fresh, so it never counts as lost). It returns
// the dropped tick.
func leaveFlameMidAnimation(t *testing.T, m *Model) (*Model, tea.Msg) {
	t.Helper()
	next, cmd := m.Update(tea.WindowSizeMsg{Width: 80, Height: 30})
	m = next.(*Model)
	next, cmd = m.Update(requireOneFlameTick(t, cmd))
	m = next.(*Model)
	if cmd == nil || !m.flamegraphModel.Animating() {
		t.Fatal("expected the animation mid-way after its first tick")
	}
	m = pressKey(m, '2')
	dropped := requireOneFlameTick(t, cmd)
	next, cmd = m.Update(dropped)
	m = next.(*Model)
	if cmd != nil || !m.flamegraphModel.Animating() {
		t.Fatal("expected the off-tab animation frozen with its tick dropped")
	}
	m.flamegraphModel.KeepTickLoopFresh()
	return m, dropped
}

// TestHiddenFlameViewportChangeSettlesFrozenAnimation covers a viewport
// change while the Flame tab is hidden and an animation is frozen there with
// its tick dropped: the hidden change installs the final layout at rest, and
// returning to Flame shows it without animating or scheduling a tick. The
// stale loop must not outlive the return either: the next animation on the
// tab gets its tick at once, and the dropped tick, arriving late, is ignored.
func TestHiddenFlameViewportChangeSettlesFrozenAnimation(t *testing.T) {
	cases := []struct {
		name     string
		msg      tea.Msg
		showHelp bool
	}{
		{name: "resize", msg: tea.WindowSizeMsg{Width: 100, Height: 30}},
		{name: "help toggle", msg: tea.KeyPressMsg{Code: tea.KeyF1}, showHelp: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, dropped := leaveFlameMidAnimation(t, newPausedFlameDashboard(t, 120, 30))

			next, cmd := m.Update(tc.msg)
			m = next.(*Model)
			if ticks := flameAnimationTicks(t, cmd); len(ticks) != 0 {
				t.Fatal("a hidden-tab viewport change scheduled a flame animation tick")
			}
			if m.flamegraphModel.Animating() {
				t.Fatal("a hidden-tab viewport change left the frozen animation running")
			}

			next, cmd = m.Update(tea.KeyPressMsg{Code: '1', Text: "1"})
			m = next.(*Model)
			if m.activeTab != TabFlame {
				t.Fatalf("expected the Flame tab, got %v", m.activeTab)
			}
			if ticks := flameAnimationTicks(t, cmd); len(ticks) != 0 {
				t.Fatal("returning to a settled Flame tab scheduled an animation tick")
			}
			if m.flamegraphModel.Animating() {
				t.Fatal("returning to Flame restarted the settled animation")
			}
			requireFlameAtTarget(t, m, tc.showHelp)

			// The dropped tick has not arrived, so only the return can have
			// ended the stale loop that would hold this animation's tick back.
			next, cmd = m.Update(tea.WindowSizeMsg{Width: 90, Height: 30})
			m = next.(*Model)
			tick := requireOneFlameTick(t, cmd)
			if _, cmd = m.Update(dropped); cmd != nil {
				t.Fatal("the dropped tick continued its loop next to the new one")
			}
			m = settleFlameThroughDashboard(t, m, tick)
			requireFlameAtTarget(t, m, tc.showHelp)
		})
	}
}
