package flamegraph

import (
	"slices"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// newSettledModel returns a model with a loaded snapshot laid out at rest.
func newSettledModel(t *testing.T) *Model {
	t.Helper()
	m, _ := newGenerationTestModel(t)
	m = deliver(t, m, dispatchAndCompute(t, m))
	if !m.HasSnapshot() || len(m.anim.frames) == 0 {
		t.Fatal("initial refresh did not lay out any frames")
	}
	return settleFlameAnimation(t, m)
}

// driveTicks delivers the tick cmd schedules, then keeps delivering the
// loop's ticks until it ends. Only the first command is executed, as the
// runtime would, to pin the generation it carries; the later ticks are built
// directly from the loop's generation so the test does not sleep through
// every tick interval.
func driveTicks(t *testing.T, m *Model, cmd tea.Cmd) *Model {
	t.Helper()
	tick := runTickCmds(t, []tea.Cmd{cmd})[0]
	if !m.anim.acceptsTick(tick.generation) {
		t.Fatal("the scheduled tick does not belong to the live loop")
	}
	for i := 0; cmd != nil; i++ {
		if i == 240 {
			t.Fatal("tick loop did not end within 240 ticks")
		}
		if i > 0 {
			tick = currentAnimTick(m)
		}
		var next tea.Model
		next, cmd = m.Update(tick)
		m = next.(*Model)
		if m.Animating() && cmd == nil {
			t.Fatalf("tick %d ended the loop while still animating", i)
		}
	}
	return m
}

// TestSetViewportReturnsAnimationTick pins that a viewport change the
// dashboard makes (resize, help toggle) hands back the command driving the
// animation it starts, and that the frames reach the target layout.
func TestSetViewportReturnsAnimationTick(t *testing.T) {
	m := newSettledModel(t)

	cmd := m.SetViewport(70, 30, true)
	if !m.Animating() {
		t.Fatal("SetViewport did not start a frame animation")
	}
	if cmd == nil {
		t.Fatal("SetViewport started an animation without a tick command")
	}
	m = driveTicks(t, m, cmd)
	if m.Animating() {
		t.Fatal("animation did not settle")
	}
	if !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("settled frames do not match the target layout")
	}
}

// TestSetViewportReusesLiveLoop pins that a viewport change while a loop is
// live starts no second loop, and that no change schedules nothing.
func TestSetViewportReusesLiveLoop(t *testing.T) {
	m := newSettledModel(t)
	if cmd := m.SetViewport(m.width, m.height, true); cmd != nil {
		t.Fatal("an unchanged viewport scheduled a tick")
	}

	first := m.SetViewport(70, 30, true)
	if first == nil {
		t.Fatal("SetViewport started an animation without a tick command")
	}
	keepTickLoopFresh(m)
	if cmd := m.SetViewport(90, 30, true); cmd != nil {
		t.Fatal("a second viewport change started a duplicate tick loop")
	}
	if !m.Animating() {
		t.Fatal("the second viewport change stopped the animation")
	}
	m = driveTicks(t, m, first)
	if !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("the live loop did not carry the frames to the latest layout")
	}
}

// TestSetViewportWithoutAnimateSnaps pins the hidden-tab path: the layout is
// installed at rest and no tick is scheduled.
func TestSetViewportWithoutAnimateSnaps(t *testing.T) {
	m := newSettledModel(t)
	if cmd := m.SetViewport(70, 30, false); cmd != nil {
		t.Fatal("a snapped viewport change scheduled a tick")
	}
	if m.Animating() {
		t.Fatal("a snapped viewport change started an animation")
	}
	if !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("snapped frames do not match the target layout")
	}
}

// TestResumeAnimationCmdRestartsLostLoop covers returning to the Flame tab
// after the dashboard dropped the pending tick: the loop still counts as live
// and its tick is not yet overdue by tickLostAfter, so only the explicit
// resume gets the animation moving again. The lost tick, should it arrive
// after all, must not become a second loop.
func TestResumeAnimationCmdRestartsLostLoop(t *testing.T) {
	m, _, cmd := newAnimatingModel(t)
	lost := runTickCmds(t, []tea.Cmd{cmd})[0]
	keepTickLoopFresh(m)
	if m.AnimationCmd() != nil {
		t.Fatal("precondition: the loop with a fresh tick should count as live")
	}

	resumed := m.ResumeAnimationCmd()
	if resumed == nil {
		t.Fatal("resume did not restart the tick loop of a running animation")
	}
	next, stale := m.Update(lost)
	m = next.(*Model)
	if stale != nil {
		t.Fatal("the lost tick continued its retired loop")
	}
	m = driveTicks(t, m, resumed)
	if m.Animating() || !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("the resumed animation did not settle on the target layout")
	}
}

// TestResumeAnimationCmdWithoutAnimation pins that resuming a settled model
// schedules nothing and clears a stale loop, so the next animation is not
// held back waiting for tickLostAfter.
func TestResumeAnimationCmdWithoutAnimation(t *testing.T) {
	m, _, _ := newAnimatingModel(t)
	m.rebuildFrames(false)
	keepTickLoopFresh(m)

	if cmd := m.ResumeAnimationCmd(); cmd != nil {
		t.Fatal("resume scheduled a tick with nothing animating")
	}
	if cmd := m.SetViewport(90, 30, true); cmd == nil {
		t.Fatal("resume left the stale loop marked live: the next animation got no tick")
	}
}
