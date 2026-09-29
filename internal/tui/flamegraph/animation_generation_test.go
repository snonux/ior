package flamegraph

import (
	"slices"
	"testing"

	coreflamegraph "ior/internal/flamegraph"

	tea "charm.land/bubbletea/v2"
)

// currentAnimTick returns the tick the model's animation command would emit
// now, without waiting out the tick interval.
func currentAnimTick(m *Model) animTickMsg {
	return animTickMsg{generation: m.anim.tickGeneration()}
}

// newAnimatingModel returns a model with a loaded snapshot whose layout is in
// the middle of an animated transition, together with the tick command that
// transition scheduled.
func newAnimatingModel(t *testing.T) (*Model, *coreflamegraph.LiveTrie, tea.Cmd) {
	t.Helper()
	m, trie := newGenerationTestModel(t)
	m = deliver(t, m, dispatchAndCompute(t, m))
	if !m.HasSnapshot() || len(m.anim.frames) == 0 {
		t.Fatal("initial refresh did not lay out any frames")
	}
	m = settleFlameAnimation(t, m)

	next, cmd := m.Update(tea.WindowSizeMsg{Width: 70, Height: 30})
	m = next.(*Model)
	if !m.anim.isAnimating() || cmd == nil {
		t.Fatal("resize did not start a frame animation")
	}
	return m, trie, cmd
}

// TestStateChangeDropsInFlightAnimationTick covers every key that starts a new
// baseline while a frame animation is running: the tick scheduled before the
// key must not restore the discarded frames.
func TestStateChangeDropsInFlightAnimationTick(t *testing.T) {
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
			m, _, tickCmd := newAnimatingModel(t)
			stale, ok := tickCmd().(animTickMsg)
			if !ok {
				t.Fatal("animation command did not emit an animTickMsg")
			}

			m = deliver(t, m, runeKey(tc.key))
			if m.statusMessage == "" {
				t.Fatalf("key %q did not change snapshot state", tc.key)
			}
			if m.anim.isAnimating() {
				t.Fatalf("key %q left the frame animation running", tc.key)
			}
			if stale.generation == m.anim.tickGeneration() {
				t.Fatalf("key %q did not invalidate the scheduled animation tick", tc.key)
			}

			next, cmd := m.Update(stale)
			m = next.(*Model)
			if n := len(m.anim.currentFrames()); n != 0 {
				t.Fatalf("stale animation tick restored %d discarded frames", n)
			}
			if cmd != nil {
				t.Fatal("stale animation tick scheduled another tick")
			}
			if m.HasSnapshot() {
				t.Fatal("stale animation tick brought back the snapshot")
			}
		})
	}
}

// TestAnimationCompletesWithCurrentGenerationTicks guards the normal path:
// ticks carrying the current generation keep the chain alive until the
// frames settle on the target layout, and the chain then ends.
func TestAnimationCompletesWithCurrentGenerationTicks(t *testing.T) {
	m, _, cmd := newAnimatingModel(t)
	first, ok := cmd().(animTickMsg)
	if !ok {
		t.Fatal("animation command did not emit an animTickMsg")
	}
	if first.generation != m.anim.tickGeneration() {
		t.Fatalf("tick generation = %d, want current %d", first.generation, m.anim.tickGeneration())
	}

	msg := first
	for i := 0; i < 240 && m.anim.isAnimating(); i++ {
		var next tea.Model
		next, cmd = m.Update(msg)
		m = next.(*Model)
		if m.anim.isAnimating() && cmd == nil {
			t.Fatalf("tick %d ended the chain while still animating", i)
		}
		msg = currentAnimTick(m)
	}
	if m.anim.isAnimating() {
		t.Fatal("animation did not settle within 240 ticks")
	}
	if cmd != nil {
		t.Fatal("settled animation still scheduled a tick")
	}
	if !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("settled frames do not match the target layout")
	}
}

// TestAnimationAfterResetIgnoresPreResetTick checks that an animation started
// after a reset runs normally, and that a tick scheduled before the reset
// neither moves its frames nor forks a second tick chain.
func TestAnimationAfterResetIgnoresPreResetTick(t *testing.T) {
	m, trie, tickCmd := newAnimatingModel(t)
	stale, ok := tickCmd().(animTickMsg)
	if !ok {
		t.Fatal("animation command did not emit an animTickMsg")
	}

	m = deliver(t, m, runeKey('r'))
	coreflamegraph.SeedTestLiveFlameData(trie, 1)
	m = deliver(t, m, dispatchAndCompute(t, m))
	if !m.HasSnapshot() || len(m.anim.frames) == 0 {
		t.Fatal("post-reset refresh did not lay out any frames")
	}
	if m.anim.isAnimating() {
		t.Fatal("first layout after reset animated from discarded frames")
	}

	next, cmd := m.Update(tea.WindowSizeMsg{Width: 110, Height: 30})
	m = next.(*Model)
	if !m.anim.isAnimating() || cmd == nil {
		t.Fatal("resize after reset did not start a frame animation")
	}

	before := slices.Clone(m.anim.frames)
	next, cmd = m.Update(stale)
	m = next.(*Model)
	if cmd != nil {
		t.Fatal("pre-reset tick forked a second tick chain")
	}
	if !slices.Equal(m.anim.frames, before) {
		t.Fatal("pre-reset tick advanced the post-reset animation")
	}
	if !m.anim.isAnimating() {
		t.Fatal("pre-reset tick stopped the post-reset animation")
	}

	next, cmd = m.Update(currentAnimTick(m))
	m = next.(*Model)
	if m.anim.isAnimating() && cmd == nil {
		t.Fatal("current tick did not keep the post-reset chain alive")
	}
	m = settleFlameAnimation(t, m)
	if !slices.Equal(m.anim.frames, m.anim.targetFrames) {
		t.Fatal("post-reset animation did not settle on the target layout")
	}
}

// runTickCmds executes animation tick commands, as the Bubble Tea runtime
// would, and returns the ticks they emit.
func runTickCmds(t *testing.T, cmds []tea.Cmd) []animTickMsg {
	t.Helper()
	msgs := make([]animTickMsg, 0, len(cmds))
	for _, cmd := range cmds {
		msg, ok := cmd().(animTickMsg)
		if !ok {
			t.Fatal("animation command did not emit an animTickMsg")
		}
		msgs = append(msgs, msg)
	}
	return msgs
}

// TestSnapshotsMidAnimationLeaveOneTickLoop checks that snapshots restarting a
// running animation reuse its tick loop instead of adding a second one:
// every round of delivered ticks must schedule exactly one next tick.
func TestSnapshotsMidAnimationLeaveOneTickLoop(t *testing.T) {
	m, trie, cmd := newAnimatingModel(t)
	cmds := []tea.Cmd{cmd}
	for i := uint64(1); i <= 2; i++ {
		coreflamegraph.SeedTestLiveFlameData(trie, i)
		var next tea.Model
		next, cmd = m.Update(dispatchAndCompute(t, m))
		m = next.(*Model)
		if !m.anim.isAnimating() {
			t.Fatalf("snapshot %d mid-animation did not keep animating", i)
		}
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	pending := runTickCmds(t, cmds)
	for round := 0; round < 3; round++ {
		var live []tea.Cmd
		for _, msg := range pending {
			next, cmd := m.Update(msg)
			m = next.(*Model)
			if cmd != nil {
				live = append(live, cmd)
			}
		}
		if len(live) != 1 {
			t.Fatalf("round %d: %d live tick loops, want 1", round, len(live))
		}
		pending = runTickCmds(t, live)
	}
}

// TestSetLiveTrieDropsInFlightAnimationTick checks that a tick scheduled for
// the previous session cannot restore its frames after SetLiveTrie.
func TestSetLiveTrieDropsInFlightAnimationTick(t *testing.T) {
	m, _, cmd := newAnimatingModel(t)
	stale := runTickCmds(t, []tea.Cmd{cmd})[0]

	m.SetLiveTrie(coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count", ""))
	if m.anim.isAnimating() {
		t.Fatal("SetLiveTrie left the frame animation running")
	}

	next, cmd := m.Update(stale)
	m = next.(*Model)
	if n := len(m.anim.currentFrames()); n != 0 {
		t.Fatalf("stale animation tick restored %d frames of the previous session", n)
	}
	if cmd != nil {
		t.Fatal("stale animation tick scheduled another tick")
	}
}

// springPositions returns the interpolated position of every spring, which a
// tick moves even when the rounded frames happen not to change.
func springPositions(m *Model) []float64 {
	positions := make([]float64, 0, 2*len(m.anim.animation.springs))
	for _, spring := range m.anim.animation.springs {
		positions = append(positions, spring.currentW, spring.currentCol)
	}
	return positions
}

// TestFastSnapshotsAndResizesDoNotStarveTicks is the negative case of the
// single-loop rule: snapshots and resizes arriving faster than a tick must
// not push the pending tick back, so it is still accepted and advances the
// frames once it fires.
func TestFastSnapshotsAndResizesDoNotStarveTicks(t *testing.T) {
	m, trie, cmd := newAnimatingModel(t)
	pending := runTickCmds(t, []tea.Cmd{cmd})[0]
	// Keep the live loop's tick from ever counting as lost, so the result
	// does not depend on how long the test takes to reach the tick.
	m.KeepTickLoopFresh()

	widths := []int{90, 60, 100}
	for i := uint64(1); i <= 3; i++ {
		coreflamegraph.SeedTestLiveFlameData(trie, i)
		var next tea.Model
		next, cmd = m.Update(dispatchAndCompute(t, m))
		m = next.(*Model)
		if cmd != nil {
			t.Fatalf("snapshot %d mid-animation scheduled a tick beside the pending one", i)
		}
		next, cmd = m.Update(tea.WindowSizeMsg{Width: widths[i-1], Height: 30})
		m = next.(*Model)
		if cmd != nil {
			t.Fatalf("resize %d mid-animation scheduled a tick beside the pending one", i)
		}
	}
	if !m.anim.isAnimating() {
		t.Fatal("snapshots and resizes ended the animation")
	}

	before := springPositions(m)
	next, cmd := m.Update(pending)
	m = next.(*Model)
	if slices.Equal(springPositions(m), before) {
		t.Fatal("the pending tick was dropped: the frames did not advance")
	}
	if cmd == nil {
		t.Fatal("the pending tick did not continue the tick loop")
	}
}

// TestLostTickRestartsLoop checks that a tick loop whose pending tick never
// arrives (the dashboard drops ticks while another tab is active) does not
// block every later animation: once the tick is overdue, the next restart
// starts a new loop and the lost tick's generation is retired.
func TestLostTickRestartsLoop(t *testing.T) {
	m, trie, cmd := newAnimatingModel(t)
	lost := runTickCmds(t, []tea.Cmd{cmd})[0]
	m.ForceTickLost()

	coreflamegraph.SeedTestLiveFlameData(trie, 1)
	next, cmd := m.Update(dispatchAndCompute(t, m))
	m = next.(*Model)
	if !m.anim.isAnimating() || cmd == nil {
		t.Fatal("a snapshot after a lost tick did not start a new tick loop")
	}
	if m.anim.acceptsTick(lost.generation) {
		t.Fatal("the new tick loop kept the lost loop's generation")
	}
	fresh := runTickCmds(t, []tea.Cmd{cmd})[0]
	next, cmd = m.Update(fresh)
	m = next.(*Model)
	if m.anim.isAnimating() && cmd == nil {
		t.Fatal("the new tick loop did not continue")
	}
}

// TestSettledAnimationEndsTickLoop checks that the tick which settles an
// animation ends its loop, so the next animation starts a new one.
func TestSettledAnimationEndsTickLoop(t *testing.T) {
	m, _, _ := newAnimatingModel(t)
	m = settleFlameAnimation(t, m)
	m.KeepTickLoopFresh()

	next, cmd := m.Update(tea.WindowSizeMsg{Width: 110, Height: 30})
	m = next.(*Model)
	if !m.anim.isAnimating() {
		t.Fatal("resize after settling did not start a frame animation")
	}
	if cmd == nil {
		t.Fatal("settling left the tick loop marked live: the new animation got no tick")
	}
}

// TestTickAfterSnapEndsTickLoop checks that a pending tick finding the
// animation snapped ends its loop without scheduling another tick, and the
// next animation starts a new loop.
func TestTickAfterSnapEndsTickLoop(t *testing.T) {
	m, _, cmd := newAnimatingModel(t)
	pending := runTickCmds(t, []tea.Cmd{cmd})[0]

	m.rebuildFrames(false)
	if m.anim.isAnimating() {
		t.Fatal("rebuildFrames(false) did not snap the animation")
	}
	next, cmd := m.Update(pending)
	m = next.(*Model)
	if cmd != nil {
		t.Fatal("a tick after the snap scheduled another tick")
	}
	m.KeepTickLoopFresh()

	next, cmd = m.Update(tea.WindowSizeMsg{Width: 110, Height: 30})
	m = next.(*Model)
	if !m.anim.isAnimating() {
		t.Fatal("resize after the snap did not start a frame animation")
	}
	if cmd == nil {
		t.Fatal("the tick after the snap left the loop marked live: the new animation got no tick")
	}
}
