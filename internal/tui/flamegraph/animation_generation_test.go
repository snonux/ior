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
