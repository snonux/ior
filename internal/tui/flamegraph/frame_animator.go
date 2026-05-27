package flamegraph

import "time"

// FrameAnimator manages the animated transition between frame layouts. It owns
// the current frame slice, the target frame slice, the frame ancestry index, and
// the spring-based AnimationState. The Model delegates all layout-swap and
// animation-tick logic here.
type FrameAnimator struct {
	animation    AnimationState
	animating    bool
	frames       []tuiFrame
	targetFrames []tuiFrame
	ancestry     frameAncestry
}

// newFrameAnimator constructs a FrameAnimator with spring parameters suitable
// for the default 30 fps / ω=6 / ζ=1 damping curve.
func newFrameAnimator() FrameAnimator {
	return FrameAnimator{
		animation: NewAnimationState(30, 6.0, 1.0),
	}
}

// applyTargetFrames installs a new frame layout and ancestry index. When animate
// is true and a previous layout exists, it kicks off a spring animation from
// the current positions. When animate is false (zoom transitions, user driving),
// it snaps directly to the target.
//
// After swapping frames it restores the selection to prevPath, clamps it,
// recomputes the filter state, ensures visibility, and refreshes the subtree
// highlight — maintaining the same post-swap invariants as the old Model method.
func (fa *FrameAnimator) applyTargetFrames(
	targetFrames []tuiFrame,
	ancestry frameAncestry,
	prevPath string,
	animate bool,
	sel *SelectionManager,
	search *SearchController,
	height int,
) {
	fa.targetFrames = targetFrames
	fa.ancestry = ancestry
	fa.animation.SetTargets(fa.targetFrames)
	if animate && len(fa.frames) > 0 && !fa.animation.Settled() {
		fa.animating = true
		fa.frames = fa.animation.CurrentFrames()
	} else {
		fa.animating = false
		fa.frames = append(fa.frames[:0], fa.targetFrames...)
	}
	if len(fa.frames) > 1 {
		sel.hasNavigableSnapshot = true
	}
	sel.restoreByPath(fa.frames, prevPath)
	sel.clamp(fa.frames)
	search.recomputeFilterState(fa.frames, fa.ancestry)
	sel.ensureNavigable(fa.frames, search.matchIndices, search.searchQuery, search.filterVisible)
	sel.ensureVisible(fa.frames, height, search.searchQuery, search.filterVisible)
	sel.subtreeSet = subtreeSetUsingAncestry(fa.frames, sel.selectedIdx, fa.ancestry, sel.subtreeSet)
}

// tickAnimation advances the spring by one frame and updates the current frames.
// Returns true while animation is still active.
func (fa *FrameAnimator) tickAnimation(sel *SelectionManager, search *SearchController) bool {
	fa.animating = fa.animation.Tick(0)
	fa.frames = fa.animation.CurrentFrames()
	sel.clamp(fa.frames)
	sel.subtreeSet = subtreeSetUsingAncestry(fa.frames, sel.selectedIdx, fa.ancestry, sel.subtreeSet)
	return fa.animating
}

// reset clears all frame/animation state, preserving the configured spring parameters.
func (fa *FrameAnimator) reset() {
	fa.animation = NewAnimationState(30, 6.0, 1.0)
	fa.animating = false
	fa.frames = nil
	fa.targetFrames = nil
	fa.ancestry = frameAncestry{}
}

// driveWindowActive reports whether lastKeyAt falls within the active drive
// window where the user is considered to be actively pressing keys.
func driveWindowActive(lastKeyAt time.Time) bool {
	if lastKeyAt.IsZero() {
		return false
	}
	return time.Since(lastKeyAt) < driveWindow
}
