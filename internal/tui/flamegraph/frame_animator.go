package flamegraph

import "time"

// FrameAnimator manages the animated transition between frame layouts. It owns
// the current frame slice, the target frame slice, the frame ancestry index, and
// the spring-based AnimationState. It knows nothing about selection or search:
// the Model re-establishes those invariants after each swap or tick (see
// Model.applyTargetFrames and Model.tickAnimation).
type FrameAnimator struct {
	animation    AnimationState
	animating    bool
	frames       []tuiFrame
	targetFrames []tuiFrame
	ancestry     frameAncestry
	// generation identifies the tick loop that may advance the animation.
	// Every tick command captures it and the Model drops a tick whose
	// generation no longer matches. reset advances it, so a tick scheduled
	// before a reset cannot restore the discarded frames, and startTicks
	// advances it whenever a new tick loop is started, so a loop already
	// running dies instead of running beside the new one (N loops would
	// animate N times as fast). Unlike the other fields it survives reset,
	// which is what makes it an invalidation token.
	generation uint64
}

// newFrameAnimator constructs a FrameAnimator with spring parameters suitable
// for the default 30 fps / ω=6 / ζ=1 damping curve.
func newFrameAnimator() FrameAnimator {
	return FrameAnimator{
		animation: NewAnimationState(30, 6.0, 1.0),
	}
}

// currentFrames returns the frames to render now: the interpolated positions
// while animating, otherwise the installed target layout. The slice is owned by
// the animator and is overwritten by the next swap or tick.
func (fa *FrameAnimator) currentFrames() []tuiFrame {
	return fa.frames
}

// currentAncestry returns the parent/child index of the installed layout.
func (fa *FrameAnimator) currentAncestry() frameAncestry {
	return fa.ancestry
}

// isAnimating reports whether a spring transition is still in progress.
func (fa *FrameAnimator) isAnimating() bool {
	return fa.animating
}

// indexByPath returns the index of the current frame with the given path, or
// -1 when no such frame exists.
func (fa *FrameAnimator) indexByPath(path string) int {
	for idx, frame := range fa.frames {
		if frame.Path == path {
			return idx
		}
	}
	return -1
}

// applyTargetFrames installs a new frame layout and ancestry index. When animate
// is true and a previous layout exists, it kicks off a spring animation from
// the current positions. When animate is false (zoom transitions, user driving),
// it snaps directly to the target, and the springs are moved onto the snapped
// positions so the next animated layout starts from what is on screen.
//
// Starting an animation does not schedule a tick: the Model does that through
// startTicks, which supersedes any tick loop already running.
func (fa *FrameAnimator) applyTargetFrames(targetFrames []tuiFrame, ancestry frameAncestry, animate bool) {
	fa.targetFrames = targetFrames
	fa.ancestry = ancestry
	fa.animation.SetTargets(fa.targetFrames)
	if animate && len(fa.frames) > 0 && !fa.animation.Settled() {
		fa.animating = true
		fa.frames = fa.animation.CurrentFrames()
	} else {
		fa.animating = false
		fa.animation.SnapToTargets()
		fa.frames = append(fa.frames[:0], fa.targetFrames...)
	}
}

// tickAnimation advances the spring by one frame and updates the current frames.
// Returns true while animation is still active.
func (fa *FrameAnimator) tickAnimation() bool {
	fa.animating = fa.animation.Tick(0)
	fa.frames = fa.animation.CurrentFrames()
	return fa.animating
}

// tickGeneration returns the generation a tick scheduled now must carry to be
// accepted by acceptsTick.
func (fa *FrameAnimator) tickGeneration() uint64 {
	return fa.generation
}

// startTicks begins a new tick loop: it advances the generation, which
// retires every tick loop already running, and returns the generation the new
// loop's ticks must carry.
func (fa *FrameAnimator) startTicks() uint64 {
	fa.generation++
	return fa.generation
}

// acceptsTick reports whether a tick scheduled for generation may advance the
// animation: it must belong to the current animation state, and a transition
// must still be in progress.
func (fa *FrameAnimator) acceptsTick(generation uint64) bool {
	return fa.animating && generation == fa.generation
}

// reset clears all frame/animation state, preserving the configured spring
// parameters, and advances the generation so every tick already scheduled is
// dropped on arrival. The spring state goes too: kept, a later animated
// layout would spring from the discarded positions instead of the frames on
// screen.
func (fa *FrameAnimator) reset() {
	fa.generation++
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
