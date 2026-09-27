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
	// before a reset cannot restore the discarded frames. Unlike the other
	// fields it survives reset, which is what makes it an invalidation token.
	generation uint64
	// ticking reports that a tick loop of the current generation is live: its
	// next tick is scheduled, due at tickDue. startTicks does not start a
	// second loop while one is live (N loops would animate N times as fast),
	// and it does not replace the live loop either: retiring the pending
	// tick on every snapshot or resize would starve the animation whenever
	// they arrive faster than a tick. The live loop picks up the new springs
	// on its next tick.
	ticking bool
	tickDue time.Time
}

// tickLostAfter is how long past its due time a live loop's pending tick may
// be before startTicks treats it as lost and starts a new loop. A tick is
// lost when the dashboard drops it, which it does while another tab is
// active; without this, a lost tick would leave ticking set and no loop would
// ever start again. The margin is wide so that a tick merely delayed by a
// busy event loop is not retired, which would starve the animation.
const tickLostAfter = 10 * animFrameDuration

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
// startTicks, which reuses the tick loop already running, if any.
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

// tickGeneration returns the generation of the current tick loop.
func (fa *FrameAnimator) tickGeneration() uint64 {
	return fa.generation
}

// startTicks is called when an animation has been (re)started. When a live
// loop exists it returns false: that loop's pending tick advances the new
// springs. Otherwise, or when the live loop's tick is overdue by more than
// tickLostAfter, it starts a new loop, advancing the generation so a lost or
// late tick of the old loop is dropped, and returns the generation the new
// loop's ticks must carry.
func (fa *FrameAnimator) startTicks(now time.Time) (generation uint64, start bool) {
	if fa.ticking && now.Before(fa.tickDue.Add(tickLostAfter)) {
		return 0, false
	}
	fa.generation++
	fa.ticking = true
	fa.tickDue = now.Add(animFrameDuration)
	return fa.generation, true
}

// continueTicks schedules the live loop's next tick and returns the
// generation it must carry. Only the tick handler calls it.
func (fa *FrameAnimator) continueTicks(now time.Time) uint64 {
	fa.ticking = true
	fa.tickDue = now.Add(animFrameDuration)
	return fa.generation
}

// stopTicks ends the live loop: its tick arrived and schedules no successor.
func (fa *FrameAnimator) stopTicks() {
	fa.ticking = false
}

// acceptsTick reports whether a tick scheduled for generation belongs to the
// current tick loop. A current tick may still find the animation settled or
// snapped; the Model then ends the loop with stopTicks.
func (fa *FrameAnimator) acceptsTick(generation uint64) bool {
	return generation == fa.generation
}

// reset clears all frame/animation state, preserving the configured spring
// parameters, ends the live tick loop and advances the generation so every
// tick already scheduled is dropped on arrival. The spring state goes too: kept, a later animated
// layout would spring from the discarded positions instead of the frames on
// screen.
func (fa *FrameAnimator) reset() {
	fa.generation++
	fa.ticking = false
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
