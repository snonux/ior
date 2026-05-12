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

// frameIndexAt returns the index of the frame rendered at terminal coordinates
// (x, y), or -1 if no frame occupies that cell. showHelp adds one extra line
// to the UI chrome so the frame area row calculations account for it.
func frameIndexAt(frames []tuiFrame, x, y, width, height int, showHelp bool) int {
	if len(frames) == 0 || width <= 0 || height <= 0 {
		return -1
	}
	if x < 0 || x >= width || y < 0 {
		return -1
	}
	extraLines := 1 // selection status line
	if showHelp {
		extraLines++
	}
	renderHeight := height - extraLines
	if renderHeight < 3 {
		renderHeight = 3
	}
	availableRows := renderHeight - 2 // flame toolbar + frame-status line
	if availableRows < 1 {
		return -1
	}
	// Row 0 is flame toolbar, rows 1..availableRows are bars, last row is status.
	if y < 1 || y > availableRows {
		return -1
	}
	targetRow := frameCoordToTargetRow(frames, y-1, availableRows)
	if targetRow < 0 {
		return -1
	}
	return findFrameAtRow(frames, targetRow, x, width)
}

// frameCoordToTargetRow converts a data-area row offset (0-based, after
// stripping the toolbar row) into the logical frame row index. Returns -1 when
// the coordinate falls in the top padding above the first visible row.
func frameCoordToTargetRow(frames []tuiFrame, dataRow, availableRows int) int {
	maxRow := maxFrameRowForSet(frames, nil)
	barHeight := computeBarHeight(availableRows, maxRow+1, maxBarVisualHeight)
	visibleDepthRows := availableRows / barHeight
	if visibleDepthRows < 1 {
		visibleDepthRows = 1
	}
	rowOffset := 0
	if maxRow+1 > visibleDepthRows {
		rowOffset = maxRow + 1 - visibleDepthRows
	}
	renderedRows := (maxRow - rowOffset + 1) * barHeight
	padTop := 0
	if renderedRows < availableRows {
		padTop = availableRows - renderedRows
	}
	if dataRow < padTop {
		return -1
	}
	depthFromTop := (dataRow - padTop) / barHeight
	return maxRow - depthFromTop
}

// findFrameAtRow scans frames for the narrowest one that occupies logical row
// targetRow and contains pixel column x within [0, width). Returning the
// narrowest frame resolves overlap between wide parent and narrow child bars.
func findFrameAtRow(frames []tuiFrame, targetRow, x, width int) int {
	best := -1
	bestWidth := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if frame.Row != targetRow || frame.Col >= width {
			continue
		}
		right := min(width, frame.Col+frame.Width)
		if x < frame.Col || x >= right {
			continue
		}
		if frame.Width < bestWidth {
			best = idx
			bestWidth = frame.Width
		}
	}
	return best
}

// driveWindowActive reports whether lastKeyAt falls within the active drive
// window where the user is considered to be actively pressing keys.
func driveWindowActive(lastKeyAt time.Time) bool {
	if lastKeyAt.IsZero() {
		return false
	}
	return time.Since(lastKeyAt) < driveWindow
}
