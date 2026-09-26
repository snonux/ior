package flamegraph

import (
	"cmp"
	"slices"
	"strings"
)

// SelectionManager tracks the currently selected frame index and its subtree
// highlight set. It does not own the frame slice or the search state: the
// frames and ancestry index come from the FrameAnimator and the navigability
// rule comes from the SearchController, so every method receives them as
// arguments and the manager never reaches into another collaborator.
type SelectionManager struct {
	selectedIdx          int
	subtreeSet           map[int]bool
	hasNavigableSnapshot bool
}

// frameFilter reports whether frame idx may be selected. A nil frameFilter
// admits every frame, which is the "no search filter active" case.
type frameFilter func(idx int) bool

// admits reports whether idx passes the filter; nil admits everything.
func (f frameFilter) admits(idx int) bool {
	return f == nil || f(idx)
}

// newSelectionManager constructs a SelectionManager with default state.
func newSelectionManager() SelectionManager {
	return SelectionManager{
		subtreeSet: make(map[int]bool),
	}
}

// selected returns the selected frame index. It may be out of range for the
// current frames; callers that index with it must bounds-check or clamp first.
func (s *SelectionManager) selected() int {
	return s.selectedIdx
}

// subtree returns the highlight set for the current selection: the selected
// frame, its descendants and its ancestors. The map is owned by the manager and
// is refilled in place, so callers must not retain or mutate it.
func (s *SelectionManager) subtree() map[int]bool {
	return s.subtreeSet
}

// selectedPath returns the path of the selected frame, or "" when the
// selection does not address a frame in frames.
func (s *SelectionManager) selectedPath(frames []tuiFrame) string {
	if s.selectedIdx < 0 || s.selectedIdx >= len(frames) {
		return ""
	}
	return frames[s.selectedIdx].Path
}

// selectFrame moves the selection to idx and refreshes the subtree highlight.
// An idx outside frames is rejected and leaves the selection unchanged.
func (s *SelectionManager) selectFrame(frames []tuiFrame, ancestry frameAncestry, idx int) bool {
	if idx < 0 || idx >= len(frames) {
		return false
	}
	s.selectedIdx = idx
	s.refreshSubtree(frames, ancestry)
	return true
}

// refreshSubtree recomputes the subtree highlight for the current selection.
func (s *SelectionManager) refreshSubtree(frames []tuiFrame, ancestry frameAncestry) {
	s.subtreeSet = subtreeSetUsingAncestry(frames, s.selectedIdx, ancestry, s.subtreeSet)
}

// jumpToMatch moves the selection to the next (direction > 0) or previous
// (direction < 0) search match, wrapping around, and keeps the subtree
// highlight in sync. With no matches the selection does not move.
func (s *SelectionManager) jumpToMatch(frames []tuiFrame, ancestry frameAncestry, matchIndices map[int]bool, direction int) {
	s.selectedIdx, s.subtreeSet = jumpMatch(frames, matchIndices, ancestry, s.selectedIdx, direction, s.subtreeSet)
}

// markNavigableSnapshot records that a layout with more than the root frame
// has been installed at least once.
func (s *SelectionManager) markNavigableSnapshot() {
	s.hasNavigableSnapshot = true
}

// reset returns the selection to the first frame and clears the highlight in
// place, as done when the snapshot state is discarded.
func (s *SelectionManager) reset() {
	s.selectedIdx = 0
	s.subtreeSet = resetBoolSet(s.subtreeSet)
	s.hasNavigableSnapshot = false
}

// clamp ensures selectedIdx is within [0, len(frames)-1].
func (s *SelectionManager) clamp(frames []tuiFrame) {
	if len(frames) == 0 {
		s.selectedIdx = 0
		return
	}
	if s.selectedIdx < 0 {
		s.selectedIdx = 0
	}
	if s.selectedIdx >= len(frames) {
		s.selectedIdx = len(frames) - 1
	}
}

// filterActive reports whether a search filter is currently applied.
func filterActive(searchQuery string) bool {
	return strings.TrimSpace(searchQuery) != ""
}

// frameNavigable reports whether frame idx exists in frames and passes the
// navigability filter.
func frameNavigable(idx int, frames []tuiFrame, navigable frameFilter) bool {
	if idx < 0 || idx >= len(frames) {
		return false
	}
	return navigable.admits(idx)
}

// ensureNavigable moves selectedIdx to the first navigable frame when the
// current selection is hidden by a filter.
func (s *SelectionManager) ensureNavigable(frames []tuiFrame, matchIndices map[int]bool, navigable frameFilter) {
	if len(frames) == 0 {
		s.selectedIdx = 0
		return
	}
	s.clamp(frames)
	if frameNavigable(s.selectedIdx, frames, navigable) {
		return
	}
	// Prefer any existing match index.
	for _, idx := range orderedMatchIndices(matchIndices) {
		if frameNavigable(idx, frames, navigable) {
			s.selectedIdx = idx
			return
		}
	}
	// Fall back to the first navigable frame.
	for idx := range frames {
		if frameNavigable(idx, frames, navigable) {
			s.selectedIdx = idx
			return
		}
	}
}

// ensureVisible scrolls selectedIdx to a frame that is actually rendered when
// the layout is taller than the viewport. Visibility is determined by the row
// offset computed from the full frame set.
func (s *SelectionManager) ensureVisible(frames []tuiFrame, height int, navigable frameFilter) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, navigable)
	if !frameNavigable(s.selectedIdx, frames, navigable) {
		return
	}
	rowOffset := visibleRowOffset(frames, height, navigable)
	selected := frames[s.selectedIdx]
	if selected.Row >= rowOffset {
		return
	}
	bestIdx := -1
	bestScore := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if !frameNavigable(idx, frames, navigable) {
			continue
		}
		if frame.Row < rowOffset {
			continue
		}
		score := abs(frame.Row-rowOffset)*1000 + abs(frame.Col-selected.Col)
		if score < bestScore {
			bestIdx = idx
			bestScore = score
		}
	}
	if bestIdx >= 0 {
		s.selectedIdx = bestIdx
	}
}

// restoreByPath tries to set selectedIdx to the frame with the given path.
// Falls back to a boundary-prefix match if the exact path is gone.
func (s *SelectionManager) restoreByPath(frames []tuiFrame, path string) {
	if path == "" || len(frames) == 0 {
		return
	}
	for idx, frame := range frames {
		if frame.Path == path {
			s.selectedIdx = idx
			return
		}
	}
	for idx, frame := range frames {
		if hasPathBoundaryPrefix(path, frame.Path) || hasPathBoundaryPrefix(frame.Path, path) {
			s.selectedIdx = idx
			return
		}
	}
}

// moveVertical moves the selection one depth level up or down within the frame set.
// Picks the horizontally closest frame at the target depth.
func (s *SelectionManager) moveVertical(frames []tuiFrame, delta int, navigable frameFilter) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, navigable)
	current := frames[s.selectedIdx]
	targets := framesAtDepthFiltered(frames, current.Depth+delta, navigable)
	if len(targets) == 0 {
		return
	}
	best := targets[0]
	bestDist := abs(frames[best].Col - current.Col)
	for _, idx := range targets[1:] {
		dist := abs(frames[idx].Col - current.Col)
		if dist < bestDist {
			best = idx
			bestDist = dist
		}
	}
	s.selectedIdx = best
}

// moveVerticalWithFallback tries primaryDelta, then fallbackDelta, then
// traversal order when the selection does not change.
func (s *SelectionManager) moveVerticalWithFallback(frames []tuiFrame, navigable frameFilter, primaryDelta, fallbackDelta, traversalDelta int) {
	before := s.selectedIdx
	s.moveVertical(frames, primaryDelta, navigable)
	if s.selectedIdx == before && fallbackDelta != 0 {
		s.moveVertical(frames, fallbackDelta, navigable)
	}
	if s.selectedIdx == before && traversalDelta != 0 {
		s.moveTraversal(frames, traversalDelta, navigable)
	}
}

// moveSibling navigates to the previous or next sibling at the same depth.
// Falls back to traversal order when there is only one sibling.
func (s *SelectionManager) moveSibling(frames []tuiFrame, delta int, navigable frameFilter) {
	if len(frames) == 0 {
		return
	}
	before := s.selectedIdx
	s.clamp(frames)
	s.ensureNavigable(frames, nil, navigable)
	current := frames[s.selectedIdx]
	siblings := framesAtDepthFiltered(frames, current.Depth, navigable)
	if len(siblings) <= 1 {
		s.moveTraversal(frames, delta, navigable)
		return
	}
	pos := indexOf(siblings, s.selectedIdx)
	if pos < 0 {
		s.moveTraversal(frames, delta, navigable)
		return
	}
	next := pos + delta
	if next < 0 {
		next = 0
	}
	if next >= len(siblings) {
		next = len(siblings) - 1
	}
	s.selectedIdx = siblings[next]
	if s.selectedIdx == before {
		s.moveTraversal(frames, delta, navigable)
	}
}

// jumpToTop moves the selection to the deepest frame closest to the current
// horizontal column.
func (s *SelectionManager) jumpToTop(frames []tuiFrame, navigable frameFilter) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, navigable)
	currentCol := frames[s.selectedIdx].Col
	bestIdx := -1
	bestDepth := -1
	bestDist := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if !navigable.admits(idx) {
			continue
		}
		dist := abs(frame.Col - currentCol)
		if frame.Depth > bestDepth {
			bestDepth = frame.Depth
			bestIdx = idx
			bestDist = dist
			continue
		}
		if frame.Depth == bestDepth {
			if dist < bestDist || (dist == bestDist && frame.Col < frames[bestIdx].Col) {
				bestIdx = idx
				bestDist = dist
			}
		}
	}
	if bestIdx >= 0 {
		s.selectedIdx = bestIdx
	}
}

// jumpToRoot moves the selection to the shallowest frame closest to the current
// horizontal column. Prefers the zoom root path when available.
func (s *SelectionManager) jumpToRoot(frames []tuiFrame, rootPath string, navigable frameFilter) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, navigable)
	if rootPath != "" {
		for idx, frame := range frames {
			if frame.Path == rootPath && (s.selectedIdx == idx || navigable.admits(idx)) {
				s.selectedIdx = idx
				return
			}
		}
	}

	currentCol := frames[s.selectedIdx].Col
	bestIdx := -1
	bestDepth := int(^uint(0) >> 1)
	bestDist := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if !navigable.admits(idx) {
			continue
		}
		dist := abs(frame.Col - currentCol)
		if frame.Depth < bestDepth {
			bestDepth = frame.Depth
			bestDist = dist
			bestIdx = idx
			continue
		}
		if frame.Depth == bestDepth {
			if dist < bestDist || (dist == bestDist && frame.Col < frames[bestIdx].Col) {
				bestDist = dist
				bestIdx = idx
			}
		}
	}
	if bestIdx >= 0 {
		s.selectedIdx = bestIdx
	}
}

// moveTraversal navigates through frames in depth-then-column order.
func (s *SelectionManager) moveTraversal(frames []tuiFrame, delta int, navigable frameFilter) {
	if len(frames) == 0 || delta == 0 {
		return
	}
	order := visibleTraversalOrder(frames, navigable)
	if len(order) == 0 {
		return
	}
	pos := indexOf(order, s.selectedIdx)
	if pos < 0 {
		pos = 0
	}
	next := pos + delta
	if next < 0 {
		next = 0
	}
	if next >= len(order) {
		next = len(order) - 1
	}
	s.selectedIdx = order[next]
}

// visibleTraversalOrder returns frame indices sorted by depth then column.
func visibleTraversalOrder(frames []tuiFrame, navigable frameFilter) []int {
	indices := make([]int, 0, len(frames))
	for idx := range frames {
		if !navigable.admits(idx) {
			continue
		}
		indices = append(indices, idx)
	}
	slices.SortFunc(indices, func(a, b int) int {
		left := frames[a]
		right := frames[b]
		if left.Depth != right.Depth {
			return cmp.Compare(left.Depth, right.Depth)
		}
		if left.Col != right.Col {
			return cmp.Compare(left.Col, right.Col)
		}
		if left.Row != right.Row {
			return cmp.Compare(left.Row, right.Row)
		}
		return cmp.Compare(a, b)
	})
	return indices
}

// visibleRowOffset computes the first logical row that fits within the visible
// area, accounting for toolbar and status lines.
func visibleRowOffset(frames []tuiFrame, height int, navigable frameFilter) int {
	if len(frames) == 0 {
		return 0
	}
	availableRows := height - 2 // toolbar + status
	if availableRows <= 0 {
		return 0
	}
	maxRow := maxFrameRowForSet(frames, navigable)
	if maxRow+1 <= availableRows {
		return 0
	}
	return maxRow + 1 - availableRows
}

// framesAtDepth returns all frame indices at a given depth, sorted by column.
func framesAtDepth(frames []tuiFrame, depth int) []int {
	return framesAtDepthFiltered(frames, depth, nil)
}

// framesAtDepthFiltered returns the indices of the frames at depth that pass
// navigable, sorted by column.
func framesAtDepthFiltered(frames []tuiFrame, depth int, navigable frameFilter) []int {
	if depth < 0 {
		return nil
	}
	indices := make([]int, 0)
	for idx, frame := range frames {
		if !navigable.admits(idx) {
			continue
		}
		if frame.Depth == depth {
			indices = append(indices, idx)
		}
	}
	slices.SortFunc(indices, func(a, b int) int {
		return cmp.Compare(frames[a].Col, frames[b].Col)
	})
	return indices
}

// indexOf returns the position of target in values, or -1 if not found.
func indexOf(values []int, target int) int {
	for idx, value := range values {
		if value == target {
			return idx
		}
	}
	return -1
}
