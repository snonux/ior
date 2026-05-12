package flamegraph

import (
	"cmp"
	"slices"
	"strings"
)

// SelectionManager tracks the currently selected frame index and related
// visibility/navigation state for the flamegraph TUI. It depends on the frame
// slice and ancestry index that live on the Model, which are passed in as
// arguments to keep the sub-controller self-contained.
type SelectionManager struct {
	selectedIdx          int
	subtreeSet           map[int]bool
	hasNavigableSnapshot bool
}

// newSelectionManager constructs a SelectionManager with default state.
func newSelectionManager() SelectionManager {
	return SelectionManager{
		subtreeSet: make(map[int]bool),
	}
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

// navigableSet returns the set of frame indices visible under the current filter,
// or nil when no filter is active (meaning all frames are navigable).
func navigableSet(searchQuery string, filterVisible map[int]bool) map[int]bool {
	if !filterActive(searchQuery) {
		return nil
	}
	return filterVisible
}

// frameNavigable reports whether frame idx can be selected given an optional
// filter-visible set.
func frameNavigable(idx int, frames []tuiFrame, searchQuery string, filterVisible map[int]bool) bool {
	if idx < 0 || idx >= len(frames) {
		return false
	}
	if !filterActive(searchQuery) {
		return true
	}
	return filterVisible[idx]
}

// ensureNavigable moves selectedIdx to the first navigable frame when the
// current selection is hidden by a filter.
func (s *SelectionManager) ensureNavigable(frames []tuiFrame, matchIndices map[int]bool, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		s.selectedIdx = 0
		return
	}
	s.clamp(frames)
	if frameNavigable(s.selectedIdx, frames, searchQuery, filterVisible) {
		return
	}
	// Prefer any existing match index.
	for _, idx := range orderedMatchIndices(matchIndices) {
		if frameNavigable(idx, frames, searchQuery, filterVisible) {
			s.selectedIdx = idx
			return
		}
	}
	// Fall back to the first navigable frame.
	for idx := range frames {
		if frameNavigable(idx, frames, searchQuery, filterVisible) {
			s.selectedIdx = idx
			return
		}
	}
}

// ensureVisible scrolls selectedIdx to a frame that is actually rendered when
// the layout is taller than the viewport. Visibility is determined by the row
// offset computed from the full frame set.
func (s *SelectionManager) ensureVisible(frames []tuiFrame, height int, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, searchQuery, filterVisible)
	if !frameNavigable(s.selectedIdx, frames, searchQuery, filterVisible) {
		return
	}
	rowOffset := visibleRowOffset(frames, height, searchQuery, filterVisible)
	selected := frames[s.selectedIdx]
	if selected.Row >= rowOffset {
		return
	}
	bestIdx := -1
	bestScore := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if !frameNavigable(idx, frames, searchQuery, filterVisible) {
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
func (s *SelectionManager) moveVertical(frames []tuiFrame, delta int, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, searchQuery, filterVisible)
	current := frames[s.selectedIdx]
	targets := framesAtDepthFiltered(frames, current.Depth+delta, navigableSet(searchQuery, filterVisible))
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
func (s *SelectionManager) moveVerticalWithFallback(frames []tuiFrame, searchQuery string, filterVisible map[int]bool, primaryDelta, fallbackDelta, traversalDelta int) {
	before := s.selectedIdx
	s.moveVertical(frames, primaryDelta, searchQuery, filterVisible)
	if s.selectedIdx == before && fallbackDelta != 0 {
		s.moveVertical(frames, fallbackDelta, searchQuery, filterVisible)
	}
	if s.selectedIdx == before && traversalDelta != 0 {
		s.moveTraversal(frames, traversalDelta, searchQuery, filterVisible)
	}
}

// moveSibling navigates to the previous or next sibling at the same depth.
// Falls back to traversal order when there is only one sibling.
func (s *SelectionManager) moveSibling(frames []tuiFrame, delta int, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		return
	}
	before := s.selectedIdx
	s.clamp(frames)
	s.ensureNavigable(frames, nil, searchQuery, filterVisible)
	current := frames[s.selectedIdx]
	siblings := framesAtDepthFiltered(frames, current.Depth, navigableSet(searchQuery, filterVisible))
	if len(siblings) <= 1 {
		s.moveTraversal(frames, delta, searchQuery, filterVisible)
		return
	}
	pos := indexOf(siblings, s.selectedIdx)
	if pos < 0 {
		s.moveTraversal(frames, delta, searchQuery, filterVisible)
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
		s.moveTraversal(frames, delta, searchQuery, filterVisible)
	}
}

// jumpToTop moves the selection to the deepest frame closest to the current
// horizontal column.
func (s *SelectionManager) jumpToTop(frames []tuiFrame, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, searchQuery, filterVisible)
	include := navigableSet(searchQuery, filterVisible)
	currentCol := frames[s.selectedIdx].Col
	bestIdx := -1
	bestDepth := -1
	bestDist := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if include != nil && !include[idx] {
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
func (s *SelectionManager) jumpToRoot(frames []tuiFrame, rootPath string, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 {
		return
	}
	s.clamp(frames)
	s.ensureNavigable(frames, nil, searchQuery, filterVisible)
	if rootPath != "" {
		for idx, frame := range frames {
			if frame.Path == rootPath && (s.selectedIdx == idx || !filterActive(searchQuery) || filterVisible[idx]) {
				s.selectedIdx = idx
				return
			}
		}
	}
	include := navigableSet(searchQuery, filterVisible)
	currentCol := frames[s.selectedIdx].Col
	bestIdx := -1
	bestDepth := int(^uint(0) >> 1)
	bestDist := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if include != nil && !include[idx] {
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
func (s *SelectionManager) moveTraversal(frames []tuiFrame, delta int, searchQuery string, filterVisible map[int]bool) {
	if len(frames) == 0 || delta == 0 {
		return
	}
	order := visibleTraversalOrder(frames, searchQuery, filterVisible)
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
func visibleTraversalOrder(frames []tuiFrame, searchQuery string, filterVisible map[int]bool) []int {
	include := navigableSet(searchQuery, filterVisible)
	indices := make([]int, 0, len(frames))
	for idx := range frames {
		if include != nil && !include[idx] {
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
func visibleRowOffset(frames []tuiFrame, height int, searchQuery string, filterVisible map[int]bool) int {
	if len(frames) == 0 {
		return 0
	}
	availableRows := height - 2 // toolbar + status
	if availableRows <= 0 {
		return 0
	}
	maxRow := maxFrameRowForSet(frames, navigableSet(searchQuery, filterVisible))
	if maxRow+1 <= availableRows {
		return 0
	}
	return maxRow + 1 - availableRows
}

// framesAtDepth returns all frame indices at a given depth, respecting the
// optional filter-visible set. Sorted by column.
func framesAtDepth(frames []tuiFrame, depth int) []int {
	return framesAtDepthFiltered(frames, depth, nil)
}

func framesAtDepthFiltered(frames []tuiFrame, depth int, include map[int]bool) []int {
	if depth < 0 {
		return nil
	}
	indices := make([]int, 0)
	for idx, frame := range frames {
		if include != nil && !include[idx] {
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
