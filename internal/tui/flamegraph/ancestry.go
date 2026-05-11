package flamegraph

import "strings"

// frameAncestry stores parent/child relationships between frames keyed by their
// slice index. It is rebuilt whenever the frames slice is rebuilt, and reused
// across keystrokes so subtree and filter-visibility lookups run in O(subtree)
// time instead of O(frames) string scans.
type frameAncestry struct {
	parent   []int
	children [][]int
}

// buildFrameAncestry derives parent/child links for the supplied frame slice
// using each frame's Path string. Robust to any ordering — the layout pass
// emits depth-first frames, but withZoomLineage appends ancestor frames at the
// tail, so contiguous-range tricks are not safe.
func buildFrameAncestry(frames []tuiFrame) frameAncestry {
	n := len(frames)
	ancestry := frameAncestry{
		parent:   make([]int, n),
		children: make([][]int, n),
	}
	if n == 0 {
		return ancestry
	}

	byPath := make(map[string]int, n)
	for idx, frame := range frames {
		byPath[frame.Path] = idx
		ancestry.parent[idx] = -1
	}
	for idx, frame := range frames {
		sep := strings.LastIndexByte(frame.Path, pathSeparatorByte)
		if sep < 0 {
			continue
		}
		parentPath := frame.Path[:sep]
		parentIdx, ok := byPath[parentPath]
		if !ok {
			continue
		}
		ancestry.parent[idx] = parentIdx
		ancestry.children[parentIdx] = append(ancestry.children[parentIdx], idx)
	}
	return ancestry
}

// subtreeSetUsingAncestry fills `set` with the selected frame, every descendant
// reachable through the child adjacency list, and every ancestor reachable
// through the parent chain. Matches the visibility contract of the legacy
// path-prefix walk in computeSubtreeSetInto.
//
// If `ancestry` is stale relative to `frames` (different length), it is rebuilt
// in place. The hot path through the model keeps ancestry warm via
// rebuildFrames, so the fallback only fires in tests that mutate frames
// directly.
func subtreeSetUsingAncestry(frames []tuiFrame, selectedIdx int, ancestry frameAncestry, set map[int]bool) map[int]bool {
	if set == nil {
		set = make(map[int]bool)
	} else {
		for idx := range set {
			delete(set, idx)
		}
	}
	if selectedIdx < 0 || selectedIdx >= len(frames) {
		return set
	}
	if len(ancestry.parent) != len(frames) {
		ancestry = buildFrameAncestry(frames)
	}
	markSubtree(ancestry, selectedIdx, set)
	for cur := ancestry.parent[selectedIdx]; cur >= 0; cur = ancestry.parent[cur] {
		set[cur] = true
	}
	return set
}

// filterVisibleSetUsingAncestry fills `set` with every match plus its full
// descendant subtree and ancestor chain — same semantics as the legacy
// computeFilterVisibleSetInto walk, but in O(sum-of-subtree-sizes) instead of
// O(frames × matches). Falls back to building ancestry on the fly when the
// supplied index is stale (see subtreeSetUsingAncestry).
func filterVisibleSetUsingAncestry(frames []tuiFrame, matchSet map[int]bool, ancestry frameAncestry, set map[int]bool) map[int]bool {
	if set == nil {
		set = make(map[int]bool)
	} else {
		for idx := range set {
			delete(set, idx)
		}
	}
	if len(matchSet) == 0 {
		return set
	}
	if len(ancestry.parent) != len(frames) {
		ancestry = buildFrameAncestry(frames)
	}
	for matchIdx := range matchSet {
		if matchIdx < 0 || matchIdx >= len(frames) {
			continue
		}
		markSubtree(ancestry, matchIdx, set)
		for cur := ancestry.parent[matchIdx]; cur >= 0; cur = ancestry.parent[cur] {
			if set[cur] {
				break
			}
			set[cur] = true
		}
	}
	return set
}

// markSubtree marks a frame and every descendant. Uses an iterative stack
// to keep allocations bounded for deep trees.
func markSubtree(ancestry frameAncestry, root int, set map[int]bool) {
	stack := []int{root}
	for len(stack) > 0 {
		last := len(stack) - 1
		idx := stack[last]
		stack = stack[:last]
		if set[idx] {
			continue
		}
		set[idx] = true
		stack = append(stack, ancestry.children[idx]...)
	}
}
