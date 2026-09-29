package flamegraph

import (
	"maps"
	"testing"
)

func TestFrameFilterNilAdmitsEverything(t *testing.T) {
	var none frameFilter
	for _, idx := range []int{-1, 0, 5} {
		if !none.admits(idx) {
			t.Fatalf("nil filter rejected %d", idx)
		}
	}
	only := frameFilter(func(idx int) bool { return idx == 2 })
	if only.admits(1) || !only.admits(2) {
		t.Fatal("non-nil filter ignored its predicate")
	}
	frames := jumpMatchFrames()
	if frameNavigable(len(frames), frames, nil) || frameNavigable(-1, frames, nil) {
		t.Fatal("frameNavigable admitted an out-of-range index")
	}
}

func TestSelectionManagerSelectFrame(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)
	s := newSelectionManager()

	if !s.selectFrame(frames, ancestry, 1) {
		t.Fatal("selectFrame(1) failed")
	}
	want := map[int]bool{0: true, 1: true, 2: true}
	if s.selected() != 1 || !maps.Equal(s.subtree(), want) {
		t.Fatalf("selected=%d subtree=%v, want 1 and %v", s.selected(), s.subtree(), want)
	}
	if got := s.selectedPath(frames); got != frames[1].Path {
		t.Fatalf("selectedPath = %q, want %q", got, frames[1].Path)
	}

	for _, idx := range []int{-1, len(frames)} {
		if s.selectFrame(frames, ancestry, idx) {
			t.Fatalf("selectFrame(%d) succeeded", idx)
		}
		if s.selected() != 1 || !maps.Equal(s.subtree(), want) {
			t.Fatalf("rejected selectFrame(%d) changed state: selected=%d subtree=%v", idx, s.selected(), s.subtree())
		}
	}
}

func TestSelectionManagerSelectedPathOutOfRange(t *testing.T) {
	s := newSelectionManager()
	if got := s.selectedPath(nil); got != "" {
		t.Fatalf("selectedPath with no frames = %q, want empty", got)
	}
	s.selectedIdx = 7
	if got := s.selectedPath(jumpMatchFrames()); got != "" {
		t.Fatalf("selectedPath out of range = %q, want empty", got)
	}
}

func TestSelectionManagerMovementHonoursFilter(t *testing.T) {
	frames := jumpMatchFrames() // root -> {a -> a1, b}
	s := newSelectionManager()

	s.moveVertical(frames, 1, nil)
	if s.selected() != 1 {
		t.Fatalf("unfiltered deeper move selected %d, want 1 (a)", s.selected())
	}

	s.selectedIdx = 0
	onlyB := frameFilter(func(idx int) bool { return idx == 0 || idx == 3 })
	s.moveVertical(frames, 1, onlyB)
	if s.selected() != 3 {
		t.Fatalf("filtered deeper move selected %d, want 3 (b)", s.selected())
	}

	// A selection hidden by the filter is moved onto a navigable frame,
	// preferring a match.
	s.selectedIdx = 2
	s.ensureNavigable(frames, map[int]bool{3: true}, onlyB)
	if s.selected() != 3 {
		t.Fatalf("ensureNavigable selected %d, want match 3", s.selected())
	}
	// With nothing navigable the selection stays put rather than landing on a
	// hidden frame.
	s.selectedIdx = 1
	s.ensureNavigable(frames, nil, func(int) bool { return false })
	if s.selected() != 1 {
		t.Fatalf("ensureNavigable with nothing navigable moved selection to %d", s.selected())
	}
}

func TestSelectionManagerJumpToMatch(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)
	s := newSelectionManager()
	s.selectFrame(frames, ancestry, 1)
	before := maps.Clone(s.subtree())

	s.jumpToMatch(frames, ancestry, nil, 1)
	if s.selected() != 1 || !maps.Equal(s.subtree(), before) {
		t.Fatalf("jump without matches changed selection: %d %v", s.selected(), s.subtree())
	}

	s.jumpToMatch(frames, ancestry, map[int]bool{3: true}, 1)
	if want := map[int]bool{0: true, 3: true}; s.selected() != 3 || !maps.Equal(s.subtree(), want) {
		t.Fatalf("jump to match: selected=%d subtree=%v, want 3 and %v", s.selected(), s.subtree(), want)
	}
}

func TestSelectionManagerResetClearsInPlace(t *testing.T) {
	frames := jumpMatchFrames()
	s := newSelectionManager()
	s.selectFrame(frames, buildFrameAncestry(frames), 2)
	set := s.subtree()

	s.reset()
	if s.selected() != 0 || len(s.subtree()) != 0 {
		t.Fatalf("reset left state: selected=%d subtree=%v", s.selected(), s.subtree())
	}
	set[99] = true
	if !s.subtree()[99] {
		t.Fatal("reset replaced the subtree map instead of clearing it in place")
	}
}
