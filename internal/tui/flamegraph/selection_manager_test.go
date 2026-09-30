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

// TestRestoreByPathSurvivesTheEmptyLayoutOfAReset: a baseline reset leaves a
// layout with only the root frame. The selection lands on root, but the path
// the user had selected stays wanted, so it comes back with the data instead of
// the root becoming the remembered path.
func TestRestoreByPathSurvivesTheEmptyLayoutOfAReset(t *testing.T) {
	full := jumpMatchFrames()
	rootOnly := full[:1]
	wanted := full[2].Path // root/a/a1

	s := newSelectionManager()
	s.selectedIdx = 2

	// Reset: only root is left. The selection falls back to it ...
	s.restoreByPath(rootOnly, s.selectedPath(full))
	if got := s.selectedPath(rootOnly); got != "root" {
		t.Fatalf("after the reset selected %q, want the root fallback", got)
	}
	// ... stays there over further empty layouts ...
	s.restoreByPath(rootOnly, s.selectedPath(rootOnly))
	// ... and returns to the wanted frame once it exists again.
	s.restoreByPath(full, s.selectedPath(rootOnly))
	if got := s.selectedPath(full); got != wanted {
		t.Fatalf("after the refill selected %q, want %q", got, wanted)
	}
	// Found exactly: nothing stays wanted, so later moves are not undone.
	s.selectedIdx = 3
	s.restoreByPath(full, s.selectedPath(full))
	if got := s.selectedPath(full); got != full[3].Path {
		t.Fatalf("selection moved to %q after being found", got)
	}
}

// TestRestoreByPathDropsTheWishWhenTheUserMoves: once the user moves off the
// fallback frame, the remembered path no longer applies.
func TestRestoreByPathDropsTheWishWhenTheUserMoves(t *testing.T) {
	full := jumpMatchFrames()
	rootOnly := full[:1]
	s := newSelectionManager()
	s.selectedIdx = 2
	s.restoreByPath(rootOnly, s.selectedPath(full))

	// The user picks another frame of a layout that still lacks root/a/a1.
	partial := []tuiFrame{full[0], full[3]}
	s.selectedIdx = 1
	s.restoreByPath(partial, s.selectedPath(partial))
	s.restoreByPath(full, s.selectedPath(partial))
	if got := s.selectedPath(full); got != "root"+pathSeparator+"b" {
		t.Fatalf("selected %q, want the user's root/b, not the abandoned root/a/a1", got)
	}
}

// TestRestoreByPathWithNoFramesRemembersThePath: a layout with no frame at all
// (nothing to fall back to) must not forget the selection either.
func TestRestoreByPathWithNoFramesRemembersThePath(t *testing.T) {
	full := jumpMatchFrames()
	s := newSelectionManager()
	s.selectedIdx = 2
	s.restoreByPath(nil, s.selectedPath(full))
	s.restoreByPath(nil, "")
	s.restoreByPath(full, "")
	if got := s.selectedPath(full); got != full[2].Path {
		t.Fatalf("selected %q, want %q", got, full[2].Path)
	}
}

// TestSelectionManagerResetForgetsTheWantedPath: a deliberate reset (the
// flame tab's own r key) returns to the first frame for good.
func TestSelectionManagerResetForgetsTheWantedPath(t *testing.T) {
	full := jumpMatchFrames()
	s := newSelectionManager()
	s.selectedIdx = 2
	s.restoreByPath(full[:1], s.selectedPath(full))
	s.reset()
	s.restoreByPath(full, s.selectedPath(full[:1]))
	if got := s.selectedPath(full); got != "root" {
		t.Fatalf("selected %q after reset, want root", got)
	}
}
