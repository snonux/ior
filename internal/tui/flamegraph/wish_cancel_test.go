package flamegraph

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

func mouseLeftClick(x, y int) tea.MouseClickMsg {
	return tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft}
}

// These tests pin that every user-driven selection change ends a pending
// selection wish (SelectionManager.wantedPath) on the paths where nothing
// else would: the wish is a memory of a frame the layout lost, and it must
// not pull the selection back after the user chose otherwise. Each test
// asserts both the state (no wish left) and the behavior (a later layout
// rebuild does not jump to the wished frame).

// siblingFrames is a layout with a real sibling pair at depth 1 (a, b), so
// moveSibling has somewhere to go besides the traversal fallback.
func siblingFrames() []tuiFrame {
	return jumpMatchFrames() // root, a, a1, b: a and b are the depth-1 siblings
}

// wishAt returns a manager selecting frames[idx] with a pending wish for path.
func wishAt(idx int, path string) SelectionManager {
	s := newSelectionManager()
	s.selectedIdx = idx
	s.wish(path)
	return s
}

// TestMoveSiblingBetweenRealSiblingsCancelsTheWish drives the branch of
// moveSibling that moves between siblings itself (it never reaches
// moveTraversal, which would cancel anyway), in both directions, plus the
// no-frames early return.
func TestMoveSiblingBetweenRealSiblingsCancelsTheWish(t *testing.T) {
	fakeWishClock(t)
	full := siblingFrames()
	const gone = "root/gone/elsewhere"

	s := wishAt(1, gone) // on a
	s.moveSibling(full, 1, nil)
	if got := s.selectedPath(full); got != full[3].Path {
		t.Fatalf("next sibling of a = %q, want %q", got, full[3].Path)
	}
	if s.wantedPath != "" {
		t.Errorf("moving to the next sibling left the wish %q", s.wantedPath)
	}

	s = wishAt(3, gone) // on b
	s.moveSibling(full, -1, nil)
	if got := s.selectedPath(full); got != full[1].Path {
		t.Fatalf("previous sibling of b = %q, want %q", got, full[1].Path)
	}
	if s.wantedPath != "" {
		t.Errorf("moving to the previous sibling left the wish %q", s.wantedPath)
	}

	s = wishAt(1, gone)
	s.moveSibling(nil, 1, nil)
	if s.wantedPath != "" {
		t.Errorf("moveSibling with no frames left the wish %q", s.wantedPath)
	}
}

// wishedZoomModel returns a static two-level model whose selection is on
// path and which wishes for root/B, a frame that exists: were the wish not
// cancelled, the next rebuild would jump to (or toward) it.
func wishedZoomModel(t *testing.T, path string) *Model {
	t.Helper()
	fakeWishClock(t)
	m := newZoomModel()
	frames := m.anim.currentFrames()
	if !m.sel.selectFrame(frames, m.anim.currentAncestry(), mustFrameIndex(t, frames, path)) {
		t.Fatalf("cannot select %q", path)
	}
	m.sel.wish("root" + pathSeparator + "B")
	return m
}

func requireWishGone(t *testing.T, m *Model, action string) {
	t.Helper()
	if m.sel.wantedPath != "" {
		t.Fatalf("%s left the wish %q pending", action, m.sel.wantedPath)
	}
}

func requireSelected(t *testing.T, m *Model, want, action string) {
	t.Helper()
	if got := m.sel.selectedPath(m.anim.currentFrames()); got != want {
		t.Fatalf("selected %q after %s, want %q (a pending wish pulled it away)", got, action, want)
	}
}

func TestZoomInCancelsTheWish(t *testing.T) {
	a := "root" + pathSeparator + "A"
	m := wishedZoomModel(t, a)
	m.zoomIn()
	if m.zoom.path() != a {
		t.Fatalf("zoom path = %q, want %q", m.zoom.path(), a)
	}
	requireWishGone(t, m, "zoomIn")
	requireSelected(t, m, a, "zoomIn")
}

// TestZoomInNoOpCancelsTheWish: "zoom unchanged" is still a user key press.
func TestZoomInNoOpCancelsTheWish(t *testing.T) {
	m := wishedZoomModel(t, "root")
	m.zoomIn()
	requireWishGone(t, m, "a no-op zoomIn")
}

func TestZoomUndoCancelsTheWish(t *testing.T) {
	a := "root" + pathSeparator + "A"
	m := wishedZoomModel(t, a)
	m.zoomIn()
	m.sel.wish("root" + pathSeparator + "B")
	m.zoomUndo()
	if m.zoom.path() != "" {
		t.Fatalf("zoom path = %q after undo, want the root", m.zoom.path())
	}
	requireWishGone(t, m, "zoomUndo")
	requireSelected(t, m, a, "zoomUndo")
}

// TestZoomUndoUnavailableCancelsTheWish: undo with an empty stack changes
// nothing visible but is still the user's move.
func TestZoomUndoUnavailableCancelsTheWish(t *testing.T) {
	m := wishedZoomModel(t, "root"+pathSeparator+"A")
	m.zoomUndo()
	requireWishGone(t, m, "an unavailable zoomUndo")
}

func TestZoomResetCancelsTheWish(t *testing.T) {
	a := "root" + pathSeparator + "A"
	m := wishedZoomModel(t, a)
	m.zoomIn()
	m.sel.wish("root" + pathSeparator + "B")
	m.zoomReset()
	if m.zoom.path() != "" {
		t.Fatalf("zoom path = %q after reset, want the root", m.zoom.path())
	}
	requireWishGone(t, m, "zoomReset")
	requireSelected(t, m, a, "zoomReset")
}

// TestZoomResetAtRootCancelsTheWish: "already at root" is still a user key.
func TestZoomResetAtRootCancelsTheWish(t *testing.T) {
	m := wishedZoomModel(t, "root"+pathSeparator+"A")
	m.zoomReset()
	requireWishGone(t, m, "a no-op zoomReset")
}

// TestMouseClickCancelsTheWish covers a click that zooms, a click on the
// current root, and a click whose zoom fails (no snapshot to descend into):
// the last returns before any selection code, so only the click's own
// cancelWish can end the wish there.
func TestMouseClickCancelsTheWish(t *testing.T) {
	click := func(t *testing.T, m *Model, path string) bool {
		t.Helper()
		x, y, ok := firstClickablePointForFrame(m, mustFrameIndex(t, m.anim.frames, path))
		if !ok {
			t.Fatalf("no clickable point for %q", path)
		}
		return m.handleMouseClick(mouseLeftClick(x, y))
	}

	t.Run("zoom", func(t *testing.T) {
		m := wishedZoomModel(t, "root")
		a := "root" + pathSeparator + "A"
		if !click(t, m, a) {
			t.Fatalf("click on %q was not handled", a)
		}
		requireWishGone(t, m, "a zooming click")
		requireSelected(t, m, a, "a zooming click")
	})
	t.Run("current root", func(t *testing.T) {
		m := wishedZoomModel(t, "root"+pathSeparator+"A")
		if !click(t, m, "root") {
			t.Fatalf("click on the current root was not handled")
		}
		requireWishGone(t, m, "a click on the root")
		requireSelected(t, m, "root", "a click on the root")
	})
	t.Run("failed zoom", func(t *testing.T) {
		m := wishedZoomModel(t, "root")
		a := "root" + pathSeparator + "A"
		x, y, ok := firstClickablePointForFrame(m, mustFrameIndex(t, m.anim.frames, a))
		if !ok {
			t.Fatalf("no clickable point for %q", a)
		}
		m.snapshot = nil // the zoom cannot resolve its target
		if m.handleMouseClick(mouseLeftClick(x, y)) {
			t.Fatalf("expected the zoom to fail")
		}
		requireWishGone(t, m, "a click whose zoom failed")
	})
}

// TestSearchApplyCancelsTheWish: a query that leaves the selection where it
// is (no match, or the filter cleared) still is a decision about it, and
// only followSearchResult's cancel ends the wish on that path.
func TestSearchApplyCancelsTheWish(t *testing.T) {
	for name, query := range map[string]string{
		"no match":       "no-such-frame-anywhere",
		"filter cleared": "",
	} {
		t.Run(name, func(t *testing.T) {
			m := wishedZoomModel(t, "root"+pathSeparator+"A")
			m.applySearchQuery(query)
			requireWishGone(t, m, "applying the query")
		})
	}
	t.Run("match", func(t *testing.T) {
		m := wishedZoomModel(t, "root")
		m.applySearchQuery("A1")
		requireWishGone(t, m, "applying a matching query")
		requireSelected(t, m, "root"+pathSeparator+"A"+pathSeparator+"A1", "applying a matching query")
	})
}
