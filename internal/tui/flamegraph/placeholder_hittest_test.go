package flamegraph

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// placeholderSnapshot is a small tree whose layout has frames on several rows,
// so a hit test that ignores the placeholder states has plenty of cells to
// wrongly resolve.
func placeholderSnapshot() *snapshotNode {
	return &snapshotNode{Name: "root", Total: 100, Children: []*snapshotNode{
		{Name: "A", Total: 60, Children: []*snapshotNode{
			{Name: "A1", Total: 30},
			{Name: "A2", Total: 30},
		}},
		{Name: "B", Total: 40},
	}}
}

// countHits returns how many cells of a width x height terminal resolve to a
// frame through frameIndexAt.
func countHits(frames []tuiFrame, width, height int) int {
	hits := 0
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if frameIndexAt(frames, x, y, width, height, false, false) >= 0 {
				hits++
			}
		}
	}
	return hits
}

// TestFrameIndexAtIgnoresCellsUnderGeometryPlaceholders covers the
// "terminal too narrow" and "viewport too short" placeholders: RenderTerminalView
// draws only a message there, so no cell may resolve to a frame, whether the
// frames were laid out for the narrow width or are stale from a wider one.
func TestFrameIndexAtIgnoresCellsUnderGeometryPlaceholders(t *testing.T) {
	const height = 20
	for _, tc := range []struct {
		name          string
		layoutWidth   int
		width, height int
		wantText      string
	}{
		{"narrow, laid out narrow", 50, 50, height, "terminal too narrow"},
		{"narrow, frames stale from wide layout", 90, 50, height, "terminal too narrow"},
		{"just under the minimum", 90, minFlameWidth - 1, height, "terminal too narrow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := buildTerminalLayout(placeholderSnapshot(), tc.layoutWidth, tc.height)
			out := RenderTerminalView(RenderContext{Frames: frames, Width: tc.width, Height: tc.height - 1, MetricLabel: "events"})
			if !strings.Contains(out, tc.wantText) {
				t.Fatalf("precondition: view does not show the placeholder %q:\n%s", tc.wantText, out)
			}
			if got := countHits(frames, tc.width, tc.height); got != 0 {
				t.Fatalf("%d cells still resolve to frames under the %q placeholder", got, tc.wantText)
			}
		})
	}
}

// TestFrameIndexAtStillHitsAtMinimumWidth is the negative control: exactly
// minFlameWidth columns draw a real flamegraph, so its frames stay hittable.
func TestFrameIndexAtStillHitsAtMinimumWidth(t *testing.T) {
	frames := buildTerminalLayout(placeholderSnapshot(), minFlameWidth, 20)
	if got := countHits(frames, minFlameWidth, 20); got == 0 {
		t.Fatal("no cell resolves to a frame at the minimum width")
	}
}

// TestFrameIndexAtAgreesWithPlaceholderDecision pins the shared predicate: a
// frame-less layout is the "waiting for data" placeholder for both sides.
func TestFrameIndexAtAgreesWithPlaceholderDecision(t *testing.T) {
	if _, ok := layoutPlaceholder(80, 10, 0); !ok {
		t.Fatal("no frames must be a placeholder")
	}
	if _, ok := layoutPlaceholder(80, 10, 3); ok {
		t.Fatal("a drawable viewport with frames must not be a placeholder")
	}
	if got := frameIndexAt(nil, 5, 5, 80, 20, false, false); got != -1 {
		t.Fatalf("frameIndexAt without frames = %d, want -1", got)
	}
}

// commitSearch opens the search input, types query and commits it with Enter.
func commitSearch(t *testing.T, m *Model, query string) *Model {
	t.Helper()
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	for _, r := range query {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	return pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
}

// TestMouseClickIgnoredWhileFilterMatchesNothing is the regression test for
// the "no frames match filter" placeholder: the model still holds frames, but
// the view draws only the message, so a click must neither zoom nor select.
func TestMouseClickIgnoredWhileFilterMatchesNothing(t *testing.T) {
	m := newZoomModel()
	targetIdx := mustFrameIndex(t, m.anim.frames, "root"+pathSeparator+"A")
	x, y, ok := firstClickablePointForFrame(m, targetIdx)
	if !ok {
		t.Fatal("expected a clickable point for A before filtering")
	}

	m = commitSearch(t, m, "zzz")
	if !strings.Contains(m.View().Content, "no frames match filter") {
		t.Fatalf("precondition: view does not show the filter placeholder:\n%s", m.View().Content)
	}
	beforeSel, beforeZoom := m.sel.selectedIdx, m.zoom.zoomPath

	for cy := 0; cy < m.height; cy++ {
		for cx := 0; cx < m.width; cx++ {
			if got := m.frameIndexAt(cx, cy); got != -1 {
				t.Fatalf("cell (%d,%d) resolves to frame %d under the filter placeholder", cx, cy, got)
			}
		}
	}
	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	m = next.(*Model)
	if m.zoom.zoomPath != beforeZoom || m.sel.selectedIdx != beforeSel {
		t.Fatalf("click under the placeholder changed state: zoom %q->%q selection %d->%d",
			beforeZoom, m.zoom.zoomPath, beforeSel, m.sel.selectedIdx)
	}
}

// TestMouseClickStillZoomsWhileFilterMatches is the negative control: a filter
// with matches draws the flamegraph, so clicks keep working.
func TestMouseClickStillZoomsWhileFilterMatches(t *testing.T) {
	m := newZoomModel()
	m = commitSearch(t, m, "a1")
	if strings.Contains(m.View().Content, "no frames match filter") {
		t.Fatal("precondition: query a1 must match frames")
	}
	targetPath := "root" + pathSeparator + "A"
	x, y, ok := firstClickablePointForFrame(m, mustFrameIndex(t, m.anim.frames, targetPath))
	if !ok {
		t.Fatal("expected a clickable point for A")
	}
	next, _ := m.Update(tea.MouseClickMsg{X: x, Y: y, Button: tea.MouseLeft})
	if got := next.(*Model).zoom.zoomPath; got != targetPath {
		t.Fatalf("click with a matching filter zoomed to %q, want %q", got, targetPath)
	}
}

// TestMouseClickIgnoredWhenTerminalTooNarrow drives the same regression
// through the model: after a resize below minFlameWidth the view shows the
// "terminal too narrow" message and a click anywhere must do nothing.
func TestMouseClickIgnoredWhenTerminalTooNarrow(t *testing.T) {
	m := newZoomModel()
	next, _ := m.Update(tea.WindowSizeMsg{Width: 50, Height: 30})
	m = next.(*Model)
	if !strings.Contains(m.View().Content, "terminal too narrow") {
		t.Fatalf("precondition: view does not show the narrow placeholder:\n%s", m.View().Content)
	}
	beforeSel, beforeZoom := m.sel.selectedIdx, m.zoom.zoomPath
	for cy := 0; cy < m.height; cy++ {
		for cx := 0; cx < m.width; cx++ {
			next, _ = m.Update(tea.MouseClickMsg{X: cx, Y: cy, Button: tea.MouseLeft})
			m = next.(*Model)
			// Check after every click: later clicks could undo an earlier
			// zoom (an ancestor click re-roots) and hide the change.
			if m.zoom.zoomPath != beforeZoom || m.sel.selectedIdx != beforeSel {
				t.Fatalf("click at (%d,%d) under the narrow placeholder changed state: zoom %q->%q selection %d->%d",
					cx, cy, beforeZoom, m.zoom.zoomPath, beforeSel, m.sel.selectedIdx)
			}
		}
	}
}
