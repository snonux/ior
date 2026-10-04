package flamegraph

import (
	"strings"
	"testing"

	"ior/internal/tui/common"

	"github.com/charmbracelet/x/ansi"
)

// Regression for task vp2: a frame named "1️⃣-report" made
// frameLabel (padOrTrim -> common.FitRight) return a label one cell wider
// than its span, because the cut counted the keycap as one cell while the
// terminal draws two. The row then overflowed its width and every later
// frame was drawn one cell right of its hit span (frameAtCell).
func TestRenderRowKeycapFrameNamesStayInsideTheirSpans(t *testing.T) {
	const width = 40
	for _, name := range []string{
		"1️⃣-report", "#️⃣#️⃣#️⃣x", "a️bcdefghij",
		"1️⃣1️⃣1️⃣1️⃣",
	} {
		for first := 1; first <= 14; first++ {
			frames := []indexedFrame{
				{idx: 0, frame: tuiFrame{Name: name, Col: 0, Width: first, Path: "a"}},
				{idx: 1, frame: tuiFrame{Name: "next", Col: first, Width: 12, Path: "b"}},
			}
			row := ansi.Strip(renderRow(frames, width, "", nil, nil, -1, true, true))
			if w := common.DisplayWidth(row); w != width {
				t.Fatalf("name %q first span %d: row is %d cells wide, want %d: %q", name, first, w, width, row)
			}
			// The second frame's label starts exactly where its hit span does.
			at := strings.Index(row, "next")
			if at < 0 {
				continue // too narrow to show "next" in full
			}
			if got := common.DisplayWidth(row[:at]); got != first {
				t.Fatalf("name %q first span %d: next drawn at cell %d, hit span starts at %d: %q", name, first, got, first, row)
			}
			for x := range width {
				want := -1
				switch {
				case x < first:
					want = 0
				case x < first+12:
					want = 1
				}
				if got := frameAtCell(frames, x, width); got != want {
					t.Fatalf("frameAtCell(%d) = %d, want %d", x, got, want)
				}
			}
		}
	}
}

// TestFrameLabelKeycapIsExactlyItsSpan is the direct check: a label is its
// span wide for keycap names whatever the span, and plain names are cut as
// before (negative check that the fix does not eat ordinary text).
func TestFrameLabelKeycapIsExactlyItsSpan(t *testing.T) {
	for width := 1; width <= 20; width++ {
		for _, name := range []string{"1️⃣-report", "plain-name-here", "日本語-report"} {
			if got := frameLabel(name, width, false, false); common.DisplayWidth(got) != width {
				t.Fatalf("frameLabel(%q, %d) = %q is %d cells wide", name, width, got, common.DisplayWidth(got))
			}
		}
	}
	if got := frameLabel("plain-name-here", 8, false, false); got != "plain-n…" {
		t.Fatalf("plain name cut = %q, want %q", got, "plain-n…")
	}
}
