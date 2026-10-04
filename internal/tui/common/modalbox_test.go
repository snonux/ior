package common

import (
	"slices"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// TestFitHintKeepsWholeSegments pins the key hint's narrowing: whole
// segments while the first fits, a marked cut below that, nothing at zero.
// (Moved from the export package with the function, task rz2.)
func TestFitHintKeepsWholeSegments(t *testing.T) {
	hint := "Enter confirm" + HintSep + "Esc cancel"
	cases := map[int]string{
		40: hint,
		26: hint,
		25: "Enter confirm",
		13: "Enter confirm",
		5:  "Ente…",
		1:  "E",
		0:  "",
	}
	for width, want := range cases {
		if got := FitHint(hint, width); got != want {
			t.Fatalf("FitHint(%d) = %q, want %q", width, got, want)
		}
	}
}

// TestModalBoxWidth pins the width policy every modal box shares.
func TestModalBoxWidth(t *testing.T) {
	cases := map[int]int{200: 64, 68: 64, 67: 63, 44: 40, 41: 40, 40: 40, 20: 20, 7: 7, 6: 7, 1: 7, 0: 7}
	for width, want := range cases {
		if got := ModalBoxWidth(64, 40, width); got != want {
			t.Errorf("ModalBoxWidth(64, 40, %d) = %d, want %d", width, got, want)
		}
	}
	if got := ModalTextWidth(ModalBoxWidth(64, 40, 6), 6); got != 6 {
		t.Errorf("ModalTextWidth at 6 columns = %d, want the view's 6 (bare)", got)
	}
	if got := ModalTextWidth(ModalBoxWidth(64, 40, 80), 80); got != 58 {
		t.Errorf("ModalTextWidth at 80 columns = %d, want 58", got)
	}
}

// TestKeepRanked pins the bare fallback's selection: the lowest ranks, in
// display order, the earlier line first among equal ranks.
func TestKeepRanked(t *testing.T) {
	lines := []RankedLine{{"title", 3}, {"input", 0}, {"err", 2}, {"hint", 1}, {"note", 2}}
	cases := map[int][]string{
		0: nil,
		1: {"input"},
		2: {"input", "hint"},
		3: {"input", "err", "hint"},
		4: {"input", "err", "hint", "note"},
		9: {"title", "input", "err", "hint", "note"},
	}
	for rows, want := range cases {
		if got := KeepRanked(lines, rows); !slices.Equal(got, want) {
			t.Fatalf("KeepRanked(%d) = %q, want %q", rows, got, want)
		}
	}
}

// TestPlaceModalFitsEverySize sweeps PlaceModal over 1x1..60x12 with a
// layout ladder whose lines hold wide runes and emoji: the frame is exactly
// width x height (lipgloss and ansi measures agree), the box is drawn
// whenever its most compact layout fits and its border is whole, and the
// bare fallback keeps the top-ranked line. A plain byte or rune trim instead
// of the grapheme cut lets a two-cell rune through one cell too wide.
func TestPlaceModalFitsEverySize(t *testing.T) {
	layouts := []ModalLayout{
		{Lines: []string{"Title 日本語", "", "input 😀😀😀😀", "", "hint • more"}, VPad: true},
		{Lines: []string{"Title 日本語", "input 😀😀😀😀", "hint • more"}},
		{Lines: []string{"input 😀😀😀😀", "hint"}},
	}
	bare := []RankedLine{{"Title 日本語", 2}, {"input 😀😀😀😀", 0}, {"hint", 1}}
	for width := 1; width <= 60; width++ {
		for height := 1; height <= 12; height++ {
			out := PlaceModal(width, height, ModalBoxWidth(40, 20, width), layouts, bare)
			lines := strings.Split(out, "\n")
			if len(lines) != height || lipgloss.Height(out) != height {
				t.Fatalf("%dx%d: %d rows", width, height, len(lines))
			}
			for _, line := range lines {
				if lipgloss.Width(line) != width || ansi.StringWidth(line) != width {
					t.Fatalf("%dx%d: line %q is %d/%d cells", width, height, line, lipgloss.Width(line), ansi.StringWidth(line))
				}
			}
			boxed := strings.Contains(out, "╭")
			if wantBox := width >= ModalBoxChrome+1 && height >= 4; boxed != wantBox {
				t.Fatalf("%dx%d: boxed=%v, want %v:\n%s", width, height, boxed, wantBox, out)
			}
			if boxed && (!strings.Contains(out, "╰") || (width >= ModalBoxChrome+4 && !strings.Contains(out, "hint"))) {
				t.Fatalf("%dx%d: box without bottom border or hint:\n%s", width, height, out)
			}
			if !boxed && width >= 2 && !strings.Contains(out, "i") {
				t.Fatalf("%dx%d: bare modal lost its input line:\n%s", width, height, out)
			}
		}
	}
}

// TestPlaceModalNonPositiveSizes checks zero and negative sizes are taken
// as one cell, without a panic.
func TestPlaceModalNonPositiveSizes(t *testing.T) {
	for _, size := range [][2]int{{0, 0}, {-3, 5}, {5, -1}} {
		out := PlaceModal(size[0], size[1], 7, []ModalLayout{{Lines: []string{"x"}}}, []RankedLine{{"x", 0}})
		if lipgloss.Height(out) != max(size[1], 1) || lipgloss.Width(out) != max(size[0], 1) {
			t.Fatalf("%v: %q", size, out)
		}
	}
}

// TestFitSegmentsKeepsWholeSegmentsWithAnyJoinerAndTail (task sz2): the stream
// footer and the stream/export modal hints all narrow through FitSegments, with
// different separators and tails; whole segments only, the first cut with the
// tail when it alone is too wide, nothing for a non-positive width.
func TestFitSegmentsKeepsWholeSegmentsWithAnyJoinerAndTail(t *testing.T) {
	segments := []string{"Sel 3/9", "Esc/F undo", "Row 3/9"}
	tests := []struct {
		width int
		want  string
	}{
		{0, ""},
		{-3, ""},
		{4, TruncateRight("Sel 3/9", 4, "~")},
		{7, "Sel 3/9"},
		{19, "Sel 3/9"},
		{20, "Sel 3/9 | Esc/F undo"},
		{29, "Sel 3/9 | Esc/F undo"},
		{30, "Sel 3/9 | Esc/F undo | Row 3/9"},
	}
	for _, tc := range tests {
		if got := FitSegments(segments, " | ", "~", tc.width); got != tc.want {
			t.Errorf("width %d: %q, want %q", tc.width, got, tc.want)
		}
	}
	if got := FitSegments(nil, " | ", "~", 40); got != "" {
		t.Errorf("no segments: %q, want empty", got)
	}
}
