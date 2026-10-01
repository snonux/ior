package common

import (
	"slices"
	"strings"

	"charm.land/lipgloss/v2"
)

// The pieces in this file draw the TUI's modal boxes so that they never
// outgrow the view they are drawn in: lipgloss.Place only pads, it returns a
// box taller or wider than the view unchanged, and the terminal then scrolls
// (task ns2 for the export modal, task rz2 for the filter, record and probes
// modals, which used them first). A modal lists its arrangements from roomy
// to compact (ModalLayout), the first whose box fits is drawn, and below the
// most compact box a borderless fallback keeps the most important lines
// (RankedLine, PlaceModal).

// ModalBoxChrome is the cells a modal box spends on its rounded border and
// two cells of horizontal padding on each side.
const ModalBoxChrome = 2 + 2*2

// HintSep separates the segments of a modal's key hint ("Enter start • Esc
// cancel"), which FitHint drops whole.
const HintSep = " • "

// ModalBoxWidth is the width of a modal box in a view width cells wide: the
// preferred width with a two-cell margin on each side, not narrower than
// minWidth while that fits, never wider than the view, and at least one text
// cell wide (ModalBoxChrome+1, so a view narrower than seven columns gets a
// box wider than itself: PlaceModal draws bare there, the export overlay's
// canvas clips).
func ModalBoxWidth(preferred, minWidth, width int) int {
	boxWidth := max(min(preferred, width-4), minWidth)
	return max(min(boxWidth, width), ModalBoxChrome+1)
}

// ModalTextWidth is the cells a modal's text line has in a view width cells
// wide whose box is boxWidth cells wide: the box's text width, or the view's
// width where PlaceModal draws the modal bare because the view is narrower
// than a box with a text cell. It is at least one.
func ModalTextWidth(boxWidth, width int) int {
	if width < ModalBoxChrome+1 {
		return max(width, 1)
	}
	return max(boxWidth-ModalBoxChrome, 1)
}

// RenderModalBox boxes lines in a rounded border boxWidth cells wide with two
// cells of horizontal padding and, with vpad, one blank row above and below.
// Each line is cut to the box's text width first (CutLine, grapheme- and
// ANSI-aware), so no line wraps inside the box: lipgloss's own wrap of a
// word longer than a narrow box let lines through wider than the box, and a
// wrapped line would add rows the caller's height budget did not count.
func RenderModalBox(lines []string, vpad bool, boxWidth int) string {
	textWidth := max(boxWidth-ModalBoxChrome, 1)
	cut := make([]string, len(lines))
	for i, line := range lines {
		cut[i] = CutLine(line, textWidth, "")
	}
	vertical := 0
	if vpad {
		vertical = 1
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(vertical, 2).
		Width(boxWidth).
		Render(strings.Join(cut, "\n"))
}

// CutLine cuts line to width cells (TruncateRight: grapheme- and
// ANSI-aware), ending in tail when cut; a line that fits is returned as is.
func CutLine(line string, width int, tail string) string {
	if DisplayWidth(line) <= width {
		return line
	}
	return TruncateRight(line, width, tail)
}

// FitSegments joins segments with sep, keeping the longest prefix of whole
// segments that fits width cells, so a narrow modal drops "• Esc cancel"
// rather than showing "Esc cance". Only when not even the first segment fits
// is it cut, ending in tail (TruncateRight's marker rule: in a one-cell
// width the first letter is kept instead). Segments must be sanitised
// already. A width of zero or less yields "".
func FitSegments(segments []string, sep, tail string, width int) string {
	if len(segments) == 0 || width <= 0 {
		return ""
	}
	line := segments[0]
	if DisplayWidth(line) > width {
		return TruncateRight(line, width, tail)
	}
	for _, seg := range segments[1:] {
		next := line + sep + seg
		if DisplayWidth(next) > width {
			break
		}
		line = next
	}
	return line
}

// FitHint fits a HintSep-separated key hint to width cells by whole
// segments (FitSegments), cutting the first with Ellipsis only when it alone
// is too wide.
func FitHint(hint string, width int) string {
	return FitSegments(strings.Split(hint, HintSep), HintSep, Ellipsis, width)
}

// ModalLayout is one arrangement of a modal box: its text lines (cut to the
// box's text width by RenderModalBox) and whether the box keeps a blank row
// of padding above and below them.
type ModalLayout struct {
	Lines []string
	VPad  bool
}

// RankedLine is a line of a modal's borderless fallback with its rank: when
// the view has fewer rows than lines, the lowest ranks are kept (KeepRanked).
type RankedLine struct {
	Text string
	Rank int
}

// KeepRanked keeps the rows lines of lowest rank, in their order in lines;
// of equal ranks the earlier line is kept. rows of zero or less keeps none.
func KeepRanked(lines []RankedLine, rows int) []string {
	if rows <= 0 {
		return nil
	}
	order := make([]int, len(lines))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return lines[a].Rank - lines[b].Rank })
	keep := order[:min(rows, len(order))]
	slices.Sort(keep)
	out := make([]string, len(keep))
	for i, index := range keep {
		out[i] = lines[index].Text
	}
	return out
}

// PlaceModal draws a modal centred in a width x height view, exactly that
// size (both at least one; smaller values are taken as one). It boxes the
// first of layouts whose box (boxWidth cells wide, ModalBoxWidth) is at most
// height rows tall. When none is, or the view is narrower than a box with a
// text cell, it draws the modal bare instead: the bare lines that fit the
// height (KeepRanked), each cut to the width, without border or padding, so
// the most important lines (the input with its cursor, the key hint) stay
// on screen down to a 1x1 view.
func PlaceModal(width, height, boxWidth int, layouts []ModalLayout, bare []RankedLine) string {
	width, height = max(width, 1), max(height, 1)
	if width >= ModalBoxChrome+1 {
		for _, layout := range layouts {
			box := RenderModalBox(layout.Lines, layout.VPad, boxWidth)
			if lipgloss.Height(box) <= height {
				return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
			}
		}
	}
	lines := KeepRanked(bare, height)
	block := 0
	for i, line := range lines {
		lines[i] = CutLine(line, width, "")
		block = max(block, DisplayWidth(lines[i]))
	}
	// Pad the lines to one block width: lipgloss.Place leaves a block as
	// wide as the view unpadded, which would leave its shorter lines short
	// of the frame's width.
	for i, line := range lines {
		lines[i] = PadRight(line, block)
	}
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, strings.Join(lines, "\n"))
}
