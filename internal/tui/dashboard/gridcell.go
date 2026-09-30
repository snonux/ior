package dashboard

import (
	"fmt"
	"image/color"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// gridCell is one terminal cell of the bubbles, treemap and icicle charts.
// Those charts paint into a [][]gridCell whose width is the view width, and
// every row must render to exactly that many terminal cells.
//
// Fills and blanks are single one-cell runes (char). Label text is placed
// grapheme by grapheme (writeGridLabel) into cluster, so multi-rune clusters
// (emoji ZWJ sequences, flags, base + combining mark) stay intact and are
// never split across cells. A two-cell cluster (CJK, most emoji) occupies its
// own cell plus the next one, which is marked cont and renders nothing, so
// the row width stays equal to the number of cells.
type gridCell struct {
	char      rune   // one-cell glyph; used when cluster is empty
	cluster   string // grapheme cluster overriding char (label text)
	cont      bool   // right half of the two-cell cluster in the previous cell
	colorSlot int    // palette slot; negative means uncoloured
	bold      bool
}

// glyph returns the text the cell renders: "" for a continuation cell,
// otherwise its grapheme cluster or rune.
func (c gridCell) glyph() string {
	switch {
	case c.cont:
		return ""
	case c.cluster != "":
		return c.cluster
	default:
		return string(c.char)
	}
}

// newGridRows returns height rows of width blank, uncoloured cells.
func newGridRows(width, height int) [][]gridCell {
	grid := make([][]gridCell, height)
	for row := range grid {
		grid[row] = make([]gridCell, width)
		for col := range grid[row] {
			grid[row][col] = gridCell{char: ' ', colorSlot: -1}
		}
	}
	return grid
}

// abbreviateLabel fits a chart label into at most maxCells terminal cells,
// cutting on grapheme boundaries with a trailing "…" (common.TruncateRight,
// so a wide rune is never split and CJK/emoji labels cannot overflow the
// tile or bubble). A single-cell budget shows just "…" for any wider label.
// A blank label becomes "?" so the tile is still marked.
//
// Leading and trailing blanks are deliberately kept, not trimmed: dir rows
// are keyed by their literal text (dirRowLabel), so "/tmp/a" and "/tmp/a "
// are different rows, and trimming would render them identically. The kept
// blank shows as an empty cell inside the tile or bubble, and the status line
// prints the full label. Labels are expected to be sanitised already
// (common.Sanitize via dirRowLabel/processLabel), so every rune has a
// well-defined width.
func abbreviateLabel(label string, maxCells int) string {
	if maxCells <= 0 {
		return ""
	}
	if strings.TrimSpace(label) == "" {
		label = "?"
	}
	if maxCells == 1 && common.DisplayWidth(label) > 1 {
		// The shared marker rule would hard-cut to the first letter here,
		// making a cut label look like a real one-letter label; the charts
		// prefer the unambiguous "…".
		return common.Ellipsis
	}
	return common.TruncateRight(label, maxCells, common.Ellipsis)
}

// writeGridLabel paints label into row starting at column start, one
// grapheme cluster at a time: a one-cell cluster takes one cell, a two-cell
// cluster takes its cell plus a continuation cell. Columns outside the row
// are skipped, and a two-cell cluster that does not fit completely (straddling
// either edge) is dropped rather than half-drawn. Zero-width clusters (a lone
// combining mark) are dropped as they have no cell of their own. It returns
// the column after the label.
func writeGridLabel(row []gridCell, start int, label string, colorSlot int, bold bool) int {
	col := start
	for label != "" {
		cluster, w := ansi.FirstGraphemeCluster(label, ansi.GraphemeWidth)
		label = label[len(cluster):]
		if w <= 0 {
			continue
		}
		if col >= 0 && col+w <= len(row) {
			setGridCell(row, col, gridCell{cluster: cluster, colorSlot: colorSlot, bold: bold})
			for i := 1; i < w; i++ {
				setGridCell(row, col+i, gridCell{cont: true, colorSlot: colorSlot, bold: bold})
			}
		}
		col += w
	}
	return col
}

// setGridCell stores cell at row[col] and keeps any wide cluster it
// overwrites consistent: overwriting half of an existing two-cell cluster
// blanks the other half, so the row never renders a wide glyph plus an
// extra cell (too wide) or an orphaned continuation (too narrow).
func setGridCell(row []gridCell, col int, cell gridCell) {
	old := row[col]
	if old.cont && col > 0 {
		row[col-1] = blankLike(row[col-1])
	}
	if !old.cont && col+1 < len(row) && row[col+1].cont {
		row[col+1] = blankLike(row[col+1])
	}
	row[col] = cell
}

// blankLike returns a one-cell blank keeping c's colour, used to repair the
// other half of a wide cluster that was partly overwritten.
func blankLike(c gridCell) gridCell {
	return gridCell{char: ' ', colorSlot: c.colorSlot, bold: c.bold}
}

// renderGridRow renders one chart row. Coloured cells are styled with their
// palette slot (the selected item in the highlight colour and bold);
// continuation cells emit nothing, as their cluster already covers them.
func renderGridRow(cells []gridCell, palette []color.Color) string {
	if len(cells) == 0 {
		return ""
	}
	var b strings.Builder
	styleCache := make(map[string]lipgloss.Style, 8)
	selectedColor := lipgloss.Color("129")
	for _, cell := range cells {
		// Fast path for the dominant plain cell (blank background, one-rune
		// glyph): WriteRune avoids the per-cell string allocation of glyph().
		if cell.colorSlot < 0 && !cell.bold && !cell.cont && cell.cluster == "" {
			b.WriteRune(cell.char)
			continue
		}
		glyph := cell.glyph()
		if glyph == "" {
			continue
		}
		if cell.colorSlot < 0 {
			if cell.bold {
				b.WriteString(lipgloss.NewStyle().Bold(true).Render(glyph))
			} else {
				b.WriteString(glyph)
			}
			continue
		}
		slot := cell.colorSlot
		if len(palette) > 0 {
			slot = slot % len(palette)
		}
		key := fmt.Sprintf("%d/%t", slot, cell.bold)
		style, ok := styleCache[key]
		if !ok {
			style = lipgloss.NewStyle().Foreground(palette[slot])
			if cell.bold {
				style = style.Foreground(selectedColor).Bold(true)
			}
			styleCache[key] = style
		}
		b.WriteString(style.Render(glyph))
	}
	return b.String()
}
