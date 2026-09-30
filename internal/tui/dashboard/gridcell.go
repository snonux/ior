package dashboard

import (
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

// selectedColor is the highlight colour of the selected item; the selected
// item is also bold, whatever its palette slot.
var selectedColor = lipgloss.Color("129")

// gridStyleKind identifies the visual style of a coloured/bold cell. Cells
// with the same kind render identically, so a run of them is styled once.
// Values >= gridStyleSlot0 are palette slots (gridStyleSlot0 + slot).
type gridStyleKind int

const (
	gridStylePlain    gridStyleKind = iota // no styling: emitted raw
	gridStyleBoldOnly                      // bold, default colour
	gridStyleSelected                      // bold in selectedColor
	gridStyleSlot0                         // first palette slot
)

// gridStyle is one precomputed style. lipgloss.Style.Render measures and
// re-splits its text on every call, which stayed the dominant cost even with
// one call per run (about 60% of a 400x118 treemap frame). So the escape
// sequences lipgloss wraps around text are captured once, by rendering a
// probe, and wrapping a run is then a concatenation. Only when the probe does
// not have the expected prefix + text + suffix shape does render fall back to
// the Style itself.
type gridStyle struct {
	style          lipgloss.Style
	prefix, suffix string
	wrappable      bool
}

// gridStyleProbe is the marker text rendered to discover a style's escape
// sequences; it cannot occur in the sequences themselves.
const gridStyleProbe = "\x00"

func newGridStyle(style lipgloss.Style) gridStyle {
	gs := gridStyle{style: style}
	probe := style.Render(gridStyleProbe)
	if before, after, ok := strings.Cut(probe, gridStyleProbe); ok && !strings.Contains(after, gridStyleProbe) {
		gs.prefix, gs.suffix, gs.wrappable = before, after, true
	}
	return gs
}

// render styles text (which never contains a newline or tab: grid cells hold
// single graphemes).
func (g gridStyle) render(text string) string {
	if g.wrappable {
		return g.prefix + text + g.suffix
	}
	return g.style.Render(text)
}

// gridStyles holds the styles of one frame, built once per palette so that
// rendering a row never constructs a Style per cell (the old per-cell
// Style.Render was the dominant cost of the treemap and bubbles views: 36ms
// for a 200x48 frame).
type gridStyles struct {
	boldOnly gridStyle
	selected gridStyle
	slots    []gridStyle
}

// newGridStyles precomputes one style per palette slot plus the bold and
// selected styles.
func newGridStyles(palette []color.Color) gridStyles {
	s := gridStyles{
		boldOnly: newGridStyle(lipgloss.NewStyle().Bold(true)),
		selected: newGridStyle(lipgloss.NewStyle().Foreground(selectedColor).Bold(true)),
		slots:    make([]gridStyle, len(palette)),
	}
	for i, c := range palette {
		s.slots[i] = newGridStyle(lipgloss.NewStyle().Foreground(c))
	}
	return s
}

// kindOf classifies cell. A selected (bold) coloured cell is styled the same
// whatever its slot, so it maps to gridStyleSelected. An empty palette leaves
// nothing to colour with, so coloured cells then count as uncoloured.
func (s gridStyles) kindOf(cell gridCell) gridStyleKind {
	switch {
	case cell.colorSlot < 0 || len(s.slots) == 0:
		if cell.bold {
			return gridStyleBoldOnly
		}
		return gridStylePlain
	case cell.bold:
		return gridStyleSelected
	default:
		return gridStyleSlot0 + gridStyleKind(cell.colorSlot%len(s.slots))
	}
}

// render styles text according to kind.
func (s gridStyles) render(kind gridStyleKind, text string) string {
	switch kind {
	case gridStylePlain:
		return text
	case gridStyleBoldOnly:
		return s.boldOnly.render(text)
	case gridStyleSelected:
		return s.selected.render(text)
	default:
		return s.slots[kind-gridStyleSlot0].render(text)
	}
}

// renderGridRows renders every row of grid with one style set.
func renderGridRows(grid [][]gridCell, palette []color.Color) []string {
	styles := newGridStyles(palette)
	lines := make([]string, len(grid))
	for i, row := range grid {
		lines[i] = renderGridRowWith(row, styles)
	}
	return lines
}

// renderGridRow renders one chart row (see renderGridRowWith).
func renderGridRow(cells []gridCell, palette []color.Color) string {
	return renderGridRowWith(cells, newGridStyles(palette))
}

// renderGridRowWith renders one chart row. Adjacent cells of the same style
// are gathered into a run and styled with ONE Render call: charts paint wide
// same-coloured blocks, so this turns thousands of per-cell escape sequences
// and Style.Render calls into a handful per row, with identical visible text
// and colours. Plain cells are written raw and end the current run.
// Continuation cells emit nothing and do not break a run, as their cluster
// already covers them and shares its style.
func renderGridRowWith(cells []gridCell, styles gridStyles) string {
	var out, run strings.Builder
	out.Grow(len(cells) + 16)
	runKind := gridStylePlain
	flush := func() {
		if run.Len() > 0 {
			out.WriteString(styles.render(runKind, run.String()))
			run.Reset()
		}
	}
	for _, cell := range cells {
		if cell.cont {
			continue
		}
		kind := styles.kindOf(cell)
		if kind != runKind {
			flush()
			runKind = kind
		}
		if kind == gridStylePlain {
			// Dominant case (blank background): no per-cell string alloc.
			if cell.cluster != "" {
				out.WriteString(cell.cluster)
			} else {
				out.WriteRune(cell.char)
			}
			continue
		}
		if cell.cluster != "" {
			run.WriteString(cell.cluster)
		} else {
			run.WriteRune(cell.char)
		}
	}
	flush()
	return out.String()
}
