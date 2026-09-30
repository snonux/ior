package dashboard

import (
	"fmt"
	"image/color"
	"regexp"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// referenceRenderRow is the original one-Render-per-cell renderer, kept here
// as the oracle the run-based renderGridRow must match cell for cell.
func referenceRenderRow(cells []gridCell, palette []color.Color) string {
	var b strings.Builder
	for _, cell := range cells {
		glyph := cell.glyph()
		if glyph == "" {
			continue
		}
		switch {
		case cell.colorSlot < 0 && cell.bold:
			b.WriteString(lipgloss.NewStyle().Bold(true).Render(glyph))
		case cell.colorSlot < 0:
			b.WriteString(glyph)
		default:
			style := lipgloss.NewStyle().Foreground(palette[cell.colorSlot%len(palette)])
			if cell.bold {
				style = style.Foreground(lipgloss.Color("129")).Bold(true)
			}
			b.WriteString(style.Render(glyph))
		}
	}
	return b.String()
}

var sgrRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// styledGlyph is one rendered grapheme and the SGR state in force for it.
type styledGlyph struct{ glyph, sgr string }

// decodeStyled walks an ANSI string and returns each visible grapheme with
// the accumulated SGR state, so two outputs that paint the same colours can be
// compared even when they group the escape sequences differently.
func decodeStyled(s string) []styledGlyph {
	var out []styledGlyph
	state := ""
	for s != "" {
		if loc := sgrRe.FindStringIndex(s); loc != nil && loc[0] == 0 {
			seq := s[:loc[1]]
			if seq == "\x1b[m" || seq == "\x1b[0m" {
				state = ""
			} else {
				state += seq
			}
			s = s[loc[1]:]
			continue
		}
		g, _ := ansi.FirstGraphemeCluster(s, ansi.GraphemeWidth)
		out = append(out, styledGlyph{glyph: g, sgr: state})
		s = s[len(g):]
	}
	return out
}

// mixedGridRow builds a row exercising every cell kind: plain blanks, bold
// blanks, several palette slots (also beyond the palette length), the selected
// bold-coloured style, wide clusters with continuation cells and overwrites.
func mixedGridRow() []gridCell {
	row := newGridRows(60, 1)[0]
	for col := 2; col < 14; col++ {
		row[col] = gridCell{char: '█', colorSlot: col / 4}
	}
	for col := 14; col < 20; col++ {
		row[col] = gridCell{char: '█', colorSlot: 11, bold: true} // selected
	}
	for col := 20; col < 24; col++ {
		row[col] = gridCell{char: '█', colorSlot: -1, bold: true} // bold, no colour
	}
	writeGridLabel(row, 26, "日本語 lbl", 3, false)
	writeGridLabel(row, 40, "🚀👩‍💻x", 9, true)
	setGridCell(row, 27, gridCell{char: 'Z', colorSlot: 2}) // splits a wide cluster
	return row
}

func TestRunRenderingMatchesPerCellReference(t *testing.T) {
	palette := treemapPalette(true)
	row := mixedGridRow()
	got := renderGridRow(row, palette)
	want := referenceRenderRow(row, palette)

	if ansi.Strip(got) != ansi.Strip(want) {
		t.Fatalf("visible text differs:\n got %q\nwant %q", ansi.Strip(got), ansi.Strip(want))
	}
	gotCells, wantCells := decodeStyled(got), decodeStyled(want)
	if len(gotCells) != len(wantCells) {
		t.Fatalf("grapheme count = %d, want %d", len(gotCells), len(wantCells))
	}
	for i := range wantCells {
		if gotCells[i] != wantCells[i] {
			t.Fatalf("cell %d (%q) styled %q, want %q", i, wantCells[i].glyph, gotCells[i].sgr, wantCells[i].sgr)
		}
	}
	// The point of the change: far fewer escape sequences than one per cell.
	if g, w := len(sgrRe.FindAllString(got, -1)), len(sgrRe.FindAllString(want, -1)); g*2 > w {
		t.Fatalf("run rendering emitted %d SGR sequences, reference %d: runs are not merged", g, w)
	}
}

func TestRunRenderingMergesOnlyIdenticalStyles(t *testing.T) {
	palette := treemapPalette(true)
	row := []gridCell{
		{char: 'a', colorSlot: 0}, {char: 'b', colorSlot: 0},
		{char: 'c', colorSlot: 1},            // different slot: new run
		{char: 'd', colorSlot: len(palette)}, // wraps to slot 0
		{char: ' ', colorSlot: -1},           // plain ends the run
		{char: 'e', colorSlot: 0},
	}
	cells := decodeStyled(renderGridRow(row, palette))
	if cells[0].sgr != cells[1].sgr || cells[0].sgr == cells[2].sgr {
		t.Fatalf("runs merged wrongly: %+v", cells)
	}
	if cells[3].sgr != cells[0].sgr {
		t.Fatalf("slot %d must wrap to slot 0's colour: %+v", len(palette), cells)
	}
	if cells[4].sgr != "" || cells[5].sgr != cells[0].sgr {
		t.Fatalf("plain cell must not carry the run's colour: %+v", cells)
	}
}

func TestRenderGridRowWithoutPaletteDoesNotPanic(t *testing.T) {
	row := []gridCell{{char: 'x', colorSlot: 2}, {char: 'y', colorSlot: 2, bold: true}}
	if got := ansi.Strip(renderGridRow(row, nil)); got != "xy" {
		t.Fatalf("got %q, want xy", got)
	}
}

func TestRenderGridRowsMatchesRenderGridRow(t *testing.T) {
	palette := treemapPalette(false)
	grid := [][]gridCell{mixedGridRow(), mixedGridRow()}
	for i, line := range renderGridRows(grid, palette) {
		if want := renderGridRow(grid[i], palette); line != want {
			t.Fatalf("row %d differs between renderGridRows and renderGridRow", i)
		}
	}
}

// treemapBenchItems builds n treemap items of decreasing size.
func treemapBenchItems(n int) []syscallTreemapItem {
	items := make([]syscallTreemapItem, 0, n)
	for i := range n {
		name := fmt.Sprintf("syscall_%d", i)
		v := uint64(1000 - i*10)
		items = append(items, syscallTreemapItem{Name: name, Key: name, Count: v, Value: v})
	}
	return items
}

// BenchmarkTreemapRender measures a whole treemap frame at sizes around the
// 33ms frame budget's old limit (~240x72 cells). Before the run-based
// renderer: 200x48 took 35.8ms and 400x118 took 155ms.
func BenchmarkTreemapRender(b *testing.B) {
	for _, size := range [][2]int{{120, 40}, {200, 48}, {400, 118}} {
		b.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(b *testing.B) {
			items := treemapBenchItems(24)
			b.ReportAllocs()
			for b.Loop() {
				_ = renderTreemapPanel("Syscalls treemap", "none", items, size[0], size[1], bubbleMetricCount, 3, true)
			}
		})
	}
}

// TestGridStyleWrapsLikeLipgloss pins the captured-escape-sequence shortcut:
// wrapping a run must give byte-for-byte what Style.Render gives, for every
// style the grid uses, and every one must take the fast path.
func TestGridStyleWrapsLikeLipgloss(t *testing.T) {
	palette := treemapPalette(true)
	styles := newGridStyles(palette)
	all := append([]gridStyle{styles.boldOnly, styles.selected}, styles.slots...)
	for i, gs := range all {
		if !gs.wrappable {
			t.Fatalf("style %d fell back to Style.Render", i)
		}
		for _, text := range []string{"█", "█████", "日本語 lbl", "🚀👩‍💻x"} {
			if got, want := gs.render(text), gs.style.Render(text); got != want {
				t.Fatalf("style %d text %q: got %q, want %q", i, text, got, want)
			}
		}
	}
}

// TestGridStyleWithoutEscapesStaysPlain: a style that renders the probe with
// no escape sequences at all wraps nothing and leaves the text untouched. The
// shortcut is only valid for foreground/bold styles, which is all the grid
// builds; it is not meant for styles that rewrite the text (padding, width).
func TestGridStyleWithoutEscapesStaysPlain(t *testing.T) {
	gs := newGridStyle(lipgloss.NewStyle())
	if got := gs.render("abc"); got != "abc" {
		t.Fatalf("plain style rendered %q", got)
	}
}
