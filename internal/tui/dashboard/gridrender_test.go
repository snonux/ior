package dashboard

import (
	"fmt"
	"image/color"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// legacyRenderGridRow is the pre-yq2 renderGridRow, copied VERBATIM (apart
// from its name) from `git show bcc904d^:internal/tui/dashboard/gridcell.go`.
// It is the oracle the run-based renderGridRow must match cell for cell: one
// lipgloss Style.Render per coloured cell, styles cached by a Sprintf key.
// Do not "improve" it; its only job is to be the old behaviour. It indexes
// palette[slot] unconditionally, so it panics on an empty palette (the one
// deliberate divergence, see TestRenderGridRowWithoutPalette).
//
// The doc comment that follows is the original one.
//
// renderGridRow renders one chart row. Coloured cells are styled with their
// palette slot (the selected item in the highlight colour and bold);
// continuation cells emit nothing, as their cluster already covers them.
func legacyRenderGridRow(cells []gridCell, palette []color.Color) string {
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

var sgrRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

// styledGlyph is one rendered grapheme and the SGR state in force for it.
type styledGlyph struct{ glyph, sgr string }

// decodeStyled walks an ANSI string and returns each visible grapheme with
// the accumulated SGR state, so two outputs that paint the same colours can be
// compared even when they group the escape sequences differently.
func decodeStyled(s string) []styledGlyph {
	return decodeStyledBy(s, func(s string) string {
		g, _ := ansi.FirstGraphemeCluster(s, ansi.GraphemeWidth)
		return g
	})
}

// decodeStyledRunes is decodeStyled with one entry per rune. The random
// corpus test uses it: adjacent cells can form one grapheme cluster (two
// regional indicators, a base and a combining mark) that the per-cell
// legacy output keeps apart with escape sequences and the run output does
// not, so grapheme boundaries legitimately differ while every rune's style
// must not.
func decodeStyledRunes(s string) []styledGlyph {
	return decodeStyledBy(s, func(s string) string {
		_, n := utf8.DecodeRuneInString(s)
		return s[:n]
	})
}

func decodeStyledBy(s string, next func(string) string) []styledGlyph {
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
		g := next(s)
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

func TestRunRenderingMatchesLegacyRenderer(t *testing.T) {
	palette := treemapPalette(true)
	row := mixedGridRow()
	got := renderGridRow(row, palette)
	want := legacyRenderGridRow(row, palette)

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

// TestRenderGridRowWithoutPalette pins the one deliberate divergence from the
// legacy renderer: with an empty palette the legacy code indexed palette[slot]
// and panicked on the first coloured cell. The new renderer treats a coloured
// cell as uncoloured, so a selected (bold) coloured cell becomes bold-only and
// a plain coloured cell renders raw.
func TestRenderGridRowWithoutPalette(t *testing.T) {
	coloured := []gridCell{{char: 'x', colorSlot: 2}, {char: 'y', colorSlot: 2, bold: true}}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("legacy renderer no longer panics on an empty palette; the divergence note is stale")
			}
		}()
		legacyRenderGridRow(coloured, nil)
	}()

	got := renderGridRow(coloured, nil)
	if ansi.Strip(got) != "xy" {
		t.Fatalf("got %q, want xy", ansi.Strip(got))
	}
	// Exactly what uncoloured cells render to, with or without a palette.
	uncoloured := []gridCell{{char: 'x', colorSlot: -1}, {char: 'y', colorSlot: -1, bold: true}}
	if want := renderGridRow(uncoloured, treemapPalette(true)); got != want {
		t.Fatalf("empty palette: got %q, want the uncoloured rendering %q", got, want)
	}
	cells := decodeStyled(got)
	if cells[0].sgr != "" || cells[1].sgr == "" {
		t.Fatalf("plain cell must be raw and the selected one bold: %+v", cells)
	}
}

// randomGridRow builds a row of random content: runs of coloured/bold fills
// (palette slots up to well beyond the palette, -1 for uncoloured), and labels
// of wide CJK, emoji (ZWJ sequences, flags), combining marks and ASCII written
// over them, so wide clusters get split and continuation cells overwritten.
func randomGridRow(rng *rand.Rand, width, paletteLen int) []gridCell {
	labels := []string{"日本語", "abc", "🚀", "👩‍💻", "🇩🇪🇫🇷", "e\u0301x", "한글", "x", "\u200d"}
	row := newGridRows(width, 1)[0]
	slot := func() int {
		switch rng.IntN(6) {
		case 0:
			return -1
		case 1:
			return paletteLen + rng.IntN(50) // out of the palette: wraps
		default:
			return rng.IntN(paletteLen)
		}
	}
	for range 4 + rng.IntN(12) {
		start := rng.IntN(width)
		if rng.IntN(2) == 0 {
			bold, sl := rng.IntN(4) == 0, slot()
			for col := start; col < min(width, start+1+rng.IntN(12)); col++ {
				setGridCell(row, col, gridCell{char: '█', colorSlot: sl, bold: bold})
			}
			continue
		}
		writeGridLabel(row, start, labels[rng.IntN(len(labels))], slot(), rng.IntN(3) == 0)
	}
	return row
}

// TestRunRenderingMatchesLegacyOnRandomRows compares the run renderer with
// the vendored legacy renderer on a seeded random corpus, in both themes:
// same visible text, and every rune painted in the same style.
func TestRunRenderingMatchesLegacyOnRandomRows(t *testing.T) {
	rng := rand.New(rand.NewPCG(20260930, 42))
	for _, isDark := range []bool{true, false} {
		palette := treemapPalette(isDark)
		for n := range 500 {
			row := randomGridRow(rng, 20+rng.IntN(80), len(palette))
			got, want := renderGridRow(row, palette), legacyRenderGridRow(row, palette)
			if ansi.Strip(got) != ansi.Strip(want) {
				t.Fatalf("dark=%v row %d: visible text differs:\n got %q\nwant %q", isDark, n, ansi.Strip(got), ansi.Strip(want))
			}
			gotCells, wantCells := decodeStyledRunes(got), decodeStyledRunes(want)
			if len(gotCells) != len(wantCells) {
				t.Fatalf("dark=%v row %d: %d runes, want %d", isDark, n, len(gotCells), len(wantCells))
			}
			for i := range wantCells {
				if gotCells[i] != wantCells[i] {
					t.Fatalf("dark=%v row %d rune %d (%q): style %q, want %q\n got %q\nwant %q",
						isDark, n, i, wantCells[i].glyph, gotCells[i].sgr, wantCells[i].sgr, got, want)
				}
			}
		}
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
