package dashboard

import (
	"strings"
	"testing"

	common "ior/internal/tui/common"
)

// Wide labels (task zo2): CJK runes and emoji take two terminal cells, and a
// ZWJ emoji sequence is several runes forming one two-cell grapheme.
const (
	cjkLabel   = "日本語のディレクトリ"
	emojiLabel = "🚀👩‍💻data"
	mixedLabel = "x日y🚀z"
)

// assertRowWidths fails unless every line of view is exactly width cells.
func assertRowWidths(t *testing.T, what, view string, width int) {
	t.Helper()
	for i, line := range strings.Split(view, "\n") {
		if got := common.DisplayWidth(line); got != width {
			t.Fatalf("%s line %d width = %d, want %d: %q", what, i, got, width, line)
		}
	}
}

// renderPlainRow renders a grid row without colours, for exact comparison.
func renderPlainRow(row []gridCell) string {
	return renderGridRow(row, nil)
}

func TestAbbreviateLabelFitsDisplayCells(t *testing.T) {
	for _, label := range []string{cjkLabel, emojiLabel, mixedLabel, "plain-ascii-label"} {
		for maxCells := 1; maxCells <= 12; maxCells++ {
			got := abbreviateLabel(label, maxCells)
			if w := common.DisplayWidth(got); w > maxCells || w == 0 {
				t.Fatalf("abbreviateLabel(%q, %d) = %q, width %d", label, maxCells, got, w)
			}
		}
	}
	if got := abbreviateLabel("日本", 3); got != "日…" {
		t.Fatalf("abbreviateLabel(日本, 3) = %q, want 日…", got)
	}
}

func TestAbbreviateLabelEdgeCases(t *testing.T) {
	tests := []struct {
		label    string
		maxCells int
		want     string
	}{
		{"abc", 0, ""},
		{"abc", -1, ""},
		{"", 5, "?"},
		{"   ", 5, "?"},
		{"", 0, ""},
		// Edge blanks are kept so dirs differing only in them stay distinct.
		{" a", 5, " a"},
		{"a ", 5, "a "},
		{"日本", 1, "…"},
	}
	for _, tt := range tests {
		if got := abbreviateLabel(tt.label, tt.maxCells); got != tt.want {
			t.Errorf("abbreviateLabel(%q, %d) = %q, want %q", tt.label, tt.maxCells, got, tt.want)
		}
	}
	if abbreviateLabel("/tmp/a", 10) == abbreviateLabel("/tmp/a ", 10) {
		t.Fatal("labels differing only in a trailing blank render identically")
	}
}

func TestWriteGridLabelWideRunesTakeTwoCells(t *testing.T) {
	row := newGridRows(10, 1)[0]
	end := writeGridLabel(row, 0, "日👩‍💻x", -1, false)
	if end != 5 {
		t.Fatalf("end column = %d, want 5", end)
	}
	if !row[1].cont || !row[3].cont || row[4].cluster != "x" {
		t.Fatalf("unexpected cells: %+v", row[:5])
	}
	if got, want := renderPlainRow(row), "日👩‍💻x     "; got != want {
		t.Fatalf("row = %q, want %q", got, want)
	}
}

func TestWriteGridLabelClipsAtEdges(t *testing.T) {
	// A wide rune straddling the right edge is dropped, not half drawn.
	row := newGridRows(10, 1)[0]
	writeGridLabel(row, 8, "ab日", -1, false)
	if got, want := renderPlainRow(row), "        ab"; got != want {
		t.Fatalf("right edge row = %q, want %q", got, want)
	}
	// A wide rune straddling the left edge is dropped too.
	row = newGridRows(10, 1)[0]
	writeGridLabel(row, -1, "日x", -1, false)
	if got, want := renderPlainRow(row), " x        "; got != want {
		t.Fatalf("left edge row = %q, want %q", got, want)
	}
	// Entirely off-screen labels and zero-width clusters change nothing.
	row = newGridRows(4, 1)[0]
	writeGridLabel(row, 10, "abc", -1, false)
	writeGridLabel(row, -10, "abc", -1, false)
	writeGridLabel(row, 0, "́", -1, false)
	if got := renderPlainRow(row); got != "    " {
		t.Fatalf("off-screen row = %q, want blanks", got)
	}
}

func TestWriteGridLabelOverwritingHalfOfWideRune(t *testing.T) {
	// Overwriting the right half blanks the left half.
	row := newGridRows(6, 1)[0]
	writeGridLabel(row, 0, "日", -1, false)
	writeGridLabel(row, 1, "z", -1, false)
	if got, want := renderPlainRow(row), " z    "; got != want {
		t.Fatalf("row = %q, want %q", got, want)
	}
	// Overwriting the left half blanks the orphaned right half.
	row = newGridRows(6, 1)[0]
	writeGridLabel(row, 1, "日", -1, false)
	writeGridLabel(row, 0, "本", -1, false)
	if got, want := renderPlainRow(row), "本    "; got != want {
		t.Fatalf("row = %q, want %q", got, want)
	}
	// Shifted wide over wide: the continuation of the new rune replaces the
	// lead of the old one, whose right half must be blanked as well.
	row = newGridRows(6, 1)[0]
	writeGridLabel(row, 1, "日", -1, false)
	writeGridLabel(row, 0, "本x", -1, false)
	if got, want := renderPlainRow(row), "本x   "; got != want {
		t.Fatalf("row = %q, want %q", got, want)
	}
	assertRowWidths(t, "overwritten row", renderGridRow(row, treemapPalette(true)), 6)
}

func wideTreemapItems() []syscallTreemapItem {
	names := []string{cjkLabel, emojiLabel, mixedLabel, "read", "日本", "🚀"}
	items := make([]syscallTreemapItem, 0, len(names))
	for i, name := range names {
		value := uint64(60 - i*8)
		items = append(items, syscallTreemapItem{Name: name, Key: name, Count: value, Value: value})
	}
	return items
}

func TestTreemapWideLabelsKeepRowWidth(t *testing.T) {
	for _, width := range []int{23, 40, 81} {
		view := renderTreemapPanel("Treemap", "none", wideTreemapItems(), width, 14, bubbleMetricCount, 1, true)
		assertRowWidths(t, "treemap", view, width)
	}
}

// TestTreemapWideLabelsStayInsideTiles checks that each label is written
// only into its own tile (leaving the last tile cell as separator), with the
// expected abbreviated text, so labels of adjacent tiles never overlap.
func TestTreemapWideLabelsStayInsideTiles(t *testing.T) {
	const width, height = 40, 12
	items := wideTreemapItems()
	tiles := layoutSyscallTreemap(items, 0, 0, width, height)
	grid := newGridRows(width, height)
	fillTreemapGrid(grid, tiles, -1)
	for idx, tile := range tiles {
		if tile.w < 2 {
			continue
		}
		var text strings.Builder
		for col := tile.x; col < tile.x+tile.w; col++ {
			cell := grid[tile.y][col]
			if cell.colorSlot != idx {
				t.Fatalf("tile %d cell %d has colour slot %d (another tile's label?)", idx, col, cell.colorSlot)
			}
			if cell.cluster != "" {
				text.WriteString(cell.cluster)
			}
		}
		if want := abbreviateLabel(tile.item.Name, tile.w-1); text.String() != want {
			t.Fatalf("tile %d label = %q, want %q", idx, text.String(), want)
		}
	}
}

func TestIcicleWideLabelsKeepRowWidth(t *testing.T) {
	const width = 30
	tiles := []icicleTile{
		{node: &icicleNode{fullPath: "/"}, depth: 0, x: 0, w: width, colorSlot: 0},
		{node: &icicleNode{fullPath: "/" + cjkLabel}, depth: 1, x: 0, w: 13, colorSlot: 1},
		{node: &icicleNode{fullPath: "/" + emojiLabel}, depth: 1, x: 13, w: 10, colorSlot: 2},
		{node: &icicleNode{fullPath: "/日"}, depth: 1, x: 23, w: 7, colorSlot: 3},
	}
	view := renderIcicleGrid("Files icicle", tiles, width, 8, bubbleMetricCount, 1, false)
	assertRowWidths(t, "icicle", view, width)
}

func TestBubbleWideLabelsKeepRowWidth(t *testing.T) {
	const width, height = 50, 16
	chart := newBubbleChart()
	chart.nodes = []bubbleNode{
		{Label: cjkLabel, x: 12, y: 5, radius: 5},
		{Label: emojiLabel, x: 30, y: 6, radius: 4},
		{Label: mixedLabel, x: 44, y: 9, radius: 3},
		// Labels overlapping at the view edges and each other.
		{Label: "日本日本日本", x: 0, y: 5, radius: 4},
		{Label: "🚀🚀🚀🚀", x: 49, y: 6, radius: 4},
	}
	for selected := range chart.nodes {
		chart.selected = selected
		assertRowWidths(t, "bubbles", chart.Render("Files", width, height), width)
	}
}

func TestDrawBubbleLabelCentresByDisplayWidth(t *testing.T) {
	grid := newGridRows(20, 3)
	node := bubbleNode{Label: "日本語", x: 10, y: 1, radius: 5}
	drawBubbleLabel(grid, 20, 3, node, false, -1)
	// "日本語" is 6 cells wide, so it starts at 10-3 = 7.
	if got, want := renderPlainRow(grid[1]), "       日本語       "; got != want {
		t.Fatalf("row = %q, want %q", got, want)
	}
}

func TestOverviewLabelWidthsUseDisplayCells(t *testing.T) {
	if got := maxLabelWidth("Gap:", "日本:"); got != 5 {
		t.Fatalf("maxLabelWidth = %d, want 5", got)
	}
	if got := padLabelRight("日本:", 7); common.DisplayWidth(got) != 7 {
		t.Fatalf("padLabelRight width = %d, want 7 (%q)", common.DisplayWidth(got), got)
	}
	if got := padLabelRight("toolong", 3); got != "toolong" {
		t.Fatalf("padLabelRight truncated: %q", got)
	}
}
