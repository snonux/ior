package flamegraph

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

// selectedBgSGR is the background parameter styleForFrame gives the selected
// frame (lipgloss.Color("129")); no other frame style uses it.
const selectedBgSGR = "48;5;129"

// TestFrameIndexAtHeightMetricUpperBandAboveShortLeaf is the regression test
// for band-exact hit testing: the leaf row spans six bands, B (20% of A's
// height) is drawn in the bottom band only, so a click above B must select
// nothing instead of B, while A stays hittable in every band.
func TestFrameIndexAtHeightMetricUpperBandAboveShortLeaf(t *testing.T) {
	const width, height = 60, 10 // 7 data rows: 6 leaf bands + root
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 60, Path: "root"},
		{Name: "A", Row: 1, Col: 0, Width: 30, Path: "root" + pathSeparator + "A", HeightTotal: 100},
		{Name: "B", Row: 1, Col: 30, Width: 30, Path: "root" + pathSeparator + "B", HeightTotal: 20},
	}
	for _, tc := range []struct {
		name    string
		x, y    int
		want    int
		heightM bool
	}{
		{"top band above short B is blank", 45, 1, -1, true},
		{"band just above B is blank", 45, 5, -1, true},
		{"bottom band hits B", 45, 6, 2, true},
		{"top band hits tall A", 10, 1, 1, true},
		{"bottom band hits A", 10, 6, 1, true},
		{"root row below leaf bands", 45, 7, 0, true},
		{"toolbar line", 10, 0, -1, true},
		{"status line", 10, 8, -1, true},
		{"left of viewport", -1, 6, -1, true},
		{"right of viewport", width, 6, -1, true},
		// Without the height metric the leaf row is a uniform bar, so the
		// same cell selects B.
		{"uniform bars keep B hittable", 45, 3, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := frameIndexAt(frames, tc.x, tc.y, width, height, false, tc.heightM); got != tc.want {
				t.Fatalf("frameIndexAt(%d,%d)=%d want %d", tc.x, tc.y, got, tc.want)
			}
		})
	}
	assertHitsMatchDrawnView(t, frames, width, height, true)
}

// TestFrameIndexAtMatchesDrawnCellsInAllBands compares hit testing with the
// full rendered view for every data cell, in both height modes, over a layout
// whose leaf row mixes tall, short and zero-height frames and whose shallower
// rows contain leaves that are not part of the banded leaf row.
func TestFrameIndexAtMatchesDrawnCellsInAllBands(t *testing.T) {
	const width = 90
	snapshot := &snapshotNode{Name: "root", Total: 100, Children: []*snapshotNode{
		{Name: "A", Total: 50, Children: []*snapshotNode{
			{Name: "a", Total: 20, HeightTotal: 90},
			{Name: "b", Total: 20, HeightTotal: 10},
			{Name: "c", Total: 10},
		}},
		{Name: "B", Total: 30, Children: []*snapshotNode{{Name: "d", Total: 30, HeightTotal: 45}}},
		{Name: "C", Total: 20, HeightTotal: 50},
	}}
	for _, height := range []int{6, 9, 14, 25} {
		frames := buildTerminalLayout(snapshot, width, height)
		for _, heightMetric := range []bool{true, false} {
			assertHitsMatchDrawnView(t, frames, width, height, heightMetric)
		}
	}

	// An 18-level chain ending in two leaves of different heights (19 rows)
	// is deeper than every viewport below (at most 17 data rows), so rows
	// are scrolled off (rowOffset > 0) in both height modes and the leaf
	// bands share the viewport with the still-visible non-leaf rows.
	deep := &snapshotNode{Name: "L17", Total: 100, Children: []*snapshotNode{
		{Name: "p", Total: 60, HeightTotal: 100},
		{Name: "q", Total: 40, HeightTotal: 35},
	}}
	for level := 16; level >= 0; level-- {
		deep = &snapshotNode{Name: fmt.Sprintf("L%d", level), Total: 100, Children: []*snapshotNode{deep}}
	}
	for _, height := range []int{6, 8, 12, 20} {
		frames := buildTerminalLayout(deep, width, height)
		for _, heightMetric := range []bool{true, false} {
			if params := computeRenderParamsForAvailableRows(frames, height-3, heightMetric); params.rowOffset == 0 {
				t.Fatalf("height=%d heightMetric=%v: rowOffset=0, deep case does not scroll", height, heightMetric)
			}
			assertHitsMatchDrawnView(t, frames, width, height, heightMetric)
		}
	}
}

// TestAnimatedHeightMetricHitsMatchDrawnCells drives the spring animation
// (B slides right while A and C appear) with the height metric active and
// checks every intermediate frame cell by cell, so overlapping spans in the
// banded leaf row resolve to the frame drawn in each band.
func TestAnimatedHeightMetricHitsMatchDrawnCells(t *testing.T) {
	const width, height = 80, 12
	before := &snapshotNode{Name: "root", Total: 100, Children: []*snapshotNode{
		{Name: "X", Total: 100, Children: []*snapshotNode{{Name: "B", Total: 100, HeightTotal: 30}}},
	}}
	after := &snapshotNode{Name: "root", Total: 100, Children: []*snapshotNode{
		{Name: "X", Total: 100, Children: []*snapshotNode{
			{Name: "A", Total: 40, HeightTotal: 100},
			{Name: "B", Total: 30, HeightTotal: 30},
			{Name: "C", Total: 30, HeightTotal: 60},
		}},
	}}
	state := NewAnimationState(30, 6.0, 1.0)
	state.SetTargets(buildTerminalLayout(before, width, height))
	state.SnapToTargets()
	state.SetTargets(buildTerminalLayout(after, width, height))

	sawOverlap := false
	for tick := 0; tick < 120 && !state.Settled(); tick++ {
		state.Tick(1.0 / 30)
		frames := state.CurrentFrames()
		sawOverlap = sawOverlap || rowHasOverlap(frames, 2)
		assertHitsMatchDrawnView(t, frames, width, height, true)
	}
	if !sawOverlap {
		t.Fatal("animation never overlapped the leaf row; the test no longer covers mid-animation spans")
	}
}

// assertHitsMatchDrawnView renders the view the way Model.View does for a
// model of the given height and checks that frameIndexAt reports, for every
// data cell, exactly the frame drawn there (or -1 for a blank cell). Frame
// ownership of a cell is read from the rendered SGR: the view is rendered
// once per frame with that frame selected, and the selected background marks
// the cells it occupies on every line, including label-less bands.
func assertHitsMatchDrawnView(t *testing.T, frames []tuiFrame, width, height int, heightMetric bool) {
	t.Helper()
	owners := drawnCellOwners(t, frames, width, height, heightMetric)
	for y, row := range owners {
		for x, want := range row {
			if got := frameIndexAt(frames, x, y, width, height, false, heightMetric); got != want {
				t.Fatalf("height=%d heightMetric=%v cell (%d,%d): hit frame %d, drawn frame %d", height, heightMetric, x, y, got, want)
			}
		}
	}
}

// drawnCellOwners returns, per rendered line and column, the index of the
// frame drawn in that cell or -1. Toolbar and status lines never hold frames.
func drawnCellOwners(t *testing.T, frames []tuiFrame, width, height int, heightMetric bool) [][]int {
	t.Helper()
	var owners [][]int
	for idx := range frames {
		out := RenderTerminalView(RenderContext{
			Frames: frames, Width: width, Height: height - 1, // minus status line, as Model.View
			SelectedIdx: idx, MetricLabel: "samples", HeightMetricActive: heightMetric, IsDark: true,
		})
		lines := strings.Split(out, "\n")
		if owners == nil {
			owners = make([][]int, len(lines))
			for y := range owners {
				owners[y] = slices.Repeat([]int{-1}, width)
			}
		}
		for y := 1; y < len(lines)-1; y++ {
			for x, selected := range selectedCells(lines[y], width) {
				if !selected {
					continue
				}
				if prev := owners[y][x]; prev >= 0 {
					t.Fatalf("cell (%d,%d) drawn by frames %d and %d", x, y, prev, idx)
				}
				owners[y][x] = idx
			}
		}
	}
	return owners
}

// selectedCells reports, for each of the width cells of a rendered line,
// whether it carries the selected-frame background. Every styled segment
// starts with one full SGR and ends with a reset, so the most recent SGR
// alone decides a cell's style. Each rune advances by its display width, so
// wide or multi-byte labels ("…", CJK) keep later cells aligned.
func selectedCells(line string, width int) []bool {
	cells := make([]bool, 0, width)
	active := false
	for i := 0; i < len(line); {
		if strings.HasPrefix(line[i:], "\x1b[") {
			end := strings.IndexByte(line[i:], 'm')
			active = sgrHasSelectedBg(line[i+2 : i+end])
			i += end + 1
			continue
		}
		r, size := utf8.DecodeRuneInString(line[i:])
		for range lipgloss.Width(string(r)) {
			cells = append(cells, active)
		}
		i += size
	}
	return cells
}

// sgrHasSelectedBg reports whether the ';'-separated SGR parameter list sets
// the selected-frame background, i.e. contains the exact consecutive
// parameters 48;5;129. Matching whole parameters avoids false hits such as
// 38;2;248;5;129 (a truecolor foreground whose digits contain the pattern).
// Extended colour sequences (38/48 with 5;n or 2;r;g;b) are skipped as units
// so their arguments are never mistaken for a new 48 introducer.
func sgrHasSelectedBg(params string) bool {
	p := strings.Split(params, ";")
	for i := 0; i < len(p); i++ {
		if p[i] != "38" && p[i] != "48" && p[i] != "58" {
			continue
		}
		switch {
		case i+2 < len(p) && p[i+1] == "5":
			if p[i] == "48" && p[i+2] == "129" {
				return true
			}
			i += 2
		case i+4 < len(p) && p[i+1] == "2":
			i += 4
		}
	}
	return false
}

// TestSGRHasSelectedBg pins the parameter-exact matching of selectedCells.
func TestSGRHasSelectedBg(t *testing.T) {
	for _, tc := range []struct {
		params string
		want   bool
	}{
		{"1;97;48;5;129", true},
		{"48;5;129", true},
		{"38;2;248;5;129", false},  // digits contain 48;5;129
		{"38;5;48;5;129", false},   // fg 48, then blink (5) and a stray 129
		{"38;5;48;48;5;129", true}, // fg 48, then the real 48;5;129 bg
		{"38;2;1;48;5;129", false}, // 48 is the truecolor blue component
		{"48;5;1290", false},
		{"48;5;238", false},
		{"", false},
	} {
		if got := sgrHasSelectedBg(tc.params); got != tc.want {
			t.Errorf("sgrHasSelectedBg(%q)=%v want %v", tc.params, got, tc.want)
		}
	}
}
