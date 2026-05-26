package flamegraph

import (
	"image/color"
	"strings"
	"testing"
)

func TestBuildTerminalLayoutWidthScaling(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "A",
				Total: 60,
				Children: []*snapshotNode{
					{Name: "A1", Total: 30},
					{Name: "A2", Total: 30},
				},
			},
			{Name: "B", Total: 40},
		},
	}

	tests := []struct {
		width   int
		wantA   int
		wantB   int
		wantA1  int
		wantA2  int
		wantAll int
	}{
		{width: 80, wantA: 48, wantB: 32, wantA1: 24, wantA2: 24, wantAll: 5},
		{width: 120, wantA: 72, wantB: 48, wantA1: 36, wantA2: 36, wantAll: 5},
		{width: 200, wantA: 120, wantB: 80, wantA1: 60, wantA2: 60, wantAll: 5},
	}

	for _, tc := range tests {
		frames := BuildTerminalLayout(snapshot, tc.width, 10)
		if len(frames) != tc.wantAll {
			t.Fatalf("width %d: expected %d frames, got %d", tc.width, tc.wantAll, len(frames))
		}
		root := mustFindFrame(t, frames, "root")
		if root.Width != tc.width || root.Row != 0 || root.Col != 0 {
			t.Fatalf("width %d: unexpected root frame %+v", tc.width, root)
		}
		a := mustFindFrame(t, frames, "root"+pathSeparator+"A")
		b := mustFindFrame(t, frames, "root"+pathSeparator+"B")
		a1 := mustFindFrame(t, frames, "root"+pathSeparator+"A"+pathSeparator+"A1")
		a2 := mustFindFrame(t, frames, "root"+pathSeparator+"A"+pathSeparator+"A2")

		if a.Width != tc.wantA || b.Width != tc.wantB {
			t.Fatalf("width %d: unexpected child widths A=%d B=%d", tc.width, a.Width, b.Width)
		}
		if a1.Width != tc.wantA1 || a2.Width != tc.wantA2 {
			t.Fatalf("width %d: unexpected grandchild widths A1=%d A2=%d", tc.width, a1.Width, a2.Width)
		}
		if b.Col != a.Col+a.Width {
			t.Fatalf("width %d: expected B col %d, got %d", tc.width, a.Col+a.Width, b.Col)
		}
	}
}

func TestBuildTerminalLayoutCullsSubCellFramesAndRespectsHeight(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "big",
				Total: 99,
				Children: []*snapshotNode{
					{Name: "deep", Total: 99},
				},
			},
			{Name: "tiny", Total: 1},
		},
	}

	frames := BuildTerminalLayout(snapshot, 80, 2)
	if hasFrame(frames, "root"+pathSeparator+"tiny") {
		t.Fatalf("expected tiny frame to be culled (<1 terminal cell)")
	}
	if hasFrame(frames, "root"+pathSeparator+"big"+pathSeparator+"deep") {
		t.Fatalf("expected deep frame to be omitted due height limit")
	}
	if !hasFrame(frames, "root"+pathSeparator+"big") {
		t.Fatalf("expected big frame to be present")
	}
}

func TestBuildTerminalLayoutKeepsChildrenVisibleWhenRoundingWouldCullAll(t *testing.T) {
	children := make([]*snapshotNode, 0, 200)
	for i := 0; i < 200; i++ {
		children = append(children, &snapshotNode{Name: "c", Total: 1})
	}
	snapshot := &snapshotNode{Name: "root", Children: children}

	frames := BuildTerminalLayout(snapshot, 120, 6)
	depthOne := 0
	for _, frame := range frames {
		if frame.Depth == 1 {
			depthOne++
		}
	}
	if depthOne == 0 {
		t.Fatalf("expected at least one visible depth-1 frame, got none")
	}
}

func TestBuildTerminalLayoutUsesPathSeparatorAndColor(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 10,
		Children: []*snapshotNode{
			{Name: "child", Total: 10},
		},
	}

	frames := BuildTerminalLayout(snapshot, 80, 4)
	child := mustFindFrame(t, frames, "root"+pathSeparator+"child")
	if !strings.Contains(child.Path, pathSeparator) {
		t.Fatalf("expected path %q to contain separator %q", child.Path, pathSeparator)
	}
	if child.Fill == nil {
		t.Fatalf("expected frame color to be set")
	}
}

func TestTerminalFrameColorSemanticPalette(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  color.RGBA
	}{
		{name: "read", label: "sys_enter_read", want: color.RGBA{R: 78, G: 132, B: 201, A: 255}},
		{name: "write", label: "sys_enter_write", want: color.RGBA{R: 222, G: 122, B: 58, A: 255}},
		{name: "metadata", label: "sys_enter_openat", want: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
		{name: "path", label: "/var/log/app.log", want: color.RGBA{R: 88, G: 156, B: 84, A: 255}},
		{name: "pid", label: "pid=1234", want: color.RGBA{R: 67, G: 151, B: 149, A: 255}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := terminalFrameColor(tc.label)
			if got != tc.want {
				t.Fatalf("unexpected semantic color for %q: got=%v want=%v", tc.label, got, tc.want)
			}
		})
	}
}

func TestRenderTerminalViewShowsNarrowMessage(t *testing.T) {
	out := RenderTerminalView(nil, 50, 10, 0, nil, nil, nil, 0, "events", false, true, false, "")
	if !strings.Contains(out, "terminal too narrow") {
		t.Fatalf("expected narrow terminal warning, got %q", out)
	}
}

func TestComputeBarHeightCappedAtThree(t *testing.T) {
	if got := computeBarHeight(30, 4, 3); got != 3 {
		t.Fatalf("expected bar height cap at 3, got %d", got)
	}
	if got := computeBarHeight(5, 10, 3); got != 1 {
		t.Fatalf("expected bar height minimum 1 when depth exceeds rows, got %d", got)
	}
}

func TestRenderTerminalViewIncludesToolbarAndStatus(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 10,
		Children: []*snapshotNode{
			{Name: "child", Total: 10},
		},
	}
	frames := BuildTerminalLayout(snapshot, 80, 6)

	out := RenderTerminalView(frames, 80, 6, 1, nil, nil, nil, 0, "events", false, true, false, "")
	if !strings.Contains(out, "Flame | view:root | frames:2") {
		t.Fatalf("expected toolbar to include frame count, got %q", out)
	}
	if !strings.Contains(out, "Selected: child") {
		t.Fatalf("expected status line to show selected frame, got %q", out)
	}
}

func TestRenderTerminalViewFillsAvailableHeightForShallowTree(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 10,
		Children: []*snapshotNode{
			{Name: "child", Total: 10},
		},
	}
	frames := BuildTerminalLayout(snapshot, 100, 20)

	out := RenderTerminalView(frames, 100, 20, 1, nil, nil, nil, 0, "events", false, true, false, "")
	lines := strings.Split(out, "\n")
	if got, want := len(lines), 20; got != want {
		t.Fatalf("expected render to fill viewport height (%d lines), got %d", want, got)
	}
}

func TestFrameLabelAddsSelectionAndMatchMarkers(t *testing.T) {
	if got := frameLabel("child", 7, true, false); got != ">child<" {
		t.Fatalf("expected selected marker label, got %q", got)
	}
	if got := frameLabel("child", 6, false, true); got != "*child" {
		t.Fatalf("expected match marker label, got %q", got)
	}
}

func TestSelectedFrameStyleDoesNotUnderline(t *testing.T) {
	style := styleForFrame(
		1,
		tuiFrame{
			Name: "child",
			Path: "root" + pathSeparator + "child",
			Fill: color.RGBA{R: 120, G: 80, B: 160, A: 255},
		},
		"root"+pathSeparator+"child",
		map[int]bool{1: true},
		nil,
		1,
		true,
		false,
		false,
	)
	rendered := style.Render(" child ")
	if strings.Contains(rendered, "\x1b[4m") || strings.Contains(rendered, "[4;") || strings.Contains(rendered, ";4m") {
		t.Fatalf("expected selected flame frame style without underline, got %q", rendered)
	}
}

func TestRenderTerminalViewShowsPersistentFilterContext(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 10,
		Children: []*snapshotNode{
			{Name: "child", Total: 10},
		},
	}
	frames := BuildTerminalLayout(snapshot, 80, 6)
	matchSet := map[int]bool{1: true}

	out := RenderTerminalView(frames, 140, 6, 1, nil, matchSet, nil, 0, "events", false, true, false, "child")
	if !strings.Contains(out, `Filter "child"`) {
		t.Fatalf("expected filter context in status line, got %q", out)
	}
}

func TestRenderTerminalViewFilterKeepsNonMatchingBranchesVisible(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "keep",
				Total: 60,
				Children: []*snapshotNode{
					{Name: "needle", Total: 60},
				},
			},
			{
				Name:  "drop",
				Total: 40,
				Children: []*snapshotNode{
					{Name: "noise", Total: 40},
				},
			},
		},
	}
	frames := BuildTerminalLayout(snapshot, 80, 8)
	needleIdx := frameIndexByPathRenderer(frames, "root"+pathSeparator+"keep"+pathSeparator+"needle")
	if needleIdx < 0 {
		t.Fatalf("expected needle frame in layout")
	}
	matchSet := map[int]bool{needleIdx: true}

	out := RenderTerminalView(frames, 180, 8, needleIdx, nil, matchSet, nil, 100, "bytes", false, true, false, "needle")
	if !strings.Contains(out, `Filter "needle": 60.0% bytes`) {
		t.Fatalf("expected filter status to report 60.0%% bytes share, got %q", out)
	}
	if !strings.Contains(out, "keep") || !strings.Contains(out, "needle") {
		t.Fatalf("expected matching branch to remain visible, got %q", out)
	}
	if !strings.Contains(out, "drop") || !strings.Contains(out, "noise") {
		t.Fatalf("expected non-matching branch to remain visible (greyed), got %q", out)
	}
	if !strings.Contains(out, "100.00% filtered bytes") {
		t.Fatalf("expected selected match share to be computed against filtered total, got %q", out)
	}
}

func TestBuildTerminalLayoutWithPathNormalizesZoomRootChildrenToFullWidth(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "zoom",
				Total: 80,
				Children: []*snapshotNode{
					{Name: "left", Total: 10},
					{Name: "right", Total: 10},
				},
			},
			{Name: "other", Total: 20},
		},
	}

	frames := buildTerminalLayoutWithPath(snapshot.Children[0], 120, 12, "root"+pathSeparator+"zoom")
	left := mustFindFrame(t, frames, "root"+pathSeparator+"zoom"+pathSeparator+"left")
	right := mustFindFrame(t, frames, "root"+pathSeparator+"zoom"+pathSeparator+"right")
	if got := left.Width + right.Width; got != 120 {
		t.Fatalf("expected zoom-root children to fill full width 120, got %d", got)
	}
	if left.Col != 0 {
		t.Fatalf("expected left child to start at column 0, got %d", left.Col)
	}
	if right.Col != left.Width {
		t.Fatalf("expected right child to start after left child, got %d want %d", right.Col, left.Width)
	}
}

func TestFilterSampleCoverageAvoidsDoubleCountingNestedMatches(t *testing.T) {
	frames := []tuiFrame{
		{Path: "root", Total: 100},
		{Path: "root" + pathSeparator + "A", Total: 60},
		{Path: "root" + pathSeparator + "A" + pathSeparator + "A1", Total: 30},
		{Path: "root" + pathSeparator + "B", Total: 40},
	}
	matchSet := map[int]bool{
		1: true, // A
		2: true, // A1 (nested under A)
	}
	if got := filterSampleCoverage(frames, matchSet, 100); got != 60 {
		t.Fatalf("expected nested matches to count once at 60%%, got %.1f%%", got)
	}
}

func TestRenderTerminalViewShowsDeepLevelTruncationHint(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 4,
		Children: []*snapshotNode{
			{
				Name:  "a",
				Total: 4,
				Children: []*snapshotNode{
					{
						Name:  "b",
						Total: 4,
						Children: []*snapshotNode{
							{
								Name:  "c",
								Total: 4,
								Children: []*snapshotNode{
									{Name: "d", Total: 4},
								},
							},
						},
					},
				},
			},
		},
	}
	frames := BuildTerminalLayout(snapshot, 80, 10)
	out := RenderTerminalView(frames, 80, 4, 0, nil, nil, nil, 0, "events", false, true, false, "")
	if !strings.Contains(out, "showing deepest levels") {
		t.Fatalf("expected truncation hint in toolbar, got %q", out)
	}
}

func TestComputeSubtreeSetIncludesAncestorsAndDescendants(t *testing.T) {
	frames := []tuiFrame{
		{Path: "root"},
		{Path: "root" + pathSeparator + "A"},
		{Path: "root" + pathSeparator + "A" + pathSeparator + "A1"},
		{Path: "root" + pathSeparator + "B"},
	}

	set := computeSubtreeSet(frames, 1)
	if !set[0] || !set[1] || !set[2] {
		t.Fatalf("expected root/A/A1 to be in selected subtree: %#v", set)
	}
	if set[3] {
		t.Fatalf("did not expect sibling branch B in subtree: %#v", set)
	}
}

func TestComputeRenderParamsHeightMetricExpandsLeafBand(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 20, Path: "root"},
		{Name: "leaf", Row: 1, Col: 0, Width: 20, Path: "root" + pathSeparator + "leaf", HeightTotal: 100},
	}

	params := computeRenderParams(frames, 8, true) // availableRows=6
	if got, want := params.barHeight, 1; got != want {
		t.Fatalf("height metric active: barHeight=%d want=%d", got, want)
	}
	if got, want := params.leafBarHeight, 5; got != want {
		t.Fatalf("height metric active: leafBarHeight=%d want=%d", got, want)
	}
}

func TestLeafFrameHeightsScaledByHeightTotal(t *testing.T) {
	frames := []indexedFrame{
		{idx: 10, frame: tuiFrame{Name: "A", HeightTotal: 100}},
		{idx: 11, frame: tuiFrame{Name: "B", HeightTotal: 50}},
		{idx: 12, frame: tuiFrame{Name: "C", HeightTotal: 0}},
	}

	heights := leafFrameHeights(frames, 5)
	if got, want := heights[10], 5; got != want {
		t.Fatalf("A height=%d want=%d", got, want)
	}
	if got, want := heights[11], 3; got != want {
		t.Fatalf("B height=%d want=%d", got, want)
	}
	if got, want := heights[12], 1; got != want {
		t.Fatalf("C height=%d want=%d", got, want)
	}
}

func TestRenderLeafRowBandFiltersFramesByBand(t *testing.T) {
	frames := []indexedFrame{
		{idx: 0, frame: tuiFrame{Name: "A", Col: 0, Width: 5, Path: "root" + pathSeparator + "A", Fill: color.RGBA{R: 150, G: 80, B: 80, A: 255}}},
		{idx: 1, frame: tuiFrame{Name: "B", Col: 5, Width: 5, Path: "root" + pathSeparator + "B", Fill: color.RGBA{R: 80, G: 120, B: 180, A: 255}}},
	}
	heights := map[int]int{
		0: 5,
		1: 2,
	}

	topBand := renderLeafRowBand(frames, heights, 3, 10, "root"+pathSeparator+"A", nil, nil, 0, true, false, false, true)
	if !strings.Contains(topBand, "A") {
		t.Fatalf("expected top band to render taller frame A, got %q", topBand)
	}
	if strings.Contains(topBand, "B") {
		t.Fatalf("expected top band to hide shorter frame B, got %q", topBand)
	}

	lowerBand := renderLeafRowBand(frames, heights, 1, 10, "root"+pathSeparator+"A", nil, nil, 0, true, false, false, true)
	if !strings.Contains(lowerBand, "A") || !strings.Contains(lowerBand, "B") {
		t.Fatalf("expected lower band to render both frames, got %q", lowerBand)
	}
}

func mustFindFrame(t *testing.T, frames []tuiFrame, path string) tuiFrame {
	t.Helper()
	for _, frame := range frames {
		if frame.Path == path {
			return frame
		}
	}
	t.Fatalf("frame with path %q not found", path)
	return tuiFrame{}
}

func hasFrame(frames []tuiFrame, path string) bool {
	for _, frame := range frames {
		if frame.Path == path {
			return true
		}
	}
	return false
}

func frameIndexByPathRenderer(frames []tuiFrame, path string) int {
	for idx, frame := range frames {
		if frame.Path == path {
			return idx
		}
	}
	return -1
}
