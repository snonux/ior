package flamegraph

import (
	"fmt"
	"image/color"
	"slices"
	"strings"
	"testing"
)

// buildTerminalLayout lays out the whole snapshot (no zoom root) into terminal
// frame cells; production code calls buildTerminalLayoutWithPath directly.
func buildTerminalLayout(snapshot *snapshotNode, width, height int) []tuiFrame {
	return buildTerminalLayoutWithPath(snapshot, width, height, "")
}

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
		frames := buildTerminalLayout(snapshot, tc.width, 10)
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

func TestBuildTerminalLayoutProducesAStableDepthFirstOrder(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 12,
		Children: []*snapshotNode{
			{
				Name:  "zeta",
				Total: 7,
				Children: []*snapshotNode{
					{Name: "zeta-two", Total: 4},
					{Name: "zeta-one", Total: 3},
				},
			},
			{Name: "alpha", Total: 5},
		},
	}
	want := []string{
		"root",
		"root" + pathSeparator + "zeta",
		"root" + pathSeparator + "zeta" + pathSeparator + "zeta-two",
		"root" + pathSeparator + "zeta" + pathSeparator + "zeta-one",
		"root" + pathSeparator + "alpha",
	}

	for run := 0; run < 3; run++ {
		frames := buildTerminalLayout(snapshot, 120, 10)
		got := make([]string, 0, len(frames))
		for _, frame := range frames {
			got = append(got, frame.Path)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("run %d paths = %q, want stable depth-first order %q", run, got, want)
		}
	}
}

func TestBuildTerminalLayoutPartitionsAParentSpanAfterRounding(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 3,
		Children: []*snapshotNode{
			{Name: "first", Total: 1},
			{Name: "second", Total: 1},
			{Name: "third", Total: 1},
		},
	}

	frames := buildTerminalLayout(snapshot, 10, 4)
	children := framesAtRowRenderer(frames, 1)
	if got, want := len(children), 3; got != want {
		t.Fatalf("depth-one frame count = %d, want %d", got, want)
	}
	assertFramesPartitionSpan(t, children, 0, 10)
	if got, want := []int{children[0].Width, children[1].Width, children[2].Width}, []int{4, 3, 3}; !slices.Equal(got, want) {
		t.Fatalf("equal child widths = %v, want stable remainder allocation %v", got, want)
	}
}

func TestBuildTerminalLayoutLeavesNoGapForAPrunedSubtree(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{Name: "visible-a", Total: 60},
			{Name: "visible-b", Total: 30},
			// The missing ten samples model a child omitted by LiveTrie pruning.
		},
	}

	frames := buildTerminalLayout(snapshot, 100, 4)
	children := framesAtRowRenderer(frames, 1)
	if got, want := len(children), 2; got != want {
		t.Fatalf("depth-one frame count = %d, want %d", got, want)
	}
	assertFramesPartitionSpan(t, children, 0, 100)
	if got, want := []int{children[0].Width, children[1].Width}, []int{67, 33}; !slices.Equal(got, want) {
		t.Fatalf("visible child widths = %v, want pruned share redistributed as %v", got, want)
	}
}

func TestBuildTerminalLayoutRedistributesPrunedShareWithoutChangingSelfValueGap(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Value: 10,
		Total: 100,
		Children: []*snapshotNode{
			{Name: "visible-a", Total: 50},
			{Name: "visible-b", Total: 30},
			// The missing ten samples model a child omitted by LiveTrie pruning.
		},
	}

	frames := buildTerminalLayout(snapshot, 100, 4)
	children := framesAtRowRenderer(frames, 1)
	if got, want := len(children), 2; got != want {
		t.Fatalf("depth-one frame count = %d, want %d", got, want)
	}
	assertFramesPartitionSpan(t, children, 0, 90)
	if got, want := []int{children[0].Width, children[1].Width}, []int{56, 34}; !slices.Equal(got, want) {
		t.Fatalf("visible child widths = %v, want pruned share redistributed within self-time band as %v", got, want)
	}
}

func TestBuildTerminalLayoutPreservesAParentSelfValueGap(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Value: 10,
		Total: 100,
		Children: []*snapshotNode{
			{Name: "child-a", Total: 60},
			{Name: "child-b", Total: 30},
		},
	}

	frames := buildTerminalLayout(snapshot, 100, 4)
	children := framesAtRowRenderer(frames, 1)
	if got, want := len(children), 2; got != want {
		t.Fatalf("depth-one frame count = %d, want %d", got, want)
	}
	if got, want := children[len(children)-1].Col+children[len(children)-1].Width, 90; got != want {
		t.Fatalf("children end at column %d, want %d so parent self value keeps its span", got, want)
	}
}

func TestBuildTerminalLayoutClampsADeepTreeToViewportHeight(t *testing.T) {
	const (
		viewportHeight = 4
		fixtureDepth   = 16
	)
	root := &snapshotNode{Name: "root", Total: 1}
	node := root
	for depth := 1; depth <= fixtureDepth; depth++ {
		child := &snapshotNode{Name: "child", Total: 1}
		node.Children = []*snapshotNode{child}
		node = child
	}

	frames := buildTerminalLayout(root, 80, viewportHeight)
	if got, want := len(frames), viewportHeight; got != want {
		t.Fatalf("deep layout frame count = %d, want %d viewport rows", got, want)
	}
	for depth, frame := range frames {
		if frame.Row != depth {
			t.Fatalf("frame %d row = %d, want %d", depth, frame.Row, depth)
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

	frames := buildTerminalLayout(snapshot, 80, 2)
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

	frames := buildTerminalLayout(snapshot, 120, 6)
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

func TestBuildTerminalLayoutCapsAllSubCellFallbackToTheChildBand(t *testing.T) {
	tests := []struct {
		name      string
		rootTotal uint64
		rootValue uint64
	}{
		{name: "proportional band", rootTotal: 10000, rootValue: 9900},
		{name: "one-cell minimum", rootTotal: 1000000, rootValue: 999900},
		{name: "one-cell minimum after pruning", rootTotal: 1000000, rootValue: 999800},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			children := make([]*snapshotNode, 0, 100)
			for idx := 0; idx < 100; idx++ {
				children = append(children, &snapshotNode{Name: fmt.Sprintf("child-%03d", idx), Total: 1})
			}
			snapshot := &snapshotNode{
				Name:     "root",
				Value:    tc.rootValue,
				Total:    tc.rootTotal,
				Children: children,
			}

			frames := buildTerminalLayout(snapshot, 120, 4)
			depthOne := framesAtRowRenderer(frames, 1)
			if got, want := len(depthOne), 1; got != want {
				t.Fatalf("fallback child count = %d, want %d within the proportional child band", got, want)
			}
			child := depthOne[0]
			if got, want := child.Path, "root"+pathSeparator+"child-000"; got != want {
				t.Fatalf("fallback child = %q, want stable first contributor %q", got, want)
			}
			if got, want := child.Col+child.Width, 1; got != want {
				t.Fatalf("fallback band ends at column %d, want %d", got, want)
			}
		})
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

	frames := buildTerminalLayout(snapshot, 80, 4)
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

func TestSemanticFrameColorRuleTableAndOrdering(t *testing.T) {
	tests := []struct {
		name  string
		label string
		want  color.RGBA
		ok    bool
	}{
		{name: "empty", label: "", ok: false},
		{name: "read before path", label: "read/path", want: color.RGBA{R: 78, G: 132, B: 201, A: 255}, ok: true},
		{name: "sys fallback rust", label: "sys_custom", want: color.RGBA{R: 191, G: 99, B: 74, A: 255}, ok: true},
		{name: "path before pid", label: "pid/1234", want: color.RGBA{R: 88, G: 156, B: 84, A: 255}, ok: true},
		{name: "unmatched", label: "dimension", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := semanticFrameColor(tc.label)
			if ok != tc.ok {
				t.Fatalf("expected ok=%v for %q, got %v", tc.ok, tc.label, ok)
			}
			if !tc.ok {
				return
			}
			gotRGBA, castOK := got.(color.RGBA)
			if !castOK {
				t.Fatalf("expected semantic color type color.RGBA, got %T", got)
			}
			if gotRGBA != tc.want {
				t.Fatalf("unexpected semantic color for %q: got=%v want=%v", tc.label, gotRGBA, tc.want)
			}
		})
	}
}

func TestRenderTerminalViewShowsNarrowMessage(t *testing.T) {
	out := RenderTerminalView(RenderContext{
		Width:       50,
		Height:      10,
		MetricLabel: "events",
		IsDark:      true,
	})
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
	frames := buildTerminalLayout(snapshot, 80, 6)

	out := RenderTerminalView(RenderContext{
		Frames:      frames,
		Width:       80,
		Height:      6,
		SelectedIdx: 1,
		MetricLabel: "events",
		IsDark:      true,
	})
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
	frames := buildTerminalLayout(snapshot, 100, 20)

	out := RenderTerminalView(RenderContext{
		Frames:      frames,
		Width:       100,
		Height:      20,
		SelectedIdx: 1,
		MetricLabel: "events",
		IsDark:      true,
	})
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
	frames := buildTerminalLayout(snapshot, 80, 6)
	matchSet := map[int]bool{1: true}

	out := RenderTerminalView(RenderContext{
		Frames:      frames,
		Width:       140,
		Height:      6,
		SelectedIdx: 1,
		MatchSet:    matchSet,
		MetricLabel: "events",
		IsDark:      true,
		SearchQuery: "child",
	})
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
	frames := buildTerminalLayout(snapshot, 80, 8)
	needleIdx := frameIndexByPathRenderer(frames, "root"+pathSeparator+"keep"+pathSeparator+"needle")
	if needleIdx < 0 {
		t.Fatalf("expected needle frame in layout")
	}
	matchSet := map[int]bool{needleIdx: true}

	out := RenderTerminalView(RenderContext{
		Frames:      frames,
		Width:       180,
		Height:      8,
		SelectedIdx: needleIdx,
		MatchSet:    matchSet,
		GlobalTotal: 100,
		MetricLabel: "bytes",
		IsDark:      true,
		SearchQuery: "needle",
	})
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

// TestRenderTerminalViewNilFilterSetMatchesSearchVisibility pins the
// FilterSet==nil fallback to the SearchController rule: a match's descendants
// stay selectable, and a frame outside every match's lineage does not.
func TestRenderTerminalViewNilFilterSetMatchesSearchVisibility(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 100,
		Children: []*snapshotNode{
			{
				Name:  "keep",
				Total: 60,
				Children: []*snapshotNode{
					{
						Name:     "needle",
						Total:    60,
						Children: []*snapshotNode{{Name: "leaf", Total: 60}},
					},
				},
			},
			{Name: "drop", Total: 40},
		},
	}
	frames := buildTerminalLayout(snapshot, 80, 8)
	sep := pathSeparator
	needleIdx := frameIndexByPathRenderer(frames, "root"+sep+"keep"+sep+"needle")
	leafIdx := frameIndexByPathRenderer(frames, "root"+sep+"keep"+sep+"needle"+sep+"leaf")
	dropIdx := frameIndexByPathRenderer(frames, "root"+sep+"drop")
	if needleIdx < 0 || leafIdx < 0 || dropIdx < 0 {
		t.Fatalf("expected needle, leaf and drop frames in layout")
	}
	matchSet := map[int]bool{needleIdx: true}
	render := func(selectedIdx int, filterSet map[int]bool) string {
		return RenderTerminalView(RenderContext{
			Frames:      frames,
			Width:       180,
			Height:      8,
			SelectedIdx: selectedIdx,
			MatchSet:    matchSet,
			FilterSet:   filterSet,
			GlobalTotal: 100,
			MetricLabel: "events",
			IsDark:      true,
			SearchQuery: "needle",
		})
	}

	// A descendant of the match keeps the selection; the legacy fallback
	// (matches + ancestors only) moved it to root.
	out := render(leafIdx, nil)
	if !strings.Contains(out, "Selected: leaf ") {
		t.Fatalf("expected descendant of match to stay selected, got %q", out)
	}
	searchSet := filterVisibleSetUsingAncestry(frames, matchSet, buildFrameAncestry(frames), nil)
	if want := render(leafIdx, searchSet); out != want {
		t.Fatalf("nil FilterSet render differs from SearchController set render:\n got  %q\n want %q", out, want)
	}

	// Negative: a frame outside the match lineage is not selectable.
	if out := render(dropIdx, nil); !strings.Contains(out, "Selected: root ") {
		t.Fatalf("expected selection outside the filter to fall back to root, got %q", out)
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
	coveredTotal, rootTotal := filterCoverageTotals(frames, matchSet, 100)
	if got := percentOfTotal(coveredTotal, rootTotal); got != 60 {
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
	frames := buildTerminalLayout(snapshot, 80, 10)
	out := RenderTerminalView(RenderContext{
		Frames:      frames,
		Width:       80,
		Height:      4,
		SelectedIdx: 0,
		MetricLabel: "events",
		IsDark:      true,
	})
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

	topBand := renderLeafRowBand(frames, heights, 3, 10, "root"+pathSeparator+"A", nil, nil, 0, true, true)
	if !strings.Contains(topBand, "A") {
		t.Fatalf("expected top band to render taller frame A, got %q", topBand)
	}
	if strings.Contains(topBand, "B") {
		t.Fatalf("expected top band to hide shorter frame B, got %q", topBand)
	}

	lowerBand := renderLeafRowBand(frames, heights, 1, 10, "root"+pathSeparator+"A", nil, nil, 0, true, true)
	if !strings.Contains(lowerBand, "A") || !strings.Contains(lowerBand, "B") {
		t.Fatalf("expected lower band to render both frames, got %q", lowerBand)
	}
}

func TestBuildRenderRowsHeightMetricUsesLeafBandsAndViewportRows(t *testing.T) {
	frames := []tuiFrame{
		{Name: "root", Row: 0, Col: 0, Width: 12, Path: "root", Fill: color.RGBA{R: 70, G: 70, B: 70, A: 255}},
		{Name: "A", Row: 1, Col: 0, Width: 6, Path: "root" + pathSeparator + "A", HeightTotal: 100, Fill: color.RGBA{R: 150, G: 80, B: 80, A: 255}},
		{Name: "B", Row: 1, Col: 6, Width: 6, Path: "root" + pathSeparator + "B", HeightTotal: 50, Fill: color.RGBA{R: 80, G: 120, B: 180, A: 255}},
	}

	rows := buildRenderRows(renderRowsContext{
		frames:             frames,
		width:              12, // width
		rowOffset:          0,  // rowOffset
		maxRow:             1,  // maxRow
		barHeight:          1,  // barHeight
		leafBarHeight:      4,  // leafBarHeight
		availableRows:      5,  // availableRows
		selectedPath:       "root",
		subtreeSet:         map[int]bool{0: true, 1: true, 2: true},
		matchSet:           nil,
		selectedIdx:        0,
		heightMetricActive: true, // heightMetricActive
		isDark:             true, // isDark
	})

	if got, want := len(rows), 5; got != want {
		t.Fatalf("row count = %d, want %d", got, want)
	}
	// In height mode, the last leaf band (h=0) is where labels are drawn.
	if got := rows[3]; !strings.Contains(got, "A") || !strings.Contains(got, "B") {
		t.Fatalf("expected bottom leaf band to show both labels, got %q", got)
	}
	// Root row is rendered after all leaf bands.
	if got := rows[4]; !strings.Contains(got, "root") {
		t.Fatalf("expected final row to be root row, got %q", got)
	}
}

func TestBuildTerminalLayoutHeightTotalUsesSnapshotAggregation(t *testing.T) {
	snapshot := &snapshotNode{
		Name:  "root",
		Total: 3,
		Children: []*snapshotNode{
			{
				Name:        "A",
				Total:       2,
				HeightTotal: 90,
			},
			{
				Name:  "B",
				Total: 1,
				Children: []*snapshotNode{
					{Name: "B1", Total: 1, HeightTotal: 30},
				},
			},
		},
	}

	frames := buildTerminalLayout(snapshot, 80, 8)
	root := mustFindFrame(t, frames, "root")
	a := mustFindFrame(t, frames, "root"+pathSeparator+"A")
	b := mustFindFrame(t, frames, "root"+pathSeparator+"B")

	if got, want := root.HeightTotal, uint64(120); got != want {
		t.Fatalf("root HeightTotal = %d, want %d", got, want)
	}
	if got, want := a.HeightTotal, uint64(90); got != want {
		t.Fatalf("A HeightTotal = %d, want %d", got, want)
	}
	if got, want := b.HeightTotal, uint64(30); got != want {
		t.Fatalf("B HeightTotal = %d, want %d", got, want)
	}
}

func TestSnapshotHeightTotalNilNodeReturnsZero(t *testing.T) {
	if got, want := snapshotHeightTotal(nil), uint64(0); got != want {
		t.Fatalf("snapshotHeightTotal(nil) = %d, want %d", got, want)
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

func framesAtRowRenderer(frames []tuiFrame, row int) []tuiFrame {
	var matches []tuiFrame
	for _, frame := range frames {
		if frame.Row == row {
			matches = append(matches, frame)
		}
	}
	return matches
}

func assertFramesPartitionSpan(t *testing.T, children []tuiFrame, col, width int) {
	t.Helper()
	if len(children) == 0 {
		t.Fatal("expected at least one child frame")
	}
	cursor := col
	for _, child := range children {
		if child.Col != cursor {
			t.Fatalf("child %q starts at %d, want contiguous column %d", child.Path, child.Col, cursor)
		}
		cursor += child.Width
	}
	if want := col + width; cursor != want {
		t.Fatalf("children end at column %d, want span end %d", cursor, want)
	}
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
