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
	out := RenderTerminalView(nil, 50, 10, 0, nil, nil, true, false, "")
	if !strings.Contains(out, "terminal too narrow") {
		t.Fatalf("expected narrow terminal warning, got %q", out)
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

	out := RenderTerminalView(frames, 80, 6, 1, nil, nil, true, false, "")
	if !strings.Contains(out, "Flame | view:root | frames:2") {
		t.Fatalf("expected toolbar to include frame count, got %q", out)
	}
	if !strings.Contains(out, "Selected: child") {
		t.Fatalf("expected status line to show selected frame, got %q", out)
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

	out := RenderTerminalView(frames, 80, 6, 1, nil, matchSet, true, false, "child")
	if !strings.Contains(out, `Filter "child"`) {
		t.Fatalf("expected filter context in status line, got %q", out)
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
	out := RenderTerminalView(frames, 80, 4, 0, nil, nil, true, false, "")
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
