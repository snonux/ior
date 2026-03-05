package flamegraph

import (
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
