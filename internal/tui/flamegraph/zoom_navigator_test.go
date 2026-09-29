package flamegraph

import (
	"slices"
	"testing"
)

// zoomTestSnapshot is root -> {a -> a1, b}.
func zoomTestSnapshot() *snapshotNode {
	return &snapshotNode{
		Name:  "root",
		Total: 10,
		Children: []*snapshotNode{
			{Name: "a", Total: 6, Children: []*snapshotNode{{Name: "a1", Total: 4}}},
			{Name: "b", Total: 4},
		},
	}
}

func zoomStackPaths(z *ZoomNavigator) []string {
	paths := make([]string, 0, len(z.zoomStack))
	for _, entry := range z.zoomStack {
		paths = append(paths, entry.path)
	}
	return paths
}

func TestZoomNavigatorSetPathRejectsMissingSnapshotOrPath(t *testing.T) {
	pathA := "root" + pathSeparator + "a"
	snapshot := zoomTestSnapshot()
	for name, tc := range map[string]struct {
		snapshot *snapshotNode
		path     string
	}{
		"nil snapshot": {nil, pathA},
		"unknown path": {snapshot, "root" + pathSeparator + "missing"},
	} {
		t.Run(name, func(t *testing.T) {
			var z ZoomNavigator
			if !z.setPath(pathA, snapshot) {
				t.Fatal("precondition: zoom into a failed")
			}
			if z.setPath(tc.path, tc.snapshot) {
				t.Fatal("setPath succeeded, want failure")
			}
			if z.path() != pathA || z.zoomRoot == nil || z.zoomRoot.Name != "a" {
				t.Fatalf("failed setPath changed state: path=%q root=%v", z.path(), z.zoomRoot)
			}
		})
	}
}

func TestZoomNavigatorSetPathRootZoomsOut(t *testing.T) {
	snapshot := zoomTestSnapshot()
	for _, path := range []string{"", "root"} {
		var z ZoomNavigator
		z.setPath("root"+pathSeparator+"a", snapshot)
		if !z.setPath(path, snapshot) {
			t.Fatalf("setPath(%q) failed", path)
		}
		if z.path() != "" || z.zoomRoot != nil {
			t.Fatalf("setPath(%q) did not zoom out: path=%q root=%v", path, z.path(), z.zoomRoot)
		}
	}
}

func TestZoomNavigatorDescendPushesPreviousRootOnlyOnSuccess(t *testing.T) {
	snapshot := zoomTestSnapshot()
	pathA := "root" + pathSeparator + "a"
	pathA1 := pathA + pathSeparator + "a1"
	var z ZoomNavigator

	if !z.descend(pathA, snapshot) || !z.descend(pathA1, snapshot) {
		t.Fatal("descend failed")
	}
	if got, want := zoomStackPaths(&z), []string{"", pathA}; !slices.Equal(got, want) {
		t.Fatalf("stack = %q, want %q", got, want)
	}

	if z.descend("root"+pathSeparator+"missing", snapshot) {
		t.Fatal("descend into a missing path succeeded")
	}
	if z.descend(pathA, nil) {
		t.Fatal("descend without a snapshot succeeded")
	}
	if got, want := zoomStackPaths(&z), []string{"", pathA}; !slices.Equal(got, want) || z.path() != pathA1 {
		t.Fatalf("failed descend changed state: path=%q stack=%q", z.path(), got)
	}
}

func TestZoomNavigatorAscendToRebuildsStack(t *testing.T) {
	snapshot := zoomTestSnapshot()
	pathA := "root" + pathSeparator + "a"
	pathA1 := pathA + pathSeparator + "a1"
	var z ZoomNavigator
	z.descend(pathA1, snapshot)

	if !z.ascendTo(pathA, snapshot) {
		t.Fatal("ascendTo failed")
	}
	if z.path() != pathA {
		t.Fatalf("path = %q, want %q", z.path(), pathA)
	}
	if got, want := zoomStackPaths(&z), []string{""}; !slices.Equal(got, want) {
		t.Fatalf("stack = %q, want %q", got, want)
	}

	if z.ascendTo("root"+pathSeparator+"missing", snapshot) {
		t.Fatal("ascendTo a missing path succeeded")
	}
	if got := zoomStackPaths(&z); z.path() != pathA || !slices.Equal(got, []string{""}) {
		t.Fatalf("failed ascendTo changed state: path=%q stack=%q", z.path(), got)
	}
}

func TestZoomNavigatorUndo(t *testing.T) {
	snapshot := zoomTestSnapshot()
	pathA := "root" + pathSeparator + "a"
	pathA1 := pathA + pathSeparator + "a1"

	t.Run("empty stack", func(t *testing.T) {
		var z ZoomNavigator
		if z.undo(snapshot) {
			t.Fatal("undo with an empty stack succeeded")
		}
	})
	t.Run("nil snapshot pops nothing", func(t *testing.T) {
		var z ZoomNavigator
		z.descend(pathA, snapshot)
		if z.undo(nil) {
			t.Fatal("undo without a snapshot succeeded")
		}
		if len(z.zoomStack) != 1 || z.path() != pathA {
			t.Fatalf("undo without a snapshot changed state: path=%q stack=%q", z.path(), zoomStackPaths(&z))
		}
	})
	t.Run("unresolvable entry is dropped", func(t *testing.T) {
		var z ZoomNavigator
		z.descend(pathA, snapshot)
		z.zoomStack = append(z.zoomStack, zoomState{path: "root" + pathSeparator + "gone"})
		if z.undo(snapshot) {
			t.Fatal("undo to a vanished path succeeded")
		}
		if got := zoomStackPaths(&z); !slices.Equal(got, []string{""}) || z.path() != pathA {
			t.Fatalf("after failed undo: path=%q stack=%q", z.path(), got)
		}
	})
	t.Run("walks back one level at a time", func(t *testing.T) {
		var z ZoomNavigator
		z.descend(pathA, snapshot)
		z.descend(pathA1, snapshot)
		for _, want := range []string{pathA, ""} {
			if !z.undo(snapshot) {
				t.Fatalf("undo towards %q failed", want)
			}
			if z.path() != want {
				t.Fatalf("path = %q, want %q", z.path(), want)
			}
		}
		if !z.alreadyAtRoot() {
			t.Fatal("expected to be back at root with an empty stack")
		}
	})
}

func TestZoomNavigatorLayoutAndResolveRoot(t *testing.T) {
	snapshot := zoomTestSnapshot()
	pathA := "root" + pathSeparator + "a"
	var z ZoomNavigator

	if root, rootPath := z.layoutRoot(snapshot); root != snapshot || rootPath != "" {
		t.Fatalf("unzoomed layoutRoot = (%v, %q), want snapshot root", root, rootPath)
	}
	z.setPath(pathA, snapshot)
	if root, rootPath := z.layoutRoot(snapshot); root == nil || root.Name != "a" || rootPath != pathA {
		t.Fatalf("zoomed layoutRoot = (%v, %q), want node a", root, rootPath)
	}

	// A newer snapshot without the zoomed node leaves no zoom root, so the
	// layout falls back to the whole snapshot while the path is kept.
	fresh := &snapshotNode{Name: "root", Children: []*snapshotNode{{Name: "b"}}}
	z.resolveRoot(fresh)
	if root, rootPath := z.layoutRoot(fresh); root != fresh || rootPath != "" || z.path() != pathA {
		t.Fatalf("after resolveRoot on a snapshot without a: root=%v rootPath=%q path=%q", root, rootPath, z.path())
	}
	z.resolveRoot(snapshot)
	if z.zoomRoot == nil || z.zoomRoot.Name != "a" {
		t.Fatalf("resolveRoot did not find a again: %v", z.zoomRoot)
	}

	z.reset()
	z.zoomRoot = snapshot // stale root with no path must be cleared
	z.resolveRoot(snapshot)
	if z.zoomRoot != nil {
		t.Fatal("resolveRoot kept a root without a zoom path")
	}
}
