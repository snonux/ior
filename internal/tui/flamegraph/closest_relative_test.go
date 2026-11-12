package flamegraph

import "testing"

// TestClosestRelativePrefersNearestAncestor pins the fallback for a vanished
// selection: the deepest surviving ancestor, not the root that merely comes
// first in the depth-first frame order.
func TestClosestRelativePrefersNearestAncestor(t *testing.T) {
	path := func(parts ...string) string {
		out := parts[0]
		for _, part := range parts[1:] {
			out += pathSeparator + part
		}
		return out
	}
	frames := []tuiFrame{
		{Path: path("root")},
		{Path: path("root", "bash")},
		{Path: path("root", "bash", "read")},
		{Path: path("root", "cat")},
	}
	if got := closestRelative(frames, path("root", "bash", "read", "/b")); got != 2 {
		t.Fatalf("vanished leaf fell to frame %d, want its parent (2)", got)
	}
	if got := closestRelative(frames[1:], path("root")); got != 0 {
		t.Fatalf("no ancestor: got %d, want the first descendant (0)", got)
	}
	if got := closestRelative(frames[3:], path("root", "bash")); got != -1 {
		t.Fatalf("no relative: got %d, want -1", got)
	}
}
