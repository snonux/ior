package flamegraph

import (
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-6
}

func TestBuildFrameLayoutBasicGeometry(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"A"}, 4)
	tr.add([]string{"B"}, 1)
	tr.computeTotals()

	cfg := defaultSVGConfig()
	cfg.Width = 100
	cfg.FrameHeight = 10
	cfg.FontSize = 10
	cfg.MinWidthPx = 1

	frames := BuildFrameLayout(tr, cfg)
	if len(frames) != 2 {
		t.Fatalf("frames len = %d, want 2", len(frames))
	}

	a := frames[0]
	if a.Name != "A" {
		t.Fatalf("first frame name = %q, want %q", a.Name, "A")
	}
	if !almostEqual(a.X, 0) {
		t.Fatalf("A x = %f, want 0", a.X)
	}
	if !almostEqual(a.Width, 80) {
		t.Fatalf("A width = %f, want 80", a.Width)
	}
	if !almostEqual(a.Percent, 80) {
		t.Fatalf("A percent = %f, want 80", a.Percent)
	}
	if a.Depth != 1 {
		t.Fatalf("A depth = %d, want 1", a.Depth)
	}

	b := frames[1]
	if b.Name != "B" {
		t.Fatalf("second frame name = %q, want %q", b.Name, "B")
	}
	if !almostEqual(b.X, 80) {
		t.Fatalf("B x = %f, want 80", b.X)
	}
	if !almostEqual(b.Width, 20) {
		t.Fatalf("B width = %f, want 20", b.Width)
	}
}

func TestBuildFrameLayoutSkipsFramesBelowMinWidth(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"A"}, 999)
	tr.add([]string{"B"}, 1)
	tr.computeTotals()

	cfg := defaultSVGConfig()
	cfg.Width = 100
	cfg.FrameHeight = 10
	cfg.FontSize = 10
	cfg.MinWidthPx = 1

	frames := BuildFrameLayout(tr, cfg)
	if len(frames) != 1 {
		t.Fatalf("frames len = %d, want 1", len(frames))
	}
	if frames[0].Name != "A" {
		t.Fatalf("remaining frame name = %q, want %q", frames[0].Name, "A")
	}
}
