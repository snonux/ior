package flamegraph

import (
	"bytes"
	"strings"
	"testing"
)

func renderSVGForTest(t *testing.T, tr *trie, cfg SVGConfig) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSVG(&buf, tr, cfg); err != nil {
		t.Fatalf("WriteSVG failed: %v", err)
	}
	return buf.String()
}

func TestWriteSVGBasic(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a", "b"}, 3)
	tr.add([]string{"a", "c"}, 2)
	tr.computeTotals()

	svg := renderSVGForTest(t, tr, defaultSVGConfig())
	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatalf("expected valid svg wrapper, got: %s", svg)
	}
	if !strings.Contains(svg, "data-name=\"a\"") || !strings.Contains(svg, "data-name=\"b\"") {
		t.Fatalf("expected rendered frame names, got: %s", svg)
	}
}

func TestWriteSVGEmptyTrie(t *testing.T) {
	tr := newTrie()
	tr.computeTotals()

	svg := renderSVGForTest(t, tr, defaultSVGConfig())
	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatalf("expected valid svg wrapper, got: %s", svg)
	}
	if strings.Contains(svg, "class=\"frame\"") {
		t.Fatalf("expected no rendered frames for empty trie, got: %s", svg)
	}
}

func TestWriteSVGMinWidth(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"wide"}, 100)
	tr.add([]string{"tiny"}, 1)
	tr.computeTotals()

	cfg := defaultSVGConfig()
	cfg.Width = 120
	cfg.MinWidthPx = 2.0
	svg := renderSVGForTest(t, tr, cfg)

	if !strings.Contains(svg, "data-name=\"wide\"") {
		t.Fatalf("expected wide frame to be rendered, got: %s", svg)
	}
	if strings.Contains(svg, "data-name=\"tiny\"") {
		t.Fatalf("expected tiny frame to be skipped by min width, got: %s", svg)
	}
}

func TestWriteSVGTitle(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a"}, 1)
	tr.computeTotals()

	cfg := defaultSVGConfig()
	cfg.Title = "Custom Flamegraph"
	svg := renderSVGForTest(t, tr, cfg)

	if !strings.Contains(svg, "Custom Flamegraph") {
		t.Fatalf("expected custom title in output, got: %s", svg)
	}
}

func TestFrameColor(t *testing.T) {
	colorA1 := frameColor("read")
	colorA2 := frameColor("read")
	colorB := frameColor("write")

	if colorA1 != colorA2 {
		t.Fatalf("expected deterministic color for identical names, got %q vs %q", colorA1, colorA2)
	}
	if !strings.HasPrefix(colorA1, "rgb(") || !strings.HasSuffix(colorA1, ")") {
		t.Fatalf("expected rgb() format, got %q", colorA1)
	}
	if colorA1 == colorB {
		t.Fatalf("expected different colors for different names, got %q", colorA1)
	}
}

func TestWriteSVGInvalidConfigFallsBack(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a"}, 1)
	tr.computeTotals()

	cfg := SVGConfig{Title: "x", Width: 0, FrameHeight: 0, FontSize: 0, MinWidthPx: 0}
	svg := renderSVGForTest(t, tr, cfg)

	if !strings.Contains(svg, `width="100%"`) {
		t.Fatalf("expected responsive svg width, got: %s", svg)
	}
	if !strings.Contains(svg, `viewBox="0 0 1200 `) {
		t.Fatalf("expected fallback viewBox width, got: %s", svg)
	}
	if !strings.Contains(svg, "I/O Flame Graph") {
		t.Fatalf("expected fallback title, got: %s", svg)
	}
}
