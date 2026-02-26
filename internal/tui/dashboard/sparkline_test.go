package dashboard

import (
	"strings"
	"testing"
)

func TestRenderSparklineEmptyOrInvalidWidth(t *testing.T) {
	if got := renderSparkline(nil, 5); got != "" {
		t.Fatalf("expected empty sparkline for nil data, got %q", got)
	}
	if got := renderSparkline([]float64{1, 2, 3}, 0); got != "" {
		t.Fatalf("expected empty sparkline for width 0, got %q", got)
	}
}

func TestRenderSparklineSingleValue(t *testing.T) {
	got := renderSparkline([]float64{10}, 8)
	if got != "        \n████████" {
		t.Fatalf("expected two-line constant sparkline, got %q", got)
	}
}

func TestRenderSparklineAllEqualValues(t *testing.T) {
	got := renderSparkline([]float64{5, 5, 5, 5}, 4)
	if got != "    \n████" {
		t.Fatalf("expected two-line flat sparkline, got %q", got)
	}
}

func TestRenderSparklineStretchesShortHistoryToWidth(t *testing.T) {
	got := renderSparkline([]float64{1, 2, 3}, 6)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %q", got)
	}
	if strings.HasPrefix(lines[1], "   ") {
		t.Fatalf("expected short history to fill width, got %q", lines[1])
	}
}

func TestRenderSparklineRespectsWidthTruncation(t *testing.T) {
	got := renderSparkline([]float64{1, 2, 3, 4, 5, 6, 7, 8}, 4)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %q", got)
	}
	if len([]rune(lines[0])) != 4 || len([]rune(lines[1])) != 4 {
		t.Fatalf("expected 4 runes per line, got %q", got)
	}
}

func TestRenderSparklineSpansLowToHigh(t *testing.T) {
	got := renderSparkline([]float64{0, 10}, 2)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %q", got)
	}
	if !strings.Contains(got, "█") {
		t.Fatalf("expected high bar, got %q", got)
	}
}

func TestRenderLabeledSparklineAlignsSecondRow(t *testing.T) {
	got := renderLabeledSparkline("Latency:", []float64{0, 10}, 2)
	lines := strings.Split(got, "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %q", got)
	}
	if !strings.HasPrefix(lines[0], "Latency: ") {
		t.Fatalf("expected label prefix on first row, got %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "         ") {
		t.Fatalf("expected padding on second row to align sparkline, got %q", lines[1])
	}
}
