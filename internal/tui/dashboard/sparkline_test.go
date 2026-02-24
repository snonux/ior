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
	if got != "▄" {
		t.Fatalf("expected single mid-bar rune, got %q", got)
	}
}

func TestRenderSparklineAllEqualValues(t *testing.T) {
	got := renderSparkline([]float64{5, 5, 5, 5}, 4)
	if got != "▄▄▄▄" {
		t.Fatalf("expected flat sparkline, got %q", got)
	}
}

func TestRenderSparklineRespectsWidthTruncation(t *testing.T) {
	got := renderSparkline([]float64{1, 2, 3, 4, 5, 6, 7, 8}, 4)
	if len([]rune(got)) != 4 {
		t.Fatalf("expected 4 runes, got %q", got)
	}
}

func TestRenderSparklineSpansLowToHigh(t *testing.T) {
	got := renderSparkline([]float64{0, 10}, 2)
	if !strings.Contains(got, "▁") || !strings.Contains(got, "█") {
		t.Fatalf("expected low/high bars, got %q", got)
	}
}
