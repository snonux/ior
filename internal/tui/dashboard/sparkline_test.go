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
	if got != "▁▁▁▁▁▁▁▁" {
		t.Fatalf("expected single-line constant sparkline, got %q", got)
	}
}

func TestRenderSparklineAllEqualValues(t *testing.T) {
	got := renderSparkline([]float64{5, 5, 5, 5}, 4)
	if got != "▁▁▁▁" {
		t.Fatalf("expected single-line flat sparkline, got %q", got)
	}
}

func TestRenderSparklineAllZeroValuesRendersBlank(t *testing.T) {
	got := renderSparkline([]float64{0, 0, 0}, 5)
	if got != "     " {
		t.Fatalf("expected blank sparkline for all-zero series, got %q", got)
	}
}

func TestRenderSparklineLeftAlignsShortHistory(t *testing.T) {
	got := renderSparkline([]float64{1, 2, 3}, 6)
	first := strings.IndexFunc(got, func(r rune) bool { return r != ' ' })
	last := strings.LastIndexFunc(got, func(r rune) bool { return r != ' ' })
	if first < 0 || last < 0 {
		t.Fatalf("expected visible sparkline cells, got %q", got)
	}
	if strings.HasPrefix(got, "   ") {
		t.Fatalf("expected sparkline not to use old right-aligned padding, got %q", got)
	}
}

func TestRenderSparklineUsesRightmostColumn(t *testing.T) {
	got := renderSparkline([]float64{1, 3, 2, 5}, 20)
	row := []rune(got)
	if len(row) != 20 {
		t.Fatalf("expected 20 columns, got %d", len(row))
	}
	if row[19] == ' ' {
		t.Fatalf("expected rightmost column to contain sparkline data, got %q", got)
	}
}

func TestRenderSparklineRespectsWidthTruncation(t *testing.T) {
	got := renderSparkline([]float64{1, 2, 3, 4, 5, 6, 7, 8}, 4)
	if len([]rune(got)) != 4 {
		t.Fatalf("expected 4 runes, got %q", got)
	}
}

func TestSampleForWidthUsesRecentTail(t *testing.T) {
	got := sampleForWidth([]float64{1, 2, 3, 4, 5, 6}, 3)
	want := []float64{4, 5, 6}
	if len(got) != len(want) {
		t.Fatalf("expected tail length %d, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected tail %v, got %v", want, got)
		}
	}
}

func TestSampleForWidthUpsamplesToFullWidth(t *testing.T) {
	got := sampleForWidth([]float64{10, 20, 30}, 7)
	if len(got) != 7 {
		t.Fatalf("expected 7 samples, got %d", len(got))
	}
	if got[0] != 10 {
		t.Fatalf("expected first sample to preserve series start, got %v", got[0])
	}
	if got[len(got)-1] != 30 {
		t.Fatalf("expected last sample to preserve series end, got %v", got[len(got)-1])
	}
}

func TestRenderSparklineSpansLowToHigh(t *testing.T) {
	got := renderSparkline([]float64{0, 10}, 2)
	if got != "▁█" {
		t.Fatalf("expected low-to-high one-row sparkline, got %q", got)
	}
}

func TestRenderLabeledSparklineSingleLine(t *testing.T) {
	got := renderLabeledSparkline("Latency:", []float64{0, 10}, 2)
	if strings.Contains(got, "\n") {
		t.Fatalf("expected single-line labeled sparkline, got %q", got)
	}
	if !strings.HasPrefix(got, "Latency: ") {
		t.Fatalf("expected label prefix, got %q", got)
	}
}
