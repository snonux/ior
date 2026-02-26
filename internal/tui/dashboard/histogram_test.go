package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"

	"github.com/charmbracelet/lipgloss"
)

func TestRenderHistogramNoBuckets(t *testing.T) {
	out := renderHistogram(statsengine.HistogramSnapshot{}, "Latency Histogram", 80, 20)
	if !strings.Contains(out, "no data") {
		t.Fatalf("expected no data placeholder, got %q", out)
	}
}

func TestRenderHistogramIncludesLabelsCountsAndScale(t *testing.T) {
	hist := statsengine.NewHistogramSnapshot(13, []statsengine.HistogramBucketSnapshot{
		{Label: "[0,1us)", Count: 1},
		{Label: "[1us,10us)", Count: 3},
		{Label: "[10us,100us)", Count: 9},
	})

	out := renderHistogram(hist, "Latency Histogram", 100, 20)
	for _, token := range []string{"Latency Histogram", "[0,1us)", "[1us,10us)", "[10us,100us)", "9", "Scale: █▓▒░"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in histogram output", token)
		}
	}
	if !strings.Contains(out, "█") {
		t.Fatalf("expected high-intensity bar rune in histogram output")
	}
}

func TestRenderLatencyAndGapsTabIncludeSparkline(t *testing.T) {
	snap := statsengine.NewSnapshot(
		[]float64{10, 20, 15, 30},
		[]float64{2, 4, 3, 5},
		nil,
		nil,
		nil,
		nil,
		statsengine.NewHistogramSnapshot(2, []statsengine.HistogramBucketSnapshot{
			{Label: "[0,1us)", Count: 2},
		}),
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{
			{Label: "[1us,10us)", Count: 1},
		}),
	)

	lat := renderLatencyTab(&snap, 100, 24)
	if !strings.Contains(lat, "Latency Histogram") || !strings.Contains(lat, "Latency sparkline:") {
		t.Fatalf("latency tab missing expected sections: %q", lat)
	}

	gap := renderGapsTab(&snap, 100, 24)
	if !strings.Contains(gap, "Gap Histogram") || !strings.Contains(gap, "Gap sparkline:") {
		t.Fatalf("gaps tab missing expected sections: %q", gap)
	}
}

func TestRenderHistogramTruncatesForSmallHeight(t *testing.T) {
	hist := statsengine.NewHistogramSnapshot(3, []statsengine.HistogramBucketSnapshot{
		{Label: "[0,1us)", Count: 1},
		{Label: "[1us,10us)", Count: 1},
		{Label: "[10us,100us)", Count: 1},
	})

	out := renderHistogram(hist, "Latency Histogram", 100, 3)
	if !strings.Contains(out, "[0,1us)") {
		t.Fatalf("expected first bucket in output: %q", out)
	}
	if strings.Contains(out, "[1us,10us)") || strings.Contains(out, "[10us,100us)") {
		t.Fatalf("expected histogram rows to be truncated for small height: %q", out)
	}
}

func TestRenderLatencyGapsTabDoesNotOverflowWidth(t *testing.T) {
	snap := statsengine.NewSnapshot(
		[]float64{10, 20, 15, 30, 18, 35},
		[]float64{2, 4, 3, 5, 7, 6},
		nil,
		nil,
		nil,
		nil,
		statsengine.NewHistogramSnapshot(6, []statsengine.HistogramBucketSnapshot{
			{Label: "[0,1us)", Count: 1},
			{Label: "[1us,10us)", Count: 2},
			{Label: "[10us,100us)", Count: 3},
		}),
		statsengine.NewHistogramSnapshot(6, []statsengine.HistogramBucketSnapshot{
			{Label: "[0,1us)", Count: 1},
			{Label: "[1us,10us)", Count: 2},
			{Label: "[10us,100us)", Count: 3},
		}),
	)

	const width = 100
	out := renderLatencyGapsTab(&snap, width, 24)
	for _, line := range strings.Split(out, "\n") {
		if lipgloss.Width(line) > width {
			t.Fatalf("latency/gaps line exceeds width %d: got %d in %q", width, lipgloss.Width(line), line)
		}
	}
}
