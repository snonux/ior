package dashboard

import (
	"strings"
	"testing"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

func TestRenderOverviewIncludesCoreMetrics(t *testing.T) {
	snap := &statsengine.Snapshot{
		Elapsed:           95 * time.Second,
		TotalSyscalls:     1200,
		SyscallRatePerSec: 12.5,
		TotalBytes:        10 * 1024 * 1024,
		ReadBytesPerSec:   4096,
		WriteBytesPerSec:  8192,
		TotalErrors:       12,
		LatencyMeanNs:     5000,
		LatencyTrend:      statsengine.Trend{Direction: statsengine.TrendRising, DeltaPercent: 12.5},
		GapTrend:          statsengine.Trend{Direction: statsengine.TrendFalling, DeltaPercent: -7.4},
		ThroughputTrend:   statsengine.Trend{Direction: statsengine.TrendStable, DeltaPercent: 0},
	}

	out := renderOverview(snap, 120, 40)
	for _, token := range []string{
		"Elapsed:",
		"Syscalls:",
		"Read/s:",
		"Errors:",
		"Trends:",
		"Latency:",
		"Gap:",
		"Throughput:",
		"Top syscalls:",
		"Top files:",
		"Top processes:",
		"Latency buckets:",
		"Gap buckets:",
	} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in overview output", token)
		}
	}
}

func TestSummarizeTopSyscalls(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		[]statsengine.SyscallSnapshot{
			{Name: "read", Count: 50},
			{Name: "write", Count: 20},
			{Name: "openat", Count: 10},
			{Name: "close", Count: 5},
		},
		nil, nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	got := summarizeTopSyscalls(&snap)
	if got != "read(50), write(20), openat(10)" {
		t.Fatalf("unexpected top syscall summary: %q", got)
	}
}

func TestRenderOverviewWithoutSnapshot(t *testing.T) {
	out := renderOverview(nil, 80, 24)
	if !strings.Contains(out, "waiting for stats") {
		t.Fatalf("expected waiting placeholder, got %q", out)
	}
}

func TestOverviewSummariesIncludeFilesProcessesAndHistograms(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		[]statsengine.SyscallSnapshot{{Name: "read", Count: 2}},
		[]statsengine.FileSnapshot{{Path: "/tmp/very/long/path/file.log", Accesses: 4}},
		[]statsengine.ProcessSnapshot{{PID: 12, Comm: "proc", Syscalls: 7}},
		statsengine.NewHistogramSnapshot(3, []statsengine.HistogramBucketSnapshot{
			{Label: "[0,1us)", Count: 2},
			{Label: "[1us,10us)", Count: 1},
		}),
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{
			{Label: "[10us,100us)", Count: 1},
		}),
	)

	out := renderOverview(&snap, 120, 40)
	for _, token := range []string{"Top files:", "Top processes:", "Latency buckets:", "Gap buckets:"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected %q in overview output", token)
		}
	}
}

func TestRenderOverviewDoesNotOverflowWidth(t *testing.T) {
	snap := statsengine.NewSnapshot(
		[]float64{10, 20, 15, 30, 18, 35, 40},
		[]float64{2, 4, 3, 5, 7, 6, 8},
		[]float64{1024, 2048, 4096, 2048, 1024},
		[]statsengine.SyscallSnapshot{{Name: "read", Count: 20}},
		[]statsengine.FileSnapshot{{Path: "/tmp/very/long/path/to/file.log", Accesses: 10}},
		[]statsengine.ProcessSnapshot{{PID: 42, Comm: "proc", Syscalls: 30}},
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	const width = 120
	out := renderOverview(&snap, width, 30)
	for _, line := range strings.Split(out, "\n") {
		if lipgloss.Width(line) > width {
			t.Fatalf("overview line exceeds width %d: got %d in %q", width, lipgloss.Width(line), line)
		}
	}
}

func TestRenderOverviewSparklineHasSafetyMargin(t *testing.T) {
	const panelInner = 80
	out := renderOverviewSparkline("Latency:", []float64{1, 2, 3, 4, 5}, panelInner)
	if strings.Contains(out, "\n") {
		t.Fatalf("expected single-line sparkline, got %q", out)
	}
	if got, max := lipgloss.Width(out), panelInner-sparklineSafetyMargin; got > max {
		t.Fatalf("expected sparkline width <= %d with safety margin, got %d", max, got)
	}
}

func TestRenderOverviewSparklineUsesAvailableWidth(t *testing.T) {
	out := renderOverviewSparkline("Latency:", make([]float64, 120), 400)
	if strings.Contains(out, "\n") {
		t.Fatalf("expected single-line sparkline, got %q", out)
	}
	want := 400 - len("Latency:") - 1 - sparklineSafetyMargin
	if got := lipgloss.Width(out) - len("Latency: "); got != want {
		t.Fatalf("expected sparkline width %d, got %d", want, got)
	}
}

func TestRenderOverviewSparklineAlignedUsesSameSparkStartColumn(t *testing.T) {
	const panelInner = 80
	labelWidth := maxLabelWidth("Latency:", "Gap:", "Throughput:")
	lat := renderOverviewSparklineAligned("Latency:", []float64{1, 2, 3}, panelInner, labelWidth)
	gap := renderOverviewSparklineAligned("Gap:", []float64{1, 2, 3}, panelInner, labelWidth)
	thr := renderOverviewSparklineAligned("Throughput:", []float64{1, 2, 3}, panelInner, labelWidth)

	latTop := strings.Split(lat, "\n")[0]
	gapTop := strings.Split(gap, "\n")[0]
	thrTop := strings.Split(thr, "\n")[0]

	prefix := strings.Repeat(" ", labelWidth-len("Latency:"))
	if !strings.HasPrefix(latTop, "Latency:"+prefix+" ") {
		t.Fatalf("unexpected latency prefix: %q", latTop)
	}
	prefix = strings.Repeat(" ", labelWidth-len("Gap:"))
	if !strings.HasPrefix(gapTop, "Gap:"+prefix+" ") {
		t.Fatalf("unexpected gap prefix: %q", gapTop)
	}
	if !strings.HasPrefix(thrTop, "Throughput: ") {
		t.Fatalf("unexpected throughput prefix: %q", thrTop)
	}
}

func TestRenderOverviewSparklineAlignedFitsSinglePanelRow(t *testing.T) {
	panelW := panelWidth(220)
	panelInner := panelInnerWidth(220)
	labelWidth := maxLabelWidth("Latency:", "Gap:", "Throughput:")
	line := renderOverviewSparklineAligned("Latency:", []float64{0, 10, 5, 10, 0}, panelInner, labelWidth)
	rendered := common.PanelStyle.Width(panelW).Render(line)
	if got := len(strings.Split(rendered, "\n")); got != 3 {
		t.Fatalf("expected sparkline to fit one panel row (3 total lines with border), got %d lines", got)
	}
}
