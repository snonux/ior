package dashboard

import (
	"strings"
	"testing"
	"time"

	"ior/internal/statsengine"
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
