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
		"Throughput:",
		"Top syscalls:",
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
