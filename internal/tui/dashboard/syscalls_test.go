package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

func TestRenderSyscallsIncludesHeaders(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		[]statsengine.SyscallSnapshot{
			{Name: "write", Count: 5, RatePerSec: 1.2, Bytes: 1024, Errors: 1},
			{Name: "read", Count: 10, RatePerSec: 2.4, Bytes: 2048, Errors: 0},
		},
		nil, nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderSyscalls(&snap, 120, 30)
	for _, token := range []string{"Syscall", "Count", "Rate/s", "p95", "p99", "Bytes", "Errors"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in syscall table view", token)
		}
	}
	if !strings.Contains(out, "read") {
		t.Fatalf("expected syscall row in output")
	}
	if !strings.Contains(out, "s:sort") {
		t.Fatalf("expected syscall sort hint in output")
	}
	if !strings.Contains(out, "sort: default") {
		t.Fatalf("expected default sort label in output")
	}
}

func TestFormatDurationNs(t *testing.T) {
	if got := formatDurationNs(50); got != "50ns" {
		t.Fatalf("unexpected ns formatting: %q", got)
	}
	if got := formatDurationNs(1500); !strings.Contains(got, "µs") {
		t.Fatalf("expected µs formatting, got %q", got)
	}
	if got := formatDurationNs(2_500_000); !strings.Contains(got, "ms") {
		t.Fatalf("expected ms formatting, got %q", got)
	}
}

func TestClampOffset(t *testing.T) {
	if got := clampOffset(-5, 10); got != 0 {
		t.Fatalf("expected 0 for negative offset, got %d", got)
	}
	if got := clampOffset(99, 4); got != 3 {
		t.Fatalf("expected max index clamp, got %d", got)
	}
}

func TestSortedSyscallSnapshotsUsesSelectedSortKey(t *testing.T) {
	rows := []statsengine.SyscallSnapshot{
		{Name: "write", Count: 8, LatencyP95Ns: 10},
		{Name: "read", Count: 3, LatencyP95Ns: 50},
	}

	sorted := sortedSyscallSnapshots(rows, tableSortState[syscallSortKey]{active: true, key: syscallSortKeyName})
	if sorted[0].Name != "read" {
		t.Fatalf("expected syscall name sort to put read first, got %q", sorted[0].Name)
	}

	sorted = sortedSyscallSnapshots(rows, tableSortState[syscallSortKey]{active: true, key: syscallSortKeyP95})
	if sorted[0].Name != "read" {
		t.Fatalf("expected p95 desc sort to put read first, got %q", sorted[0].Name)
	}
}

func TestSyscallSortKeyForColumnKeepsLogicalMeaningAcrossWidths(t *testing.T) {
	key, ok := syscallSortKeyForColumn(120, 4)
	if !ok || key != syscallSortKeyP95 {
		t.Fatalf("expected compact column 4 to map to p95, got %v ok=%v", key, ok)
	}

	key, ok = syscallSortKeyForColumn(160, 7)
	if !ok || key != syscallSortKeyP95 {
		t.Fatalf("expected full column 7 to map to p95, got %v ok=%v", key, ok)
	}
}
