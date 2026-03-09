package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

func TestRenderProcessesIncludesHeaders(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		nil, nil,
		[]statsengine.ProcessSnapshot{
			{PID: 200, Comm: "proc-b", Syscalls: 10, RatePerSec: 2.3, Bytes: 2048, AvgLatencyNs: 1500},
			{PID: 100, Comm: "proc-a", Syscalls: 20, RatePerSec: 4.6, Bytes: 4096, AvgLatencyNs: 2500},
		},
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderProcesses(&snap, 120, 30)
	for _, token := range []string{"PID", "Comm", "Syscalls", "Total Bytes", "Avg Latency"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected header token %q", token)
		}
	}
	if !strings.Contains(out, "100") || !strings.Contains(out, "proc-a") {
		t.Fatalf("expected process row in output")
	}
	if !strings.Contains(out, "s:sort") {
		t.Fatalf("expected processes sort hint in output")
	}
	if !strings.Contains(out, "sort: default") {
		t.Fatalf("expected processes default sort label in output")
	}
}

func TestRenderProcessesShowsSinglePIDNote(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		nil, nil,
		[]statsengine.ProcessSnapshot{
			{PID: 77, Comm: "proc", Syscalls: 1},
		},
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderProcessesWithOffset(&snap, 100, 20, 0, 0, 77)
	if !strings.Contains(out, "most useful with All PIDs") {
		t.Fatalf("expected single-pid guidance note")
	}
}

func TestTruncateText(t *testing.T) {
	got := truncateText("very-long-process-name", 10)
	if got != "very-lo..." {
		t.Fatalf("unexpected truncation result: %q", got)
	}
}

func TestSortedProcessTableRowsUsesSelectedSortKey(t *testing.T) {
	rows := []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
		{PID: 100, Comm: "agent", Syscalls: 3},
	}

	sorted := sortedProcessTableRows(rows, tableSortState[processSortKey]{active: true, key: processSortKeyComm})
	if sorted[0].PID != 100 {
		t.Fatalf("expected comm sort to put PID 100 first, got %d", sorted[0].PID)
	}

	sorted = sortedProcessTableRows(rows, tableSortState[processSortKey]{active: true, key: processSortKeyPID})
	if sorted[0].PID != 100 {
		t.Fatalf("expected pid asc sort to put PID 100 first, got %d", sorted[0].PID)
	}
}
