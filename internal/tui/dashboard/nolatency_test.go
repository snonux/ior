package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

// noLatencyFixture is a snapshot with one timed syscall/process and one
// whose every invocation was untimed (exit_group: statsengine NoLatency),
// with the placeholder 0s the engine leaves in its latency fields.
func noLatencyFixture() (statsengine.Snapshot, statsengine.SyscallSnapshot, statsengine.SyscallSnapshot) {
	timed := statsengine.SyscallSnapshot{Name: "read", Count: 4, LatencyMeanNs: 1500, LatencyMinNs: 1000,
		LatencyMaxNs: 2000, LatencyP50Ns: 1400, LatencyP95Ns: 1900, LatencyP99Ns: 2000, TotalLatencyNs: 6000}
	untimed := statsengine.SyscallSnapshot{Name: "exit_group", Count: 2, NoLatency: true}
	snap := statsengine.NewSnapshot(nil, nil, nil,
		[]statsengine.SyscallSnapshot{timed, untimed}, nil,
		[]statsengine.ProcessSnapshot{
			{PID: 10, Comm: "timed", Syscalls: 4, AvgLatencyNs: 1500, TotalLatencyNs: 6000},
			{PID: 11, Comm: "untimed", Syscalls: 1, NoLatency: true},
		},
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return snap, timed, untimed
}

// TestSyscallRowsShowDashForNoLatency (task pr2): every latency cell of a
// syscall without a timed sample (all exit_group/exit/rt_sigreturn) renders
// "-", in the full and the compact table, while a timed row keeps its
// numbers, including the identical 0-valued fields of a timed row.
func TestSyscallRowsShowDashForNoLatency(t *testing.T) {
	_, timed, untimed := noLatencyFixture()
	zeroTimed := statsengine.SyscallSnapshot{Name: "getpid", Count: 1}
	full := syscallRowsFull([]statsengine.SyscallSnapshot{timed, untimed, zeroTimed})
	compact := syscallRowsCompact([]statsengine.SyscallSnapshot{timed, untimed, zeroTimed})

	wantFull := [][]string{
		{"1.5µs", "1.0µs", "2.0µs", "1.4µs", "1.9µs", "2.0µs"},
		{"-", "-", "-", "-", "-", "-"},
		{"0ns", "0ns", "0ns", "0ns", "0ns", "0ns"},
	}
	wantCompact := [][]string{{"1.5µs", "1.9µs", "2.0µs"}, {"-", "-", "-"}, {"0ns", "0ns", "0ns"}}
	for i := range wantFull {
		if got := full[i][4:10]; strings.Join(got, "|") != strings.Join(wantFull[i], "|") {
			t.Errorf("full row %d latency cells = %v, want %v", i, got, wantFull[i])
		}
		if got := compact[i][4:7]; strings.Join(got, "|") != strings.Join(wantCompact[i], "|") {
			t.Errorf("compact row %d latency cells = %v, want %v", i, got, wantCompact[i])
		}
	}
	// The non-latency cells of the untimed row are unchanged.
	if full[1][2] != "2" || full[1][11] != "0" {
		t.Errorf("untimed row count/errors = %q/%q, want 2/0", full[1][2], full[1][11])
	}
}

// TestProcessRowsShowDashForNoLatency: a process seen only at its
// exit_group has no average latency; its Avg Latency cell renders "-".
func TestProcessRowsShowDashForNoLatency(t *testing.T) {
	snap, _, _ := noLatencyFixture()
	rows := processRows(snap.Processes())
	got := map[string]string{}
	for _, row := range rows {
		got[row[1]] = row[5]
	}
	if got["timed"] != "1.5µs" || got["untimed"] != "-" {
		t.Fatalf("avg latency cells = %v, want timed 1.5µs, untimed -", got)
	}
}

// TestBubbleAndTreemapDetailsShowDashForNoLatency: the bubble and treemap
// views of the Syscalls and Processes tabs describe the same rows, so their
// p95/avg detail text says "-" as well.
func TestBubbleAndTreemapDetailsShowDashForNoLatency(t *testing.T) {
	snap, _, _ := noLatencyFixture()
	details := map[string]string{}
	for _, d := range syscallBubbleData(snap.Syscalls(), bubbleMetricCount) {
		details["bubble "+d.Label] = d.Detail
	}
	for _, d := range processBubbleData(&snap, bubbleMetricCount) {
		details["bubble "+d.Label] = d.Detail
	}
	for _, it := range buildSyscallTreemapItems(snap.Syscalls(), bubbleMetricCount) {
		details["treemap "+it.Name] = it.Detail
	}
	for _, it := range buildProcessesTreemapItems(&snap, bubbleMetricCount) {
		details["treemap "+it.Name] = it.Detail
	}
	checks := 0
	for key, detail := range details {
		untimed := strings.Contains(key, "exit_group") || strings.Contains(key, "untimed")
		dashed := strings.HasSuffix(detail, "p95 -") || strings.HasSuffix(detail, "avg -")
		if untimed != dashed {
			t.Errorf("%s detail = %q, want a dash latency only for the untimed rows", key, detail)
		}
		checks++
	}
	if checks != 8 {
		t.Fatalf("got %d bubble/treemap items %v, want 8", checks, details)
	}
}
