package export

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ior/internal/statsengine"
)

// TestSnapshotCSVNilSnapshot verifies that SnapshotCSV writes a valid CSV file
// with only the header and summary rows when the snapshot is nil.
func TestSnapshotCSVNilSnapshot(t *testing.T) {
	// Run inside a temp dir so the timestamped CSV file is automatically
	// cleaned up after the test.
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	name, err := SnapshotCSV(nil)
	if err != nil {
		t.Fatalf("SnapshotCSV(nil) returned error: %v", err)
	}
	if name == "" {
		t.Fatal("SnapshotCSV returned empty filename")
	}
	if !strings.HasPrefix(filepath.Base(name), "ior-snapshot-") {
		t.Fatalf("unexpected filename prefix: %q", name)
	}

	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read csv file: %v", err)
	}

	r := csv.NewReader(strings.NewReader(string(data)))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}

	// Nil snapshot: expect header + 4 summary rows.
	if len(records) < 5 {
		t.Fatalf("expected at least 5 CSV rows, got %d", len(records))
	}
	if records[0][0] != "section" {
		t.Fatalf("expected header row first cell 'section', got %q", records[0][0])
	}
	for _, row := range records[1:5] {
		if row[0] != "summary" {
			t.Fatalf("expected summary row, got section=%q", row[0])
		}
	}
}

// TestSnapshotCSVWithData verifies that SnapshotCSV emits syscall, file, and
// process rows when the snapshot contains non-empty data.
func TestSnapshotCSVWithData(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	snap := statsengine.NewSnapshot(
		nil, nil, nil,
		[]statsengine.SyscallSnapshot{
			{Name: "read", Count: 10, RatePerSec: 1.5, Bytes: 4096},
		},
		[]statsengine.FileSnapshot{
			{Path: "/tmp/x", Accesses: 3, BytesRead: 128, BytesWritten: 64, AvgLatencyNs: 100},
		},
		[]statsengine.ProcessSnapshot{
			{PID: 42, Comm: "cat", Syscalls: 5, RatePerSec: 0.5, AvgLatencyNs: 200},
		},
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{
			{Label: "0-1µs", LowerNs: 0, UpperNs: 1000, Count: 1},
		}),
		statsengine.NewHistogramSnapshot(0, nil),
	)

	name, err := SnapshotCSV(&snap)
	if err != nil {
		t.Fatalf("SnapshotCSV returned error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read csv file: %v", err)
	}

	content := string(data)
	for _, want := range []string{"syscall", "read", "file", "/tmp/x", "process", "42", "latency_hist", "0-1µs"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected %q in CSV output, got:\n%s", want, content)
		}
	}
}

// TestSnapValueHelpers verifies the nil-safe helper functions directly.
func TestSnapValueHelpers(t *testing.T) {
	if got := snapValue(nil, func(s *statsengine.Snapshot) uint64 { return s.TotalSyscalls }); got != 0 {
		t.Fatalf("snapValue(nil) = %d, want 0", got)
	}
	if got := snapValueF(nil, func(s *statsengine.Snapshot) float64 { return s.SyscallRatePerSec }); got != 0 {
		t.Fatalf("snapValueF(nil) = %f, want 0", got)
	}
	if got := trendSummary(nil, func(s *statsengine.Snapshot) statsengine.Trend { return s.LatencyTrend }); got != "stable:0.00" {
		t.Fatalf("trendSummary(nil) = %q, want stable:0.00", got)
	}

	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil,
		statsengine.NewHistogramSnapshot(0, nil),
		statsengine.NewHistogramSnapshot(0, nil),
	)
	snap.TotalSyscalls = 99
	snap.SyscallRatePerSec = 3.14
	snap.LatencyTrend = statsengine.Trend{Direction: statsengine.TrendRising, DeltaPercent: 12.5}

	if got := snapValue(&snap, func(s *statsengine.Snapshot) uint64 { return s.TotalSyscalls }); got != 99 {
		t.Fatalf("snapValue = %d, want 99", got)
	}
	if got := snapValueF(&snap, func(s *statsengine.Snapshot) float64 { return s.SyscallRatePerSec }); got != 3.14 {
		t.Fatalf("snapValueF = %f, want 3.14", got)
	}
	if got := trendSummary(&snap, func(s *statsengine.Snapshot) statsengine.Trend { return s.LatencyTrend }); got != "rising:12.50" {
		t.Fatalf("trendSummary = %q, want rising:12.50", got)
	}
}
