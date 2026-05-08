package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
)

func TestRenderFilesIncludesHeaders(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil,
		nil,
		nil,
		nil,
		[]statsengine.FileSnapshot{
			{Path: "/var/log/app.log", Accesses: 42, BytesRead: 4096, BytesWritten: 2048, AvgLatencyNs: 1500, MaxLatencyNs: 20_000},
		},
		nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)

	out := renderFiles(&snap, 120, 30)
	for _, token := range []string{"Path", "Accesses", "Read", "Write", "Avg Latency", "Max Latency", "app.log"} {
		if !strings.Contains(out, token) {
			t.Fatalf("expected token %q in files table output", token)
		}
	}
	if !strings.Contains(out, "s/S:sort") {
		t.Fatalf("expected files sort hint in output")
	}
	if !strings.Contains(out, "sort: default") {
		t.Fatalf("expected files default sort label in output")
	}
}

func TestRenderFilesNoData(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	if got := renderFiles(&snap, 100, 20); got != "Files: no data" {
		t.Fatalf("unexpected no-data output: %q", got)
	}
}

func TestTruncatePathMiddle(t *testing.T) {
	longPath := "/very/long/path/with/high/cardinality/segments/and/filename.log"
	got := truncatePathMiddle(longPath, 24)
	if len(got) != 24 {
		t.Fatalf("expected truncated path length 24, got %d (%q)", len(got), got)
	}
	if !strings.Contains(got, "...") {
		t.Fatalf("expected ellipsis in truncated path, got %q", got)
	}
	if !strings.HasPrefix(got, "/very") || !strings.HasSuffix(got, "e.log") {
		t.Fatalf("expected head and tail preservation, got %q", got)
	}
}

func TestFilePathWidthExpandsOnWideTerminal(t *testing.T) {
	got := filePathWidth(180)
	if got <= 80 {
		t.Fatalf("expected wide path column to use remaining space, got %d", got)
	}
}

func TestAggregateFilesByDir(t *testing.T) {
	files := []statsengine.FileSnapshot{
		{Path: "/var/log/a.log", Accesses: 10, BytesRead: 100, BytesWritten: 40, AvgLatencyNs: 100, MaxLatencyNs: 300, TotalLatencyNs: 1000},
		{Path: "/var/log/b.log", Accesses: 20, BytesRead: 200, BytesWritten: 60, AvgLatencyNs: 200, MaxLatencyNs: 500, TotalLatencyNs: 4000},
		{Path: "/tmp/c.log", Accesses: 5, BytesRead: 50, BytesWritten: 10, AvgLatencyNs: 1000, MaxLatencyNs: 1200, TotalLatencyNs: 5000},
	}

	got := aggregateFilesByDir(files)
	if len(got) != 2 {
		t.Fatalf("expected 2 grouped dirs, got %d", len(got))
	}

	// Sorted by accesses desc, then directory asc.
	if got[0].Dir != "/var/log" {
		t.Fatalf("expected first dir /var/log, got %q", got[0].Dir)
	}
	if got[0].Accesses != 30 || got[0].BytesRead != 300 || got[0].BytesWritten != 100 {
		t.Fatalf("unexpected aggregated counters for /var/log: %+v", got[0])
	}
	if got[0].FileCount != 2 {
		t.Fatalf("expected file count 2 for /var/log, got %d", got[0].FileCount)
	}
	if got[0].MaxLatencyNs != 500 {
		t.Fatalf("expected max latency 500 for /var/log, got %d", got[0].MaxLatencyNs)
	}
	// Weighted average: (100*10 + 200*20) / 30 = 166.666...
	if got[0].AvgLatencyNs < 166.6 || got[0].AvgLatencyNs > 166.7 {
		t.Fatalf("unexpected weighted avg latency for /var/log: %f", got[0].AvgLatencyNs)
	}

	if got[1].Dir != "/tmp" || got[1].Accesses != 5 || got[1].FileCount != 1 {
		t.Fatalf("unexpected second grouped dir: %+v", got[1])
	}
}

func TestAggregateFilesByDirEmpty(t *testing.T) {
	if got := aggregateFilesByDir(nil); len(got) != 0 {
		t.Fatalf("expected empty result for nil input, got %d entries", len(got))
	}
	if got := aggregateFilesByDir([]statsengine.FileSnapshot{}); len(got) != 0 {
		t.Fatalf("expected empty result for empty input, got %d entries", len(got))
	}
}

func TestDirPathWidthAccountsForFilesColumn(t *testing.T) {
	if got := dirPathWidth(180); got != filePathWidth(180)-6 {
		t.Fatalf("expected dirPathWidth to reserve 6 extra chars, got dir=%d file=%d", got, filePathWidth(180))
	}
}

func TestSortedFileSnapshotsUsesSelectedSortKey(t *testing.T) {
	rows := []statsengine.FileSnapshot{
		{Path: "/tmp/z.log", Accesses: 9, BytesRead: 10},
		{Path: "/tmp/a.log", Accesses: 3, BytesRead: 50},
	}

	sorted := sortedFileSnapshots(rows, tableSortState[fileSortKey]{active: true, key: fileSortKeyPath})
	if sorted[0].Path != "/tmp/a.log" {
		t.Fatalf("expected path sort to put /tmp/a.log first, got %q", sorted[0].Path)
	}

	sorted = sortedFileSnapshots(rows, tableSortState[fileSortKey]{active: true, key: fileSortKeyRead})
	if sorted[0].Path != "/tmp/a.log" {
		t.Fatalf("expected read desc sort to put /tmp/a.log first, got %q", sorted[0].Path)
	}

	sorted = sortedFileSnapshots(rows, tableSortState[fileSortKey]{active: true, key: fileSortKeyPath, reverse: true})
	if sorted[0].Path != "/tmp/z.log" {
		t.Fatalf("expected reverse path sort to put /tmp/z.log first, got %q", sorted[0].Path)
	}
}

func TestSortedDirSnapshotsUsesSelectedSortKey(t *testing.T) {
	rows := []DirSnapshot{
		{Dir: "/var/log", Accesses: 9, FileCount: 1},
		{Dir: "/tmp", Accesses: 3, FileCount: 4},
	}

	sorted := sortedDirSnapshots(rows, tableSortState[fileDirSortKey]{active: true, key: fileDirSortKeyDir})
	if sorted[0].Dir != "/tmp" {
		t.Fatalf("expected dir sort to put /tmp first, got %q", sorted[0].Dir)
	}

	sorted = sortedDirSnapshots(rows, tableSortState[fileDirSortKey]{active: true, key: fileDirSortKeyFileCount})
	if sorted[0].Dir != "/tmp" {
		t.Fatalf("expected file-count sort to put /tmp first, got %q", sorted[0].Dir)
	}

	sorted = sortedDirSnapshots(rows, tableSortState[fileDirSortKey]{active: true, key: fileDirSortKeyDir, reverse: true})
	if sorted[0].Dir != "/var/log" {
		t.Fatalf("expected reverse dir sort to put /var/log first, got %q", sorted[0].Dir)
	}
}
