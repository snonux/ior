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
