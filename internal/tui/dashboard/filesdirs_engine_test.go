package dashboard

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// engineSnapshotForDominantDir is the task 0r2 scenario on a real engine:
// 10,000 files under /data read once each (98.7% of the accesses) next to 64
// files under /etc read twice. None of /data's files makes the engine's
// top-64 file ranking, so a directory view aggregated from Snapshot.Files()
// showed only /etc.
func engineSnapshotForDominantDir(t *testing.T) *statsengine.Snapshot {
	t.Helper()
	pair := func(path string) *event.Pair {
		return &event.Pair{
			File:     file.NewFd(3, path, -1),
			Duration: 10,
			Bytes:    4,
			ExitEv:   &types.RetEvent{RetType: types.READ_CLASSIFIED},
		}
	}
	e := statsengine.NewEngine(statsengine.DefaultTopN)
	for i := 0; i < 10000; i++ {
		e.Ingest(pair(fmt.Sprintf("/data/f%05d", i)))
	}
	for r := 0; r < 2; r++ {
		for i := 0; i < 64; i++ {
			e.Ingest(pair(fmt.Sprintf("/etc/c%02d", i)))
		}
	}
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestDirViewsShowTheDominantDirectoryOutsideTheTopFiles(t *testing.T) {
	snap := engineSnapshotForDominantDir(t)

	table := renderFilesDirGroupedWithSort(snap, 120, 20, 0, 0, tableSortState[fileDirSortKey]{})
	if !strings.Contains(table, "/data") || !strings.Contains(table, "10000") {
		t.Fatalf("table lacks /data with its 10000 accesses:\n%s", table)
	}

	var bubbleIDs []string
	for _, d := range filesDirBubbleData(snap) {
		bubbleIDs = append(bubbleIDs, d.ID)
	}
	if !contains(bubbleIDs, "/data") {
		t.Fatalf("bubbles lack /data: %v", bubbleIDs)
	}

	items := buildFilesTreemapItems(snap, bubbleMetricCount)
	if len(items) == 0 || items[0].Key != "/data" || items[0].Count != 10000 {
		t.Fatalf("treemap must lead with /data, got %+v", items)
	}

	tiles, ok := buildIcicleTiles(snap, 120, 20, bubbleMetricCount)
	if !ok {
		t.Fatal("icicle has no tiles")
	}
	if len(tiles) == 0 || tiles[0].node.fullPath != "/data" {
		t.Fatalf("icicle must lead with /data, got first tile %+v", tiles[0].node)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// remainderSnapshot is an engine-style snapshot with two ranked directories
// and a remainder row folding three more.
func remainderSnapshot() *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil,
		statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{}).
		WithDirs([]statsengine.DirSnapshot{
			{Dir: "/a", Accesses: 50, FileCount: 5},
			{Dir: "/b", Accesses: 40, FileCount: 4},
		}, statsengine.DirSnapshot{Folded: 3, Accesses: 30, BytesRead: 300, FileCount: 6})
	return &snap
}

func TestRemainderRowIsShownAndPinnedLast(t *testing.T) {
	snap := remainderSnapshot()
	rows := snapshotDirRows(snap)
	if len(rows) != 3 || !rows[2].IsRemainder() {
		t.Fatalf("rows = %+v, want /a, /b, remainder", rows)
	}
	table := renderFilesDirGroupedWithSort(snap, 120, 20, 0, 0, tableSortState[fileDirSortKey]{})
	if !strings.Contains(table, "(other: 3 dirs)") {
		t.Fatalf("remainder row missing from the table:\n%s", table)
	}

	// Ascending-by-accesses would put the 30-access remainder between /a and
	// /b or first; it must stay last under every sort key and direction.
	for key := fileDirSortKeyAccesses; key <= fileDirSortKeyDir; key++ {
		for _, desc := range []bool{false, true} {
			sorted := sortedDirSnapshots(rows, tableSortState[fileDirSortKey]{active: true, key: key, reverse: desc})
			if len(sorted) != 3 || !sorted[2].IsRemainder() {
				t.Fatalf("sort key %v reverse=%v moved the remainder: %+v", key, desc, sorted)
			}
		}
	}
	if !rows[2].IsRemainder() || rows[0].Dir != "/a" {
		t.Fatal("sortedDirSnapshots must not reorder its input")
	}
}

func TestRemainderRowHasAStableNonPathIdentity(t *testing.T) {
	snap := remainderSnapshot()

	if got := keysOf(snapshotDirRows(snap), dirKey); got[2] != remainderDirKey || strings.ContainsAny(got[0]+got[1], "\x00") {
		t.Fatalf("keys = %q", got)
	}
	items := buildFilesTreemapItems(snap, bubbleMetricCount)
	if len(items) != 3 || items[2].Key != remainderDirKey || items[2].Name != "(other: 3 dirs)" {
		t.Fatalf("treemap items = %+v", items)
	}
	data := filesDirBubbleData(snap)
	if len(data) != 3 || data[2].ID != remainderDirKey || data[2].Label != "(other: 3 dirs)" {
		t.Fatalf("bubble data = %+v", data)
	}
	tiles, ok := buildIcicleTiles(snap, 120, 20, bubbleMetricCount)
	if !ok {
		t.Fatal("no icicle tiles")
	}
	var leaf *icicleNode
	for _, tile := range tiles {
		if tile.node.remainder {
			leaf = tile.node
		}
	}
	if leaf == nil || leaf.fullPath != remainderDirKey || leaf.accesses != 30 || leaf.label() != "(other: 3 dirs)" {
		t.Fatalf("icicle remainder leaf = %+v", leaf)
	}
	if out := renderFilesIcicle(snap, 120, 20, bubbleMetricCount, len(tiles)-1, true); !strings.Contains(out, "(other: 3 dirs)") {
		t.Fatalf("icicle status/label lacks the remainder:\n%s", out)
	}
}

func TestEnterOnRemainderRowShowsNoticeAndNoFilter(t *testing.T) {
	m := filesModel(true)
	m.latest = remainderSnapshot()
	m.filesDirTab.offset = 2 // the remainder row

	if req, ok := enterFilterRequest(t, m); ok {
		t.Fatalf("Enter on the remainder must not request a filter, got %+v", req)
	}
	if m.filterNotice != otherDirsNotice {
		t.Fatalf("notice = %q, want the remainder notice", m.filterNotice)
	}

	// A real directory row still filters.
	m = filesModel(true)
	m.latest = remainderSnapshot()
	m.filesDirTab.offset = 0
	if _, ok := enterFilterRequest(t, m); !ok || m.filterNotice != "" {
		t.Fatalf("Enter on /a must filter without a notice (ok=%v notice=%q)", ok, m.filterNotice)
	}
}
