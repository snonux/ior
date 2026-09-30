package statsengine

import (
	"fmt"
	"testing"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

func buildDirs(t *testing.T, r *dirRanker, topN int) ([]DirSnapshot, DirSnapshot) {
	t.Helper()
	rows, other, err := buildDirSnapshots(r.snapshotInputs(), topN)
	if err != nil {
		t.Fatalf("buildDirSnapshots: %v", err)
	}
	return rows, other
}

func TestDirOf(t *testing.T) {
	cases := map[string]string{
		"/var/log/a.log": "/var/log", "/etc": "/", "//x": "/", "./src/main.go": "./src",
		"a//b": "a/", "a.log": NoDirGroup, "socket:[1]": NoDirGroup, "": NoDirGroup,
	}
	for path, want := range cases {
		if got := DirOf(path); got != want {
			t.Errorf("DirOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestDirRankerCountsDirectoriesOfFilesOutsideTheTopN is the task 0r2
// regression: a directory of thousands of once-read files must be ranked by
// its total even though none of its files is in the file ranker's top-N.
func TestDirRankerCountsDirectoriesOfFilesOutsideTheTopN(t *testing.T) {
	e := NewEngine(DefaultTopN)
	for i := 0; i < 10000; i++ {
		e.Ingest(newFilePair(fmt.Sprintf("/data/f%05d", i), 10, 5, types.READ_CLASSIFIED))
	}
	for r := 0; r < 2; r++ {
		for i := 0; i < 64; i++ {
			e.Ingest(newFilePair(fmt.Sprintf("/etc/c%02d", i), 20, 1, types.READ_CLASSIFIED))
		}
	}

	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	dirs := snap.Dirs()
	if len(dirs) != 2 || dirs[0].Dir != "/data" || dirs[1].Dir != "/etc" {
		t.Fatalf("directory ranking = %+v, want /data then /etc", dirs)
	}
	data := dirs[0]
	if data.Accesses != 10000 || data.BytesRead != 50000 || data.TotalLatencyNs != 100000 || data.AvgLatencyNs != 10 {
		t.Fatalf("/data counters wrong: %+v", data)
	}
	// Past the sketch size the count is an estimate: 10,000 within 25%.
	if data.FileCount < 7500 || data.FileCount > 12500 {
		t.Fatalf("/data FileCount = %d, want about 10000", data.FileCount)
	}
	if etc := dirs[1]; etc.Accesses != 128 || etc.FileCount != 64 || etc.MaxLatencyNs != 20 {
		t.Fatalf("/etc row wrong (FileCount is exact below the sketch size): %+v", etc)
	}
	if _, ok := snap.DirsOther(); ok {
		t.Fatal("no directory fell outside the top-N, want no remainder")
	}
	// The file view still holds only the top-N files: the bug's premise.
	if snap.FilesCount() > DefaultTopN {
		t.Fatalf("FilesCount = %d, want <= %d", snap.FilesCount(), DefaultTopN)
	}
}

func TestDirRankerRemainderSumsTheDirectoriesBelowTheTopN(t *testing.T) {
	r := newDirRankerWithConfig(2)
	// Accesses per directory: a=5, b=4, c=3, d=1 (bytes = accesses * 10).
	for dir, n := range map[string]int{"/a": 5, "/b": 4, "/c": 3, "/d": 1} {
		for i := 0; i < n; i++ {
			r.Add(newFilePair(dir+"/f", uint64(n), 10, types.WRITE_CLASSIFIED))
		}
	}

	rows, other := buildDirs(t, r, 2)
	if len(rows) != 2 || rows[0].Dir != "/a" || rows[1].Dir != "/b" {
		t.Fatalf("top rows = %+v, want /a then /b", rows)
	}
	if !other.IsRemainder() || other.Folded != 2 || other.Accesses != 4 || other.BytesWritten != 40 ||
		other.MaxLatencyNs != 3 || other.FileCount != 2 || other.Dir != "" {
		t.Fatalf("remainder wrong: %+v", other)
	}
	total := other.Accesses
	for _, row := range rows {
		total += row.Accesses
	}
	if total != 13 {
		t.Fatalf("rows + remainder = %d accesses, want all 13", total)
	}
}

// TestDirRankerCompactionKeepsTheTotalExact pins the cardinality guard: the
// tracked set stays bounded, the hot directory survives, and the counters of
// the dropped directories are folded into the remainder rather than lost.
func TestDirRankerCompactionKeepsTheTotalExact(t *testing.T) {
	r := newDirRankerWithLimits(3, 5)
	const hot, cold = 50, 300
	for i := 0; i < hot; i++ {
		r.Add(newFilePair("/hot/f", 1, 1, types.READ_CLASSIFIED))
	}
	for i := 0; i < cold; i++ {
		r.Add(newFilePair(fmt.Sprintf("/cold/d%d/f", i), 1, 1, types.READ_CLASSIFIED))
		if len(r.byDir) > r.maxSeen {
			t.Fatalf("cardinality guard failed: %d dirs tracked, maxSeen %d", len(r.byDir), r.maxSeen)
		}
	}

	rows, other := buildDirs(t, r, 3)
	if len(rows) == 0 || rows[0].Dir != "/hot" || rows[0].Accesses != hot {
		t.Fatalf("hot directory must stay top-ranked: %+v", rows)
	}
	total := other.Accesses
	for _, row := range rows {
		total += row.Accesses
	}
	if total != hot+cold {
		t.Fatalf("rows + remainder = %d accesses, want %d (compaction lost counts)", total, hot+cold)
	}
	if !other.IsRemainder() || other.Folded == 0 {
		t.Fatalf("expected a remainder after compaction, got %+v", other)
	}
}

func TestDirRankerIgnoresUnrankablePairsLikeTheFileRanker(t *testing.T) {
	r := newDirRankerWithConfig(3)
	r.Add(nil)
	r.Add(&event.Pair{})
	r.Add(&event.Pair{File: file.NewFd(1, "", -1), Duration: 10})
	r.Add(&event.Pair{File: file.NewFd(1, event.NoFileName, -1), Duration: 10})

	rows, other := buildDirs(t, r, 3)
	if len(rows) != 0 || other.IsRemainder() {
		t.Fatalf("unrankable pairs must not appear: rows=%+v other=%+v", rows, other)
	}
}

func TestDirRankerGroupsNamesWithoutSeparator(t *testing.T) {
	r := newDirRankerWithConfig(3)
	r.Add(newFilePair("a.log", 1, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("socket:[1]", 1, 1, types.READ_CLASSIFIED))
	r.Add(newFilePair("/top", 1, 1, types.READ_CLASSIFIED))

	rows, _ := buildDirs(t, r, 3)
	if len(rows) != 2 || rows[0].Dir != NoDirGroup || rows[0].Accesses != 2 || rows[0].FileCount != 2 || rows[1].Dir != "/" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestEngineResetClearsDirectories(t *testing.T) {
	e := NewEngine(4)
	e.Ingest(newFilePair("/a/x", 1, 1, types.READ_CLASSIFIED))
	e.Reset()
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Dirs()) != 0 {
		t.Fatalf("Reset left directories behind: %+v", snap.Dirs())
	}
}

func TestSnapshotDirsFallBackToGroupingFilesWithoutEngineRows(t *testing.T) {
	snap := NewSnapshot(nil, nil, nil, nil, []FileSnapshot{
		{Path: "/var/log/a", Accesses: 10, BytesRead: 100, TotalLatencyNs: 1000, MaxLatencyNs: 300},
		{Path: "/var/log/b", Accesses: 20, BytesWritten: 60, TotalLatencyNs: 4000, MaxLatencyNs: 500},
		{Path: "/tmp/c", Accesses: 5},
	}, nil, HistogramSnapshot{}, HistogramSnapshot{})

	got := snap.Dirs()
	if len(got) != 2 || got[0].Dir != "/var/log" || got[1].Dir != "/tmp" {
		t.Fatalf("fallback dirs = %+v", got)
	}
	if got[0].Accesses != 30 || got[0].BytesRead != 100 || got[0].BytesWritten != 60 || got[0].FileCount != 2 ||
		got[0].MaxLatencyNs != 500 || got[0].AvgLatencyNs < 166.6 || got[0].AvgLatencyNs > 166.7 {
		t.Fatalf("fallback counters wrong: %+v", got[0])
	}
	if _, ok := snap.DirsOther(); ok {
		t.Fatal("fallback has no remainder row")
	}
	if got := AggregateFilesByDir(nil); len(got) != 0 {
		t.Fatalf("nil input must give no rows, got %+v", got)
	}
}

func TestWithDirsOverridesTheFallbackAndCopiesRows(t *testing.T) {
	rows := []DirSnapshot{{Dir: "/x", Accesses: 3}}
	snap := NewSnapshot(nil, nil, nil, nil, []FileSnapshot{{Path: "/y/a", Accesses: 9}}, nil, HistogramSnapshot{}, HistogramSnapshot{}).
		WithDirs(rows, DirSnapshot{Folded: 2, Accesses: 4})
	rows[0].Dir = "mutated"

	if got := snap.Dirs(); len(got) != 1 || got[0].Dir != "/x" {
		t.Fatalf("WithDirs must win over grouping files and copy its input: %+v", got)
	}
	if other, ok := snap.DirsOther(); !ok || other.Folded != 2 || other.Accesses != 4 {
		t.Fatalf("remainder lost: %+v %v", other, ok)
	}
	// An engine-style snapshot with no directories stays empty.
	empty := NewSnapshot(nil, nil, nil, nil, []FileSnapshot{{Path: "/y/a", Accesses: 9}}, nil, HistogramSnapshot{}, HistogramSnapshot{}).
		WithDirs(nil, DirSnapshot{})
	if len(empty.Dirs()) != 0 {
		t.Fatalf("explicitly empty dirs must not fall back to files: %+v", empty.Dirs())
	}
}

func TestFileSketchExactBelowKAndBoundedAbove(t *testing.T) {
	s := newFileSketch(64)
	for i := uint64(0); i < 40; i++ {
		s.Add(i * 0x9E3779B97F4A7C15)
		s.Add(i * 0x9E3779B97F4A7C15) // re-adding is idempotent
	}
	if got := s.Estimate(); got != 40 {
		t.Fatalf("Estimate below k = %d, want exactly 40", got)
	}

	big := newFileSketch(256)
	for i := uint64(1); i <= 20000; i++ {
		big.Add(i * 0x9E3779B97F4A7C15)
	}
	if len(big.hashes) != 256 {
		t.Fatalf("sketch holds %d hashes, want k=256", len(big.hashes))
	}
	if got := big.Estimate(); got < 15000 || got > 25000 {
		t.Fatalf("Estimate = %d, want about 20000", got)
	}
}

// BenchmarkDirRankerAdd measures the per-event cost the directory ranker
// adds to Engine.Ingest under the engine lock: a hot mix of repeated files
// across a few hundred directories.
func BenchmarkDirRankerAdd(b *testing.B) {
	r := newDirRankerWithConfig(DefaultTopN)
	pairs := make([]*event.Pair, 4096)
	for i := range pairs {
		pairs[i] = newFilePair(fmt.Sprintf("/d%d/f%d", i%300, i), 10, 1, types.READ_CLASSIFIED)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Add(pairs[i%len(pairs)])
	}
}
