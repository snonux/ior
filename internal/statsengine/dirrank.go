package statsengine

import (
	"cmp"
	"hash/maphash"
	"slices"

	"ior/internal/event"
	"ior/internal/globalfilter"
)

// NoDirGroup is the Dir of the row collecting every file name without a
// separator: relative names such as "a.log", and non-path names such as
// "socket:[123]" or "pipe:[456]". It matches filepath.Dir's answer for those
// names. "./a" lands here too (its literal directory text is "."), so the
// group mixes names that share no path prefix; the dashboard therefore cannot
// turn it into a filter.
const NoDirGroup = "."

// DirOf returns the directory-group key of a file path: its literal
// directory text (globalfilter.LiteralDir - the text before the last
// separator, "/" for a top-level entry), or NoDirGroup when there is no
// separator. Unlike filepath.Dir it does not Clean: a directory row turns
// into the directory-children filter ^dir/* (globalfilter.DirPattern), which
// the matcher defines by the same LiteralDir, so the filter selects exactly
// the files the row counts - none of a subdirectory's (those have their own
// rows) and none outside. With filepath.Dir, "./src/main.go" grouped under
// "src", "//usr/lib/x" under "/usr/lib" and "a/../b/c" under "b", and Enter
// on those rows selected none of the files they counted.
func DirOf(path string) string {
	if dir, ok := globalfilter.LiteralDir(path); ok {
		return dir
	}
	return NoDirGroup
}

const (
	// dirRankMaxSeenFactor scales topN into the number of directories the
	// ranker tracks before it compacts (the same guard the file ranker uses).
	dirRankMaxSeenFactor = 32

	// dirFileSketchSize is K of the per-directory distinct-file sketch (see
	// fileSketch): exact up to K-1 files, about 1/sqrt(K-2) = 6% standard
	// error beyond. It costs at most 8*K bytes per tracked directory.
	dirFileSketchSize = 256
)

// dirTotals are the counters that add up across files and directories: a
// directory's counters are the sum of its files', and the remainder row is
// the sum of the directories that did not make the top-N.
type dirTotals struct {
	accesses     uint64
	bytesRead    uint64
	bytesWritten uint64
	totalLatency uint64
	maxLatency   uint64
	files        uint64 // distinct files (estimated past dirFileSketchSize)
}

func (t *dirTotals) add(o dirTotals) {
	t.accesses += o.accesses
	t.bytesRead += o.bytesRead
	t.bytesWritten += o.bytesWritten
	t.totalLatency += o.totalLatency
	t.maxLatency = max(t.maxLatency, o.maxLatency)
	t.files += o.files
}

// dirStats is one tracked directory: its running counters and the sketch
// that counts its distinct files without keeping their names.
type dirStats struct {
	dir string
	dirTotals
	sketch fileSketch
}

// dirSnapshotInput is the copy of one tracked directory taken under the
// engine lock; files is the sketch's estimate at capture time.
type dirSnapshotInput struct {
	dir string
	dirTotals
}

// dirSnapshotInputs is everything the snapshot builder needs from the
// ranker: the tracked directories plus the folded counters of the ones that
// compaction dropped.
type dirSnapshotInputs struct {
	dirs        []dirSnapshotInput
	evicted     dirTotals
	evictedDirs uint64
}

// dirRanker aggregates every ranked file pair into its directory, so the
// Files tab's directory view covers ALL traffic rather than the directories
// of the top-N files: a directory of 10,000 files read once each has no file
// in the file ranker's top-N, yet dominates the directory ranking.
//
// Memory is bounded like fileRanker's: once more than maxSeen directories are
// tracked it keeps the topN by accesses and folds the counters of the rest
// into evicted, so the total (top rows + remainder) stays exact even though
// an evicted directory that reappears restarts its own row from zero.
type dirRanker struct {
	topN        int
	maxSeen     int
	seed        maphash.Seed
	byDir       map[string]*dirStats
	evicted     dirTotals
	evictedDirs uint64
}

func newDirRankerWithConfig(topN int) *dirRanker {
	if topN <= 0 {
		topN = fileRankTopNDefault
	}
	return newDirRankerWithLimits(topN, topN*dirRankMaxSeenFactor)
}

func newDirRankerWithLimits(topN, maxSeen int) *dirRanker {
	if topN <= 0 {
		topN = fileRankTopNDefault
	}
	maxSeen = max(maxSeen, topN)
	return &dirRanker{
		topN:    topN,
		maxSeen: maxSeen,
		seed:    maphash.MakeSeed(),
		byDir:   make(map[string]*dirStats),
	}
}

// Add folds one pair into its file's directory. Pairs without a rankable
// path (see rankablePath) are ignored, exactly as the file ranker ignores
// them, so both views count the same events.
func (r *dirRanker) Add(pair *event.Pair) {
	if r == nil || pair == nil {
		return
	}
	path, ok := rankablePath(pair)
	if !ok {
		return
	}

	dir := DirOf(path)
	stats := r.byDir[dir]
	if stats == nil {
		stats = &dirStats{dir: dir, sketch: newFileSketch(dirFileSketchSize)}
		r.byDir[dir] = stats
	}

	stats.accesses++
	stats.totalLatency += pair.Duration
	stats.maxLatency = max(stats.maxLatency, pair.Duration)
	read, written := pairFileBytes(pair)
	stats.bytesRead += read
	stats.bytesWritten += written
	stats.sketch.Add(maphash.String(r.seed, path))

	r.compactIfNeeded()
}

// compactIfNeeded keeps the topN directories once cardinality crosses the
// guard and folds the rest into the evicted remainder.
func (r *dirRanker) compactIfNeeded() {
	if len(r.byDir) <= r.maxSeen {
		return
	}
	all := make([]*dirStats, 0, len(r.byDir))
	for _, stats := range r.byDir {
		all = append(all, stats)
	}
	slices.SortFunc(all, compareDirStats)

	kept := make(map[string]*dirStats, r.topN)
	for i, stats := range all {
		if i < r.topN {
			kept[stats.dir] = stats
			continue
		}
		totals := stats.dirTotals
		totals.files = stats.sketch.Estimate()
		r.evicted.add(totals)
		r.evictedDirs++
	}
	r.byDir = kept
}

// compareDirStats orders directories best first: most accesses, then by name.
func compareDirStats(a, b *dirStats) int {
	if a.accesses != b.accesses {
		return cmp.Compare(b.accesses, a.accesses)
	}
	return cmp.Compare(a.dir, b.dir)
}

// snapshotInputs copies the tracked state; it runs under the engine lock, so
// it only copies (at most maxSeen small structs) and leaves ranking to
// buildDirSnapshots.
func (r *dirRanker) snapshotInputs() dirSnapshotInputs {
	if r == nil {
		return dirSnapshotInputs{}
	}
	in := dirSnapshotInputs{
		dirs:        make([]dirSnapshotInput, 0, len(r.byDir)),
		evicted:     r.evicted,
		evictedDirs: r.evictedDirs,
	}
	for _, stats := range r.byDir {
		totals := stats.dirTotals
		totals.files = stats.sketch.Estimate()
		in.dirs = append(in.dirs, dirSnapshotInput{dir: stats.dir, dirTotals: totals})
	}
	return in
}

// buildDirSnapshots ranks the captured directories and returns the topN rows
// (accesses descending, then directory) plus the remainder row summing every
// other directory, including the compacted-away ones. The remainder has
// Folded == 0 when nothing fell outside the topN. The error return is
// reserved for future validation, like buildFileSnapshots.
func buildDirSnapshots(in dirSnapshotInputs, topN int) ([]DirSnapshot, DirSnapshot, error) {
	if topN <= 0 {
		topN = fileRankTopNDefault
	}
	sorted := slices.Clone(in.dirs)
	slices.SortFunc(sorted, func(a, b dirSnapshotInput) int {
		if a.accesses != b.accesses {
			return cmp.Compare(b.accesses, a.accesses)
		}
		return cmp.Compare(a.dir, b.dir)
	})

	rest := in.evicted
	folded := in.evictedDirs
	rows := make([]DirSnapshot, 0, min(topN, len(sorted)))
	for i, d := range sorted {
		if i < topN {
			rows = append(rows, d.toSnapshot())
			continue
		}
		rest.add(d.dirTotals)
		folded++
	}

	var other DirSnapshot
	if folded > 0 {
		other = DirSnapshot{Folded: folded}
		other.applyTotals(rest)
	}
	return rows, other, nil
}

func (d dirSnapshotInput) toSnapshot() DirSnapshot {
	s := DirSnapshot{Dir: d.dir}
	s.applyTotals(d.dirTotals)
	return s
}

func (s *DirSnapshot) applyTotals(t dirTotals) {
	s.Accesses = t.accesses
	s.BytesRead = t.bytesRead
	s.BytesWritten = t.bytesWritten
	s.MaxLatencyNs = t.maxLatency
	s.TotalLatencyNs = t.totalLatency
	s.FileCount = t.files
	s.AvgLatencyNs = 0
	if t.accesses > 0 {
		s.AvgLatencyNs = float64(t.totalLatency) / float64(t.accesses)
	}
}

// AggregateFilesByDir groups files by DirOf and sums each group's counters
// into one DirSnapshot, ordered by accesses (desc), then dir. It is the
// fallback Snapshot.Dirs uses for a snapshot built without engine-provided
// directory rows (NewSnapshot in tests and exporters): it can only see the
// files it is given, so on a live engine snapshot - which carries the top-N
// files only - the engine's own directory ranking is the one to use.
func AggregateFilesByDir(files []FileSnapshot) []DirSnapshot {
	if len(files) == 0 {
		return nil
	}

	dirs := make(map[string]*dirTotals, len(files))
	for _, f := range files {
		dir := DirOf(f.Path)
		t := dirs[dir]
		if t == nil {
			t = &dirTotals{}
			dirs[dir] = t
		}
		t.add(dirTotals{
			accesses:     f.Accesses,
			bytesRead:    f.BytesRead,
			bytesWritten: f.BytesWritten,
			totalLatency: f.TotalLatencyNs,
			maxLatency:   f.MaxLatencyNs,
			files:        1,
		})
	}

	out := make([]DirSnapshot, 0, len(dirs))
	for dir, t := range dirs {
		s := DirSnapshot{Dir: dir}
		s.applyTotals(*t)
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b DirSnapshot) int {
		if a.Accesses != b.Accesses {
			return cmp.Compare(b.Accesses, a.Accesses)
		}
		return cmp.Compare(a.Dir, b.Dir)
	})
	return out
}
