package statsengine

import (
	"cmp"
	"container/heap"
	"slices"

	"ior/internal/event"
	"ior/internal/types"
)

const fileRankTopNDefault = 20

type fileRanker struct {
	topN    int
	maxSeen int
	byPath  map[string]*fileRankStats
	topHeap fileRankHeap
}

type fileRankStats struct {
	path         string
	accesses     uint64
	bytesRead    uint64
	bytesWritten uint64
	totalLatency uint64
	maxLatency   uint64
	heapIndex    int
}

type fileSnapshotInput struct {
	path         string
	accesses     uint64
	bytesRead    uint64
	bytesWritten uint64
	totalLatency uint64
	maxLatency   uint64
}

type fileRankHeap []*fileRankStats

func newFileRanker() *fileRanker {
	return newFileRankerWithConfig(fileRankTopNDefault)
}

func newFileRankerWithConfig(topN int) *fileRanker {
	if topN <= 0 {
		topN = fileRankTopNDefault
	}
	return newFileRankerWithLimits(topN, topN*32)
}

func newFileRankerWithLimits(topN int, maxSeen int) *fileRanker {
	if topN <= 0 {
		topN = fileRankTopNDefault
	}
	if maxSeen < topN {
		maxSeen = topN
	}

	r := &fileRanker{
		topN:    topN,
		maxSeen: maxSeen,
		byPath:  make(map[string]*fileRankStats),
	}
	heap.Init(&r.topHeap)
	return r
}

func (r *fileRanker) Add(pair *event.Pair) {
	if r == nil || pair == nil || pair.File == nil {
		return
	}

	path := pair.File.Name()
	if path == "" || path == "N:file" {
		return
	}

	stats := r.byPath[path]
	if stats == nil {
		stats = &fileRankStats{path: path, heapIndex: -1}
		r.byPath[path] = stats
	}

	stats.accesses++
	stats.totalLatency += pair.Duration
	if pair.Duration > stats.maxLatency {
		stats.maxLatency = pair.Duration
	}
	r.addBytes(stats, pair)
	r.updateHeap(stats)
	r.compactIfNeeded()
}

// Snapshot returns a slice of FileSnapshots for all tracked files.
// It panics on build error, which should never happen for a valid ranker.
func (r *fileRanker) Snapshot() []FileSnapshot {
	if r == nil {
		return nil
	}

	snap, err := buildFileSnapshots(r.snapshotInputs())
	if err != nil {
		panic("buildFileSnapshots: " + err.Error())
	}
	return snap
}

func (r *fileRanker) snapshotInputs() []fileSnapshotInput {
	if r == nil {
		return nil
	}
	inputs := make([]fileSnapshotInput, 0, len(r.topHeap))
	for _, stats := range r.topHeap {
		inputs = append(inputs, fileSnapshotInput{
			path:         stats.path,
			accesses:     stats.accesses,
			bytesRead:    stats.bytesRead,
			bytesWritten: stats.bytesWritten,
			totalLatency: stats.totalLatency,
			maxLatency:   stats.maxLatency,
		})
	}
	return inputs
}

// buildFileSnapshots converts raw file ranker inputs into sorted FileSnapshot
// slices. The error return is reserved for future validation; currently this
// function always succeeds.
func buildFileSnapshots(inputs []fileSnapshotInput) ([]FileSnapshot, error) {
	out := make([]FileSnapshot, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, in.toSnapshot())
	}
	slices.SortFunc(out, func(a, b FileSnapshot) int {
		if a.Accesses != b.Accesses {
			return cmp.Compare(b.Accesses, a.Accesses)
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return out, nil
}

func (r *fileRanker) addBytes(stats *fileRankStats, pair *event.Pair) {
	retEv, ok := pair.ExitEv.(*types.RetEvent)
	if !ok {
		return
	}

	switch retEv.RetType {
	case types.READ_CLASSIFIED:
		stats.bytesRead += pair.Bytes
	case types.WRITE_CLASSIFIED:
		stats.bytesWritten += pair.Bytes
	case types.TRANSFER_CLASSIFIED:
		// Transfer syscalls move bytes in both directions from a file-centric view.
		stats.bytesRead += pair.Bytes
		stats.bytesWritten += pair.Bytes
	}
}

func (r *fileRanker) updateHeap(stats *fileRankStats) {
	if stats.heapIndex >= 0 {
		heap.Fix(&r.topHeap, stats.heapIndex)
		return
	}

	if len(r.topHeap) < r.topN {
		heap.Push(&r.topHeap, stats)
		return
	}

	worst := r.topHeap[0]
	if !betterFileRank(stats, worst) {
		return
	}

	heap.Pop(&r.topHeap)
	heap.Push(&r.topHeap, stats)
}

func (r *fileRanker) compactIfNeeded() {
	if len(r.byPath) <= r.maxSeen {
		return
	}

	// Keep only currently top-ranked paths once cardinality crosses the guard.
	kept := make(map[string]*fileRankStats, len(r.topHeap))
	for _, stats := range r.topHeap {
		kept[stats.path] = stats
	}
	r.byPath = kept
}

func (s fileSnapshotInput) toSnapshot() FileSnapshot {
	avg := 0.0
	if s.accesses > 0 {
		avg = float64(s.totalLatency) / float64(s.accesses)
	}

	return FileSnapshot{
		Path:           s.path,
		Accesses:       s.accesses,
		BytesRead:      s.bytesRead,
		BytesWritten:   s.bytesWritten,
		AvgLatencyNs:   avg,
		MaxLatencyNs:   s.maxLatency,
		TotalLatencyNs: s.totalLatency,
	}
}

func betterFileRank(a, b *fileRankStats) bool {
	if a.accesses != b.accesses {
		return a.accesses > b.accesses
	}
	return a.path < b.path
}

func (h *fileRankHeap) Len() int {
	return len(*h)
}

func (h *fileRankHeap) Less(i, j int) bool {
	// Keep the worst-ranked item at root for O(log N) eviction.
	return betterFileRank((*h)[j], (*h)[i])
}

func (h *fileRankHeap) Swap(i, j int) {
	(*h)[i], (*h)[j] = (*h)[j], (*h)[i]
	(*h)[i].heapIndex = i
	(*h)[j].heapIndex = j
}

func (h *fileRankHeap) Push(x any) {
	stats := x.(*fileRankStats)
	stats.heapIndex = len(*h)
	*h = append(*h, stats)
}

func (h *fileRankHeap) Pop() any {
	old := *h
	n := len(old)
	stats := old[n-1]
	stats.heapIndex = -1
	*h = old[:n-1]
	return stats
}
