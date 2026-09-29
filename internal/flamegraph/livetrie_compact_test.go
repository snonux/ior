package flamegraph

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
)

// countBelowRoot returns the real number of nodes below the root, the value
// LiveTrie.nodeCount must track.
func countBelowRoot(lt *LiveTrie) int {
	return countTrieNodes(lt.root) - 1
}

// assertNodeCount checks the cap and that nodeCount matches the real count.
func assertNodeCount(t *testing.T, lt *LiveTrie, step int) {
	t.Helper()
	if lt.nodeCount > lt.maxNodes {
		t.Fatalf("after %d records nodeCount = %d, above cap %d", step, lt.nodeCount, lt.maxNodes)
	}
	if got := countBelowRoot(lt); got != lt.nodeCount {
		t.Fatalf("after %d records nodeCount = %d, real node count %d", step, lt.nodeCount, got)
	}
}

func TestLiveTrieCompactionBoundsNodesAndConservesTotals(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "bytes")
	lt.maxNodes = 64
	var wantTotal, wantHeight uint64
	for i := 0; i < 5000; i++ {
		record := IterRecord{Comm: "svc", Path: fmt.Sprintf("/rare/f%05d", i), Cnt: Counter{Count: 1, Bytes: 2}}
		if i%2 == 0 {
			// A hot file that must survive every compaction.
			record.Path = "/hot/file"
		}
		lt.AddRecord(record)
		wantTotal += record.Cnt.Count
		wantHeight += record.Cnt.Bytes
		assertNodeCount(t, lt, i+1)
	}

	snapshot, _ := lt.SnapshotTree()
	if snapshot.Total != wantTotal || snapshot.HeightTotal != wantHeight {
		t.Fatalf("root totals = %d/%d, want %d/%d", snapshot.Total, snapshot.HeightTotal, wantTotal, wantHeight)
	}
	hot := findSnapshotPath(t, snapshot, "svc", "/hot", "/file")
	if got, want := hot.Total, uint64(2500); got != want {
		t.Fatalf("hot file total = %d, want %d (compaction must not fold a large subtree)", got, want)
	}
	rare := findSnapshotPath(t, snapshot, "svc", "/rare")
	other := findSnapshotChild(rare, liveTrieOtherFrame)
	if other == nil {
		t.Fatalf("expected folded rare files under %q, got children %d", liveTrieOtherFrame, len(rare.Children))
	}
	if other.Value != other.Total || len(other.Children) != 0 {
		t.Fatalf("bucket must be a leaf carrying its value: %+v", other)
	}
	assertTotalsConsistent(t, lt.root)
}

// TestLiveTrieCompactionKeepsAFrameThatAppearsLate is the multi-cycle
// regression: one-off noise forces dozens of compactions while a steady 2%
// frame, which first appears long after the noise started, keeps receiving
// events. Folding everything below 0.1% of the running root total on every
// cycle kept restarting that frame from zero, so it never became visible.
func TestLiveTrieCompactionKeepsAFrameThatAppearsLate(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	lt.maxNodes = 2000
	noise := 0
	addNoise := func() {
		lt.AddRecord(IterRecord{Comm: "noise", Path: fmt.Sprintf("/n/%07d", noise), Cnt: Counter{Count: 1}})
		noise++
	}
	for i := 0; i < 20000; i++ {
		addNoise()
	}
	const steadyEvents = 40000
	late := uint64(0)
	for i := 0; i < steadyEvents; i++ {
		if i%50 == 0 {
			lt.AddRecord(IterRecord{Comm: "late", Path: "/steady", Cnt: Counter{Count: 1}})
			late++
			continue
		}
		addNoise()
		assertNodeCount(t, lt, i)
	}

	snapshot, _ := lt.SnapshotTree()
	steady := findSnapshotPath(t, snapshot, "late", "/steady")
	if steady.Total != late {
		t.Fatalf("late frame total = %d, want all %d of its events", steady.Total, late)
	}
	if got, want := snapshot.Total, uint64(noise)+late; got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	assertTotalsConsistent(t, lt.root)
}

// TestLiveTrieCompactionKeepsALateFrameOverOldIdleFrames: more than half the
// cap is taken by frames that were busy early and then went idle. Ranking by
// all-time totals kept them forever and starved a steady frame that appeared
// later: folded each cycle with a handful of events, it never grew past them.
// Ranking by rate lets the idle frames decay below it.
func TestLiveTrieCompactionKeepsALateFrameOverOldIdleFrames(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	lt.maxNodes = 2000
	const oldFrames = 1100 // > maxNodes/2
	for i := 0; i < oldFrames; i++ {
		lt.AddRecord(IterRecord{Comm: "old", Path: fmt.Sprintf("/o/%04d", i), Cnt: Counter{Count: 100}})
	}
	const events = 300_000
	late := uint64(0)
	for i := 0; i < events; i++ {
		if i%500 == 0 { // 0.2% of the new events
			lt.AddRecord(IterRecord{Comm: "late", Path: "/steady", Cnt: Counter{Count: 1}})
			late++
			continue
		}
		lt.AddRecord(IterRecord{Comm: "noise", Path: fmt.Sprintf("/n/%07d", i), Cnt: Counter{Count: 1}})
		if lt.nodeCount > lt.maxNodes {
			t.Fatalf("nodeCount = %d, above cap %d", lt.nodeCount, lt.maxNodes)
		}
	}

	// The first compaction may fold the frame while it has a single event or
	// two: at that point the old frames legitimately outrank it. After that
	// it must keep everything.
	snapshot, _ := lt.SnapshotTree()
	steady := findSnapshotPath(t, snapshot, "late", "/steady")
	if steady.Total+5 < late {
		t.Fatalf("late frame total = %d of its %d events: it kept being folded", steady.Total, late)
	}
	if got, want := snapshot.Total, uint64(oldFrames*100+events); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	assertTotalsConsistent(t, lt.root)
}

func TestLiveTrieCompactionDoesNotOvershoot(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	lt.maxNodes = 1000
	// A dominant path hides every file below, so none is spared as shown.
	lt.AddRecord(IterRecord{Comm: "svc", Path: "/hot", Cnt: Counter{Count: 1_000_000}})
	for i := 0; lt.nodeCount < lt.maxNodes; i++ {
		lt.AddRecord(IterRecord{Comm: "svc", Path: fmt.Sprintf("/d%02d/f%05d", i%40, i), Cnt: Counter{Count: uint64(1 + i%7)}})
	}
	lt.AddRecord(IterRecord{Comm: "svc", Path: "/d00/trigger", Cnt: Counter{Count: 1}})
	// One compaction folds the excess over half the cap, plus at most one
	// new bucket per directory, and not far past it.
	if got, target := lt.nodeCount, lt.maxNodes/2; got > target+40 || got < target-40 {
		t.Fatalf("nodeCount after compaction = %d, want within 40 of %d", got, target)
	}
}

// TestLiveTrieCompactionPreservesTheView compacts tries whose snapshots use
// the root and depth-one fallbacks and checks that, with buckets left out,
// the view equals the full-walk reference of the trie before compacting.
func TestLiveTrieCompactionPreservesTheView(t *testing.T) {
	tests := []struct {
		name        string
		comms, dirs int
		skew        bool
	}{
		{name: "root fallback", comms: 3000, dirs: 2},
		{name: "depth-one fallback", comms: 2, dirs: 3000},
		{name: "visible mix", comms: 5, dirs: 40, skew: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
			lt.maxNodes = 0 // build without compacting
			rng := rand.New(rand.NewSource(7))
			for i := 0; i < 20000; i++ {
				n := rng.Intn(20000)
				if tc.skew && rng.Intn(3) == 0 {
					n %= 3
				}
				lt.AddRecord(IterRecord{
					Comm: fmt.Sprintf("c%d", n%tc.comms),
					Path: fmt.Sprintf("/d%d/f%d", n%tc.dirs, n),
					Cnt:  Counter{Count: uint64(1 + rng.Intn(3))},
				})
			}
			want, _ := referenceSnapshot(lt.root, 0, lt.root.total, false)
			before := lt.nodeCount

			// Leave just enough room for the shown nodes plus one bucket
			// under each of them and the root (the most sparing them can
			// create), so the fallback's tiny shown nodes are among the
			// smallest candidates and only sparing them keeps the view.
			shown := markShownNodes(lt.root)
			setMarks(shown, markNone)
			lt.maxNodes = (4*(2*len(shown)+1))/3 + 1
			lt.compactLocked()
			if lt.nodeCount > lt.compactedEnough() {
				t.Fatalf("nodeCount %d -> %d, want at most %d", before, lt.nodeCount, lt.compactedEnough())
			}
			t.Logf("nodes %d -> %d, shown %d", before, lt.nodeCount, len(shown))
			assertTotalsConsistent(t, lt.root)

			got := buildSnapshot(lt.root, 0, liveTrieMinFraction, lt.root.total)
			if !reflect.DeepEqual(withoutBuckets(got), want) {
				t.Fatalf("view changed by compaction\ngot  %s\nwant %s", dumpSnapshot(withoutBuckets(got)), dumpSnapshot(want))
			}
		})
	}
}

func TestLiveTrieCompactionWithZeroTotalsKeepsTheTopLevels(t *testing.T) {
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	lt.maxNodes = 60
	for i := 0; i < 400; i++ {
		lt.AddRecord(IterRecord{Comm: fmt.Sprintf("c%d", i%4), Path: fmt.Sprintf("/d%d/f%d", i%3, i), Cnt: Counter{}})
		assertNodeCount(t, lt, i+1)
	}
	if lt.root.bucket != nil {
		t.Fatal("zero-total compaction folded root children instead of the deepest nodes")
	}
	for i := 0; i < 4; i++ {
		if lt.root.childMap[fmt.Sprintf("c%d", i)] == nil {
			t.Fatalf("root child c%d was folded", i)
		}
	}
}

func TestLiveTrieBucketIsNotARealOtherFrame(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "")
	lt.maxNodes = 40
	lt.AddRecord(IterRecord{Comm: liveTrieOtherFrame, Cnt: Counter{Count: 1000}})
	for i := 0; i < 100; i++ {
		lt.AddRecord(IterRecord{Comm: fmt.Sprintf("noise%03d", i), Cnt: Counter{Count: 1}})
	}
	bucket := lt.root.bucket
	real := lt.root.childMap[liveTrieOtherFrame]
	if bucket == nil || real == nil || bucket == real {
		t.Fatalf("want a bucket separate from the real frame, got bucket=%p real=%p", bucket, real)
	}
	bucketTotal := bucket.total
	lt.AddRecord(IterRecord{Comm: liveTrieOtherFrame, Cnt: Counter{Count: 5}})
	if real.total != 1005 || bucket.total != bucketTotal {
		t.Fatalf("insert reached the bucket: real=%d bucket=%d (was %d)", real.total, bucket.total, bucketTotal)
	}
	assertTotalsConsistent(t, lt.root)
}

func TestFoldableAtRequiresANetSaving(t *testing.T) {
	leaf := func(name string, mark compactMark) *trieNode { return &trieNode{name: name, mark: mark} }
	tests := []struct {
		name string
		node *trieNode
		want bool
	}{
		{name: "nothing marked", node: &trieNode{children: []*trieNode{leaf("a", markNone)}}, want: false},
		{name: "lone marked leaf", node: &trieNode{children: []*trieNode{leaf("a", markFold), leaf("b", markNone)}}, want: false},
		{name: "two marked leaves", node: &trieNode{children: []*trieNode{leaf("a", markFold), leaf("b", markFold)}}, want: true},
		{name: "lone marked subtree", node: &trieNode{children: []*trieNode{{name: "a", mark: markFold, children: []*trieNode{leaf("x", markFold)}}}}, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := foldableAt(tc.node); got != tc.want {
				t.Fatalf("foldableAt = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("lone marked leaf with an existing bucket", func(t *testing.T) {
		bucket := leaf(liveTrieOtherFrame, markNone)
		node := &trieNode{children: []*trieNode{leaf("a", markFold), bucket}, bucket: bucket}
		if !foldableAt(node) {
			t.Fatal("foldableAt = false, want true")
		}
	})
}

func TestSelectLowestRankedMatchesASort(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for _, size := range []int{0, 1, 2, 3, 10, 257, 5000} {
		candidates := make([]foldCandidate, size)
		for i := range candidates {
			// Few distinct ranks and depths, so the later keys decide.
			candidates[i] = foldCandidate{rate: float64(rng.Intn(4)), depth: int32(rng.Intn(3)), order: int32(i)}
		}
		sorted := slices.Clone(candidates)
		slices.SortFunc(sorted, func(left, right foldCandidate) int {
			switch {
			case foldRankLess(left, right):
				return -1
			case foldRankLess(right, left):
				return 1
			}
			return 0
		})
		for _, k := range []int{0, 1, size / 3, size / 2, size - 1, size} {
			if k < 0 || k > size {
				continue
			}
			got := slices.Clone(candidates)
			selectLowestRanked(got, k)
			lowest := slices.Clone(got[:k])
			slices.SortFunc(lowest, func(left, right foldCandidate) int { return int(left.order - right.order) })
			want := slices.Clone(sorted[:k])
			slices.SortFunc(want, func(left, right foldCandidate) int { return int(left.order - right.order) })
			if !slices.Equal(lowest, want) {
				t.Fatalf("size %d k %d: selected set differs from the %d lowest-ranked", size, k, k)
			}
		}
	}
}

func TestLiveTrieCompactionDisabledBelowTwoNodes(t *testing.T) {
	for _, maxNodes := range []int{-1, 0, 1} {
		t.Run(fmt.Sprint(maxNodes), func(t *testing.T) {
			lt := NewLiveTrie([]string{"comm"}, "count", "")
			lt.maxNodes = maxNodes
			for i := 0; i < 10; i++ {
				lt.AddRecord(IterRecord{Comm: fmt.Sprintf("c%d", i), Cnt: Counter{Count: 1}})
			}
			if got, want := lt.nodeCount, 10; got != want {
				t.Fatalf("nodeCount = %d, want %d (no compaction)", got, want)
			}
		})
	}
}

func TestLiveTrieResetClearsNodeCount(t *testing.T) {
	lt := NewLiveTrie([]string{"comm"}, "count", "")
	lt.AddRecord(IterRecord{Comm: "a", Cnt: Counter{Count: 1}})
	lt.Reset()
	if lt.nodeCount != 0 {
		t.Fatalf("nodeCount = %d after reset, want 0", lt.nodeCount)
	}
	if got := lt.maxNodes; got != liveTrieMaxNodes {
		t.Fatalf("maxNodes = %d, want default %d", got, liveTrieMaxNodes)
	}
}

// withoutBuckets returns a copy of the snapshot without "[other]" nodes.
func withoutBuckets(node *SnapshotNode) *SnapshotNode {
	out := *node
	out.Children = nil
	for _, child := range node.Children {
		if child.Name != liveTrieOtherFrame {
			out.Children = append(out.Children, withoutBuckets(child))
		}
	}
	return &out
}

// assertTotalsConsistent checks that every cached subtree total still equals
// the sum of the node's own value and its children's totals, that every
// topChildren list is still exact and that no compaction mark is left over.
func assertTotalsConsistent(t *testing.T, node *trieNode) {
	t.Helper()
	total, heightTotal := referenceTotals(node)
	if node.total != total || node.heightTotal != heightTotal {
		t.Fatalf("node %q totals = %d/%d, want %d/%d", node.name, node.total, node.heightTotal, total, heightTotal)
	}
	if node.mark != markNone {
		t.Fatalf("node %q left with compaction mark %d", node.name, node.mark)
	}
	assertTopChildren(t, node)
	if node.bucket != nil && !slices.Contains(node.children, node.bucket) {
		t.Fatalf("node %q bucket is not among its children", node.name)
	}
	for _, child := range node.children {
		assertTotalsConsistent(t, child)
	}
}
