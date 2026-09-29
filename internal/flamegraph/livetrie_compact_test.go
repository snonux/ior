package flamegraph

import (
	"fmt"
	"slices"
	"testing"
)

// countBelowRoot returns the real number of nodes below the root, the value
// LiveTrie.nodeCount must track.
func countBelowRoot(lt *LiveTrie) int {
	return countTrieNodes(lt.root) - 1
}

func TestLiveTrieCompactionBoundsNodesAndConservesTotals(t *testing.T) {
	const maxNodes = 64
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "bytes")
	lt.maxNodes = maxNodes
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

		if lt.nodeCount > maxNodes {
			t.Fatalf("after %d records nodeCount = %d, above cap %d", i+1, lt.nodeCount, maxNodes)
		}
		if got := countBelowRoot(lt); got != lt.nodeCount {
			t.Fatalf("after %d records nodeCount = %d, real node count %d", i+1, lt.nodeCount, got)
		}
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

func TestLiveTrieCompactionFoldsEverythingWhenNoSubtreeIsSmall(t *testing.T) {
	// Equal-sized branches: at the first pass each root child holds 1/5 of
	// the total, far above 0.1%, so only the growing threshold can shrink it.
	const maxNodes = 8
	lt := NewLiveTrie([]string{"comm", "path"}, "count", "")
	lt.maxNodes = maxNodes
	for i := 0; i < 40; i++ {
		lt.AddRecord(IterRecord{Comm: fmt.Sprintf("c%d", i%5), Path: fmt.Sprintf("/f%d", i), Cnt: Counter{Count: 1}})
		if lt.nodeCount > maxNodes {
			t.Fatalf("nodeCount = %d, above cap %d", lt.nodeCount, maxNodes)
		}
		if got := countBelowRoot(lt); got != lt.nodeCount {
			t.Fatalf("nodeCount = %d, real node count %d", lt.nodeCount, got)
		}
	}
	if got, want := lt.root.total, uint64(40); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
	assertTotalsConsistent(t, lt.root)
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

func TestFoldSmallChildrenReusesExistingBucket(t *testing.T) {
	root := &trieNode{}
	insertTriePath(root, []string{liveTrieOtherFrame}, 5, 5)
	insertTriePath(root, []string{"big"}, 100, 100)
	insertTriePath(root, []string{"small", "leaf"}, 1, 1)

	removed := foldSmallChildren(root, func(total uint64) bool { return total < 10 })
	if got, want := removed, 2; got != want {
		t.Fatalf("removed = %d, want %d (small and its leaf, bucket reused)", got, want)
	}
	bucket := findChild(root, liveTrieOtherFrame)
	if bucket == nil || bucket.total != 6 || bucket.value != 6 {
		t.Fatalf("bucket = %+v, want value and total 6", bucket)
	}
	if findChild(root, "small") != nil || root.childMap["small"] != nil {
		t.Fatal("small subtree should be folded out of children and childMap")
	}
	if got := trieNodeNames(root.topChildren); !slices.Equal(got, []string{"big", liveTrieOtherFrame}) {
		t.Fatalf("topChildren = %v, want [big %s]", got, liveTrieOtherFrame)
	}
	assertTotalsConsistent(t, root)
}

// assertTotalsConsistent checks that every cached subtree total still equals
// the sum of the node's own value and its children's totals, and that every
// topChildren list is still exact.
func assertTotalsConsistent(t *testing.T, node *trieNode) {
	t.Helper()
	total, heightTotal := referenceTotals(node)
	if node.total != total || node.heightTotal != heightTotal {
		t.Fatalf("node %q totals = %d/%d, want %d/%d", node.name, node.total, node.heightTotal, total, heightTotal)
	}
	assertTopChildren(t, node)
	for _, child := range node.children {
		assertTotalsConsistent(t, child)
	}
}
