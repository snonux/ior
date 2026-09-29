package flamegraph

import (
	"cmp"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// referenceSnapshot is the former full-walk snapshot algorithm, kept as the
// oracle for the prune-before-build snapshotBuilder: it re-sums every subtree
// from the nodes' own values, materialises every child and only then prunes,
// and rebuilds fallback children with forceKeep. The two must agree exactly.
func referenceSnapshot(node *trieNode, depth int, rootTotal uint64, forceKeep bool) (*SnapshotNode, uint64) {
	total, heightTotal := referenceTotals(node)
	if !forceKeep && depth > 0 && fractionBelow(total, rootTotal, liveTrieMinFraction) {
		return nil, total
	}
	children := slices.Clone(node.children)
	slices.SortFunc(children, func(a, b *trieNode) int { return cmp.Compare(a.name, b.name) })
	snaps := make([]*SnapshotNode, len(children))
	totals := make([]uint64, len(children))
	visible := 0
	for i, child := range children {
		snaps[i], totals[i] = referenceSnapshot(child, depth+1, rootTotal, false)
		if snaps[i] != nil {
			visible++
		}
	}
	if visible == 0 && depth <= liveTrieVisibleChildrenFallbackMaxDepth {
		order := make([]int, 0, len(children))
		for i := range children {
			if totals[i] > 0 {
				order = append(order, i)
			}
		}
		slices.SortFunc(order, func(a, b int) int {
			if totals[a] != totals[b] {
				return cmp.Compare(totals[b], totals[a])
			}
			return cmp.Compare(children[a].name, children[b].name)
		})
		for _, i := range order[:min(len(order), liveTrieMinVisibleChildrenWhenPruned)] {
			snaps[i], _ = referenceSnapshot(children[i], depth+1, rootTotal, true)
		}
	}
	out := &SnapshotNode{Name: node.name, Value: node.value, Total: total, HeightTotal: heightTotal}
	for _, snap := range snaps {
		if snap != nil {
			out.Children = append(out.Children, snap)
		}
	}
	return out, total
}

func referenceTotals(node *trieNode) (uint64, uint64) {
	total, heightTotal := node.value, node.heightValue
	for _, child := range node.children {
		childTotal, childHeight := referenceTotals(child)
		total += childTotal
		heightTotal += childHeight
	}
	return total, heightTotal
}

func TestLiveTrieSnapshotMatchesFullWalkReference(t *testing.T) {
	tests := []struct {
		name    string
		records int
		fanout  int
		comms   int
		dirs    int
		skew    bool
		// zero records every event with a zero count, so nothing is pruned.
		zero bool
		// forced reports whether the fallback must have kept nodes below
		// the fraction, so the case cannot silently stop exercising it.
		forced bool
	}{
		{name: "narrow", records: 200, fanout: 3, comms: 7, dirs: 13},
		{name: "tiny root children trigger the root fallback", records: 20000, fanout: 4000, comms: 4000, dirs: 3, forced: true},
		{name: "tiny depth-one children trigger their fallback", records: 20000, fanout: 4000, comms: 2, dirs: 4000, forced: true},
		{name: "tiny depth-two children get no fallback", records: 5000, fanout: 4000, comms: 7, dirs: 13},
		{name: "skewed mix of visible and pruned", records: 20000, fanout: 600, comms: 7, dirs: 13, skew: true},
		{name: "empty", records: 0, fanout: 1, comms: 1, dirs: 1},
		{name: "all-zero totals keep every node", records: 300, fanout: 100, comms: 3, dirs: 4, zero: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rng := rand.New(rand.NewSource(int64(tc.records + tc.fanout)))
			lt := NewLiveTrie([]string{"comm", "path"}, "count", "bytes")
			for i := 0; i < tc.records; i++ {
				n := rng.Intn(tc.fanout)
				if tc.skew && rng.Intn(4) == 0 {
					n %= 5
				}
				count := uint64(1 + rng.Intn(3))
				if tc.zero {
					count = 0
				}
				lt.AddRecord(IterRecord{
					Comm: fmt.Sprintf("c%d", n%tc.comms),
					Path: fmt.Sprintf("/d%d/f%d", n%tc.dirs, n),
					Cnt:  Counter{Count: count, Bytes: uint64(rng.Intn(100))},
				})
			}
			got, _ := lt.SnapshotTree()
			rootTotal, _ := referenceTotals(lt.root)
			want, _ := referenceSnapshot(lt.root, 0, rootTotal, false)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("snapshot differs from the full-walk reference\ngot  %s\nwant %s", dumpSnapshot(got), dumpSnapshot(want))
			}
			if forced := countForcedNodes(got, got.Total) > 0; forced != tc.forced {
				t.Fatalf("fallback-kept nodes present = %v, want %v", forced, tc.forced)
			}
		})
	}
}

func TestInsertTriePathMaintainsSubtreeTotalsIncrementally(t *testing.T) {
	root := &trieNode{}
	paths := [][]string{{"a", "b"}, {"a", "c"}, {"a"}, {}, {"d", "e", "f"}, {"a", "b"}}
	created := 0
	for i, frames := range paths {
		created += insertLiveTriePath(root, frames, uint64(i+1), uint64(10*(i+1)))
	}
	if got, want := created, 6; got != want {
		t.Fatalf("created nodes = %d, want %d", got, want)
	}
	var check func(node *trieNode)
	check = func(node *trieNode) {
		total, heightTotal := referenceTotals(node)
		if node.total != total || node.heightTotal != heightTotal {
			t.Fatalf("node %q totals = %d/%d, want %d/%d", node.name, node.total, node.heightTotal, total, heightTotal)
		}
		for _, child := range node.children {
			check(child)
		}
		assertTopChildren(t, node)
	}
	check(root)
}

func TestInsertTriePathSkipsTopChildrenUpkeep(t *testing.T) {
	// The batch trie never reads topChildren, so its insert must not pay
	// for them.
	tr := newTrie()
	tr.add([]string{"a", "b"}, 3)
	if len(tr.root.topChildren) != 0 || len(findChild(tr.root, "a").topChildren) != 0 {
		t.Fatal("batch trie insert maintained topChildren")
	}
	if got, want := tr.root.total, uint64(3); got != want {
		t.Fatalf("root total = %d, want %d", got, want)
	}
}

func TestPromoteTopChildTracksLargestChildrenUnderRandomInserts(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	root := &trieNode{}
	for i := 0; i < 5000; i++ {
		// Zero values exercise the "empty children never enter" rule.
		frame := fmt.Sprintf("c%02d", rng.Intn(40))
		insertLiveTriePath(root, []string{frame}, uint64(rng.Intn(4)), 0)
		assertTopChildren(t, root)
	}
	if got := len(root.topChildren); got != trieTopChildren {
		t.Fatalf("topChildren len = %d, want %d", got, trieTopChildren)
	}
}

// assertTopChildren checks node.topChildren against a from-scratch selection.
func assertTopChildren(t *testing.T, node *trieNode) {
	t.Helper()
	want := appendLargestChildren(nil, node.children, node.bucket, trieTopChildren)
	if !slices.Equal(node.topChildren, want) {
		t.Fatalf("node %q topChildren = %v, want %v", node.name, trieNodeNames(node.topChildren), trieNodeNames(want))
	}
}

func trieNodeNames(nodes []*trieNode) []string {
	names := make([]string, len(nodes))
	for i, node := range nodes {
		names[i] = node.name
	}
	return names
}

func TestAppendLargestChildren(t *testing.T) {
	nodes := func(spec ...string) []*trieNode {
		out := make([]*trieNode, 0, len(spec))
		for _, s := range spec {
			var name string
			var total uint64
			_, _ = fmt.Sscanf(s, "%1s%d", &name, &total)
			out = append(out, &trieNode{name: name, total: total})
		}
		return out
	}
	tests := []struct {
		name     string
		children []*trieNode
		// skip is the 0-based index of the child passed as skip, or 0 for
		// none (the tables never skip their first child).
		skip  int
		limit int
		want  string
	}{
		{name: "none", children: nil, limit: 3, want: ""},
		{name: "zero totals are skipped", children: nodes("a0", "b0"), limit: 3, want: ""},
		{name: "fewer than limit", children: nodes("a1", "b2"), limit: 3, want: "b,a"},
		{name: "largest first then by name", children: nodes("d1", "c5", "a2", "b2", "e9", "f1"), limit: 3, want: "e,c,a"},
		{name: "ties at the cut keep the smaller names", children: nodes("z1", "y1", "x1", "w1"), limit: 2, want: "w,x"},
		{name: "zero limit", children: nodes("a1"), limit: 0, want: ""},
		{name: "skip is never selected", children: nodes("a1", "b9", "c2"), skip: 1, limit: 3, want: "c,a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix := []*trieNode{{name: "keep"}}
			var skip *trieNode
			if tc.skip > 0 {
				skip = tc.children[tc.skip]
			}
			got := appendLargestChildren(prefix, tc.children, skip, tc.limit)
			if got[0].name != "keep" {
				t.Fatal("existing dst entries were overwritten")
			}
			names := make([]string, 0, len(got)-1)
			for _, node := range got[1:] {
				names = append(names, node.name)
			}
			if joined := strings.Join(names, ","); joined != tc.want {
				t.Fatalf("got %q, want %q", joined, tc.want)
			}
		})
	}
}

// countForcedNodes counts the snapshot nodes below the root that the fraction
// rule alone would have pruned, i.e. the ones only the fallback keeps.
func countForcedNodes(node *SnapshotNode, rootTotal uint64) int {
	count := 0
	for _, child := range node.Children {
		if fractionBelow(child.Total, rootTotal, liveTrieMinFraction) {
			count++
		}
		count += countForcedNodes(child, rootTotal)
	}
	return count
}

func dumpSnapshot(node *SnapshotNode) string {
	if node == nil {
		return "<nil>"
	}
	var sb strings.Builder
	var walk func(node *SnapshotNode, depth int)
	walk = func(node *SnapshotNode, depth int) {
		fmt.Fprintf(&sb, "%s%s v=%d t=%d ht=%d\n", strings.Repeat("  ", depth), node.Name, node.Value, node.Total, node.HeightTotal)
		for _, child := range node.Children {
			walk(child, depth+1)
		}
	}
	walk(node, 0)
	return sb.String()
}
