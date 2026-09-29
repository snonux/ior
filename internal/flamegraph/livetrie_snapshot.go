package flamegraph

import (
	"cmp"
	"slices"
)

// snapshotBuilder turns the visible part of a LiveTrie into a SnapshotNode
// tree. It runs under the trie's read lock, so its cost is what ingestion
// waits for; it is therefore proportional to the visible nodes, never to the
// whole recorded history:
//
//   - Pruning is decided before recursing, from the subtree totals and
//     topChildren lists that insertTriePath maintains on every insert. A
//     pruned subtree is neither walked nor materialised, and the pruned tail
//     of a wide fan-out is usually not even scanned (selectVisibleChildren).
//   - A node's snapshot Total/HeightTotal are its full subtree totals, pruned
//     descendants included, so the renderer can still see how much of the
//     band the omitted children occupy.
//
// Pruning compares each node's subtree total against the running root total
// (liveTrieMinFraction), so the same node can be visible in an early snapshot
// and pruned from a later one. When that would hide every child of the root
// or of a depth-one node, the liveTrieMinVisibleChildrenWhenPruned largest
// non-empty children are kept anyway, so a view of many equally tiny
// branches does not collapse to a bare root.
type snapshotBuilder struct {
	minFraction float64
	rootTotal   uint64
	// scratch is a stack of candidate children shared by the whole walk: each
	// level appends its kept children above its parent's and truncates them
	// when done, so selecting children allocates only while the stack grows.
	scratch []*trieNode
}

// buildSnapshot returns the snapshot of node (at depth) and its visible
// descendants.
func buildSnapshot(node *trieNode, depth int, minFraction float64, rootTotal uint64) *SnapshotNode {
	builder := snapshotBuilder{minFraction: minFraction, rootTotal: rootTotal}
	return builder.build(node, depth)
}

func (b *snapshotBuilder) build(node *trieNode, depth int) *SnapshotNode {
	snapshot := &SnapshotNode{
		Name:        node.name,
		Value:       node.value,
		Total:       node.total,
		HeightTotal: node.heightTotal,
	}

	base := len(b.scratch)
	b.selectVisibleChildren(node, depth)
	kept := b.scratch[base:]
	if len(kept) == 0 {
		return snapshot
	}
	// Name order keeps the layout stable between refreshes regardless of the
	// order in which frames were first seen.
	slices.SortFunc(kept, func(left, right *trieNode) int {
		return cmp.Compare(left.name, right.name)
	})

	// Deeper levels push their candidates above kept, never into it. If such
	// an append grows b.scratch into a new array, kept still refers to the
	// old one, whose contents nothing changes any more.
	snapshot.Children = make([]*SnapshotNode, len(kept))
	for i, child := range kept {
		snapshot.Children[i] = b.build(child, depth+1)
	}
	b.scratch = b.scratch[:base]
	return snapshot
}

// selectVisibleChildren appends to b.scratch the children of node that pass
// the fraction rule, or the fallback set when none does at a shallow depth.
//
// node.topChildren (largest first) usually spares the scan of all children:
//   - if even the largest child is pruned, none is visible;
//   - if the list is full and its last entry is pruned, or it is not full
//     (then every other child is empty), only list members can be visible.
//
// Only a node with at least trieTopChildren visible children scans them all.
// That scan is allocation-free and the node cap bounds its length.
func (b *snapshotBuilder) selectVisibleChildren(node *trieNode, depth int) {
	top := node.topChildren
	var largest uint64
	if len(top) > 0 {
		largest = top[0].total
	}
	if b.pruned(largest) {
		b.fallback(node, depth)
		return
	}

	// b.rootTotal > 0 guards the empty-trie case, in which nothing is pruned
	// and empty children, never listed in topChildren, must be kept too.
	candidates := node.children
	if b.rootTotal > 0 && (len(top) < trieTopChildren || b.pruned(top[len(top)-1].total)) {
		candidates = top
	}
	for _, child := range candidates {
		if !b.pruned(child.total) {
			b.scratch = append(b.scratch, child)
		}
	}
}

// fallback appends the largest non-empty children of a shallow node none of
// whose children passed the fraction rule. insertTriePath keeps exactly that
// set in topChildren, so this costs nothing even for a huge fan-out.
func (b *snapshotBuilder) fallback(node *trieNode, depth int) {
	if depth > liveTrieVisibleChildrenFallbackMaxDepth {
		return
	}
	b.scratch = append(b.scratch, node.topChildren...)
}

// pruned reports whether a subtree total falls below the minimum fraction of
// the running root total. An empty trie prunes nothing.
func (b *snapshotBuilder) pruned(total uint64) bool {
	return fractionBelow(total, b.rootTotal, b.minFraction)
}

// fractionBelow reports whether total/rootTotal < minFraction. It is the one
// definition of "small" shared by snapshot pruning and compaction, so the
// first compaction pass only ever removes nodes a snapshot would not show.
func fractionBelow(total, rootTotal uint64, minFraction float64) bool {
	return rootTotal > 0 && float64(total)/float64(rootTotal) < minFraction
}
