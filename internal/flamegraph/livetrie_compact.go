package flamegraph

const (
	// liveTrieMaxNodes caps how many nodes (root excluded) a LiveTrie keeps.
	// Without a cap every distinct frame path of a long high-cardinality
	// session (e.g. comm,tracepoint,path) stays in memory until a manual
	// reset. At roughly 100-200 bytes per node the cap bounds the trie to
	// tens of megabytes while staying far above what a snapshot can show:
	// the 0.1% pruning rule admits at most 1000 visible nodes per depth.
	liveTrieMaxNodes = 1 << 19

	// liveTrieOtherFrame names the bucket that compaction folds small
	// sibling subtrees into. It is a leaf whose own value carries their
	// totals, so every ancestor's total is unchanged by compaction.
	liveTrieOtherFrame = "[other]"

	// liveTrieCompactFractionStep multiplies the compaction threshold on
	// each pass that did not yet bring the trie down to half its cap.
	liveTrieCompactFractionStep = 4
)

// compactLocked shrinks the trie to at most half of lt.maxNodes by folding
// small sibling subtrees into per-parent liveTrieOtherFrame buckets.
//
// The first pass uses liveTrieMinFraction, the snapshot pruning rule, so it
// only removes subtrees no snapshot would show except as a fallback child.
// If that is not enough the threshold grows by liveTrieCompactFractionStep
// per pass; once it exceeds the whole root total every child of the root is
// folded, so the loop always terminates. Stopping at half the cap, not at the
// cap, makes compactions at least maxNodes/2 node insertions apart, so the
// full walk they need stays amortised O(1) per insert.
//
// Folding is lossy only in attribution: totals are conserved, but a frame
// that was folded and later reappears starts a fresh node, with its early
// history counted in its parent's bucket.
func (lt *LiveTrie) compactLocked() {
	target := lt.maxNodes / 2
	for fraction := liveTrieMinFraction; lt.nodeCount > target; fraction *= liveTrieCompactFractionStep {
		rootTotal := lt.root.total
		small := func(total uint64) bool {
			if fraction > 1 {
				return true
			}
			return fractionBelow(total, rootTotal, fraction)
		}
		lt.nodeCount -= foldSmallChildren(lt.root, small)
		if fraction > 1 {
			return
		}
	}
}

// foldSmallChildren folds every child of node whose subtree total is small
// into node's liveTrieOtherFrame bucket, recurses into the kept children and
// returns the net number of nodes removed. An existing bucket is reused and
// never folded into itself.
func foldSmallChildren(node *trieNode, small func(uint64) bool) int {
	bucket := node.childMap[liveTrieOtherFrame]
	removed := 0
	var foldedTotal, foldedHeight uint64
	kept := node.children[:0]
	for _, child := range node.children {
		if child == bucket || !small(child.total) {
			kept = append(kept, child)
			continue
		}
		removed += countTrieNodes(child)
		foldedTotal += child.total
		foldedHeight += child.heightTotal
		delete(node.childMap, child.name)
	}
	// Clear the dropped tail so the folded subtrees can be collected.
	clear(node.children[len(kept):])
	node.children = kept

	if removed > 0 {
		if bucket == nil {
			bucket = &trieNode{name: liveTrieOtherFrame}
			node.children = append(node.children, bucket)
			node.childMap[liveTrieOtherFrame] = bucket
			removed--
		}
		bucket.value += foldedTotal
		bucket.heightValue += foldedHeight
		bucket.total += foldedTotal
		bucket.heightTotal += foldedHeight
	}
	// The folded children may have been in topChildren and the bucket grew,
	// so rebuild the list from the kept children.
	node.topChildren = appendLargestChildren(node.topChildren[:0], node.children, trieTopChildren)

	for _, child := range node.children {
		removed += foldSmallChildren(child, small)
	}
	return removed
}

// countTrieNodes returns the number of nodes in the subtree rooted at node,
// node included.
func countTrieNodes(node *trieNode) int {
	count := 1
	for _, child := range node.children {
		count += countTrieNodes(child)
	}
	return count
}
