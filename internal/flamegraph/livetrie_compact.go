package flamegraph

const (
	// liveTrieMaxNodes caps how many nodes (root excluded) a LiveTrie keeps.
	// Without a cap every distinct frame path of a long high-cardinality
	// session (e.g. comm,tracepoint,path) stays in memory until a manual
	// reset. A node costs about 210-290 bytes of heap in a path-heavy trie
	// (node, name, child map and slice entries; measured), so 2^18 nodes
	// bound the trie to roughly 55-75MB, still far more than a snapshot can
	// show: the 0.1% pruning rule admits at most 1000 visible nodes per depth.
	liveTrieMaxNodes = 1 << 18

	// liveTrieOtherFrame names the bucket that compaction folds small
	// sibling subtrees into. It is a leaf whose own value carries their
	// totals, so every ancestor's total is unchanged by compaction. It is
	// identified by trieNode.bucket, not by name, so a real frame with this
	// name stays a separate node.
	liveTrieOtherFrame = "[other]"
)

// compactMark is a node's scratch state during one compactLocked call.
type compactMark uint8

const (
	markNone compactMark = iota
	// markShown: the current snapshot shows the node.
	markShown
	// markFold: the node is selected to be folded into its parent's bucket.
	markFold
)

// foldCandidate is a node that compaction may fold. The ranking keys are
// copied out of the node so ranking a few hundred thousand candidates does
// not chase a pointer per comparison; order (the walk position) breaks the
// remaining ties, making the ranking a reproducible strict total order.
// Names are deliberately not compared: with hundreds of thousands of
// equally ranked leaves, string comparisons made ranking several times
// slower.
type foldCandidate struct {
	node  *trieNode
	rate  float64
	depth int32
	order int32
}

// rateClock turns a node's all-time total into the event rate compaction
// ranks by: its share of the root events that arrived since the node was
// born (trieNode.birthRootTotal). window, the root growth since the previous
// compaction (the whole history before the first one), is added to every
// node's age, so a node born moments ago is judged over at least one
// compaction interval instead of looking hot because of one event.
type rateClock struct {
	rootTotal uint64
	window    float64
}

// rate returns node's rate, see rateClock.
func (c rateClock) rate(node *trieNode) float64 {
	return float64(node.total) / (float64(c.rootTotal-node.birthRootTotal) + c.window)
}

// compactLocked shrinks the trie towards half of lt.maxNodes by folding the
// least significant subtrees into per-parent liveTrieOtherFrame buckets.
//
// Candidates are ranked by rate (see rateClock), lowest first, then deepest
// first, then in walk order, and only as many as needed are folded. Ranking
// by all-time totals instead let frames that were busy long ago and then
// went idle fill the kept half forever, while a steady frame that appeared
// later was folded, restarted from zero and folded again. By rate, both the
// one-off noise that fills the trie and old idle frames decay below a frame
// that keeps receiving events. A node's rank is the maximum of its own rate
// and its children's ranks, so a child never outranks its parent (ties go to
// the deeper node): every selected set is closed under descendants and whole
// subtrees fold at once. Reported totals stay exact; rates only rank.
//
// Nodes the current snapshot shows, including the depth <= 1 fallback
// children, are spared: compaction does not change the view except for the
// new buckets. Only if folding every other node is not enough (a trie that
// shows almost everything, e.g. one whose totals are all zero) is the view
// itself compacted, still lowest-ranked and deepest first so the top levels
// stay.
//
// Totals are conserved; what is lost is the attribution of folded frames. A
// folded frame that reappears starts a fresh node.
//
// Compaction runs inside the AddRecord that crossed the cap, under the write
// lock. In ior that is the event-loop goroutine (the TUI print callback calls
// Ingest), so the pause stops event consumption and can back up the BPF ring
// buffer, dropping events under a high rate of unique paths. The pause is a
// few memory-bound walks, expected O(n) for n nodes: about 40ms at the
// default cap (BenchmarkLiveTrieCompaction; over 100ms on a heavily
// oversubscribed dev box), plus GC of the folded nodes afterwards. It runs at
// most once per maxNodes/4 new nodes; a lower cap shortens it
// proportionally.
func (lt *LiveTrie) compactLocked() {
	shown := markShownNodes(lt.root)
	defer setMarks(shown, markNone)

	clock := rateClock{
		rootTotal: lt.root.total,
		window:    float64(max(lt.root.total-lt.lastCompactRootTotal, 1)),
	}
	lt.lastCompactRootTotal = lt.root.total
	for _, includeShown := range []bool{false, true} {
		lt.foldRanked(collectFoldCandidates(lt.root, lt.nodeCount, clock, includeShown))
		if lt.nodeCount <= lt.compactedEnough() {
			return
		}
	}
}

// compactedEnough is the node count at which compaction may stop. It aims at
// maxNodes/2, but each new bucket costs a node and lone leaves are not folded
// (foldableAt), so it settles for maxNodes*3/4: that still leaves at least
// maxNodes/4 inserts before the next compaction.
func (lt *LiveTrie) compactedEnough() int {
	return lt.maxNodes * 3 / 4
}

// foldRanked folds growing sets of the lowest-ranked candidates until the
// trie is compacted enough or the candidates are exhausted. Each set grows
// by the remaining excess over maxNodes/2, which is at least maxNodes/4, so
// there are at most five passes. selectLowestRanked only partitions, never
// fully sorts: which candidates fold depends on the ranking, their order
// among each other does not.
func (lt *LiveTrie) foldRanked(candidates []foldCandidate) {
	target := lt.maxNodes / 2
	k := 0
	for {
		prev := k
		k = min(k+lt.nodeCount-target, len(candidates))
		selectLowestRanked(candidates[prev:], k-prev)
		for _, candidate := range candidates[:k] {
			candidate.node.mark = markFold
		}
		lt.nodeCount -= foldMarkedChildren(lt.root)
		for _, candidate := range candidates[:k] {
			// Unfolded (skipped) candidates must not stay marked; folded
			// ones are detached and marking them no longer matters.
			candidate.node.mark = markNone
		}
		if lt.nodeCount <= lt.compactedEnough() || k == len(candidates) {
			return
		}
	}
}

// markShownNodes marks every node the current snapshot shows as markShown
// and returns them, so compaction can spare them.
func markShownNodes(root *trieNode) []*trieNode {
	builder := snapshotBuilder{minFraction: liveTrieMinFraction, rootTotal: root.total}
	var shown []*trieNode
	var walk func(node *trieNode, depth int)
	walk = func(node *trieNode, depth int) {
		base := len(builder.scratch)
		builder.selectVisibleChildren(node, depth)
		for _, child := range builder.scratch[base:] {
			child.mark = markShown
			shown = append(shown, child)
			walk(child, depth+1)
		}
		builder.scratch = builder.scratch[:base]
	}
	walk(root, 0)
	return shown
}

// collectFoldCandidates returns every non-root, non-bucket node, sparing
// markShown ones unless includeShown, unordered, with its rank computed
// bottom-up (see compactLocked). nodeCount sizes the result up front;
// growing it by appending was a noticeable part of the pause.
func collectFoldCandidates(root *trieNode, nodeCount int, clock rateClock, includeShown bool) []foldCandidate {
	candidates := make([]foldCandidate, 0, nodeCount)
	// walk returns the rank of node: the maximum of its rate and its frame
	// children's ranks. A bucket is skipped; its folded mass must not keep
	// its parent alive.
	var walk func(node *trieNode, depth int) float64
	walk = func(node *trieNode, depth int) float64 {
		rank := clock.rate(node)
		for _, child := range node.children {
			if child == node.bucket {
				continue
			}
			childRank := walk(child, depth+1)
			rank = max(rank, childRank)
			// A shown node's hidden descendants are still candidates.
			if includeShown || child.mark != markShown {
				candidates = append(candidates, foldCandidate{
					node:  child,
					rate:  childRank,
					depth: int32(depth + 1),
					order: int32(len(candidates)),
				})
			}
		}
		return rank
	}
	walk(root, 0)
	return candidates
}

// foldRankLess is the fold ranking (see compactLocked): lower rank first,
// then deeper, then earlier in the walk. It is a strict total order because
// order is unique.
func foldRankLess(left, right foldCandidate) bool {
	if left.rate != right.rate {
		return left.rate < right.rate
	}
	if left.depth != right.depth {
		return left.depth > right.depth
	}
	return left.order < right.order
}

// selectLowestRanked reorders candidates so that its first k entries are the
// k lowest-ranked ones, in expected linear time (quickselect with a
// median-of-three pivot). A full sort was the largest part of the pause.
func selectLowestRanked(candidates []foldCandidate, k int) {
	lo, hi := 0, len(candidates)
	for hi-lo > 1 && k > lo && k < hi {
		pivot := partitionFoldCandidates(candidates[lo:hi]) + lo
		switch {
		case pivot == k:
			return
		case pivot < k:
			lo = pivot + 1
		default:
			hi = pivot
		}
	}
}

// partitionFoldCandidates partitions c around a median-of-three pivot and
// returns the pivot's final index: everything before it ranks lower,
// everything after it higher.
func partitionFoldCandidates(c []foldCandidate) int {
	last, mid := len(c)-1, len(c)/2
	if foldRankLess(c[mid], c[0]) {
		c[mid], c[0] = c[0], c[mid]
	}
	if foldRankLess(c[last], c[0]) {
		c[last], c[0] = c[0], c[last]
	}
	if foldRankLess(c[mid], c[last]) {
		c[mid], c[last] = c[last], c[mid]
	}
	// c[last] now holds the median of the three.
	store := 0
	for i := 0; i < last; i++ {
		if foldRankLess(c[i], c[last]) {
			c[i], c[store] = c[store], c[i]
			store++
		}
	}
	c[store], c[last] = c[last], c[store]
	return store
}

// foldMarkedChildren folds, below node, every markFold child that foldableAt
// allows into its parent's bucket and returns the net number of nodes
// removed.
func foldMarkedChildren(node *trieNode) int {
	removed := 0
	if foldableAt(node) {
		removed = foldMarked(node)
	}
	for _, child := range node.children {
		removed += foldMarkedChildren(child)
	}
	return removed
}

// foldableAt reports whether folding node's markFold children removes at
// least one node net. Folding a lone leaf into a new bucket would only
// replace its name with liveTrieOtherFrame.
func foldableAt(node *trieNode) bool {
	marked := 0
	var only *trieNode
	for _, child := range node.children {
		if child.mark == markFold {
			marked++
			only = child
		}
	}
	if marked == 0 {
		return false
	}
	return marked > 1 || node.bucket != nil || len(only.children) > 0
}

// foldMarked moves node's markFold children into its bucket (creating it if
// needed), rebuilds its topChildren if a member was folded and returns the
// net nodes removed.
func foldMarked(node *trieNode) int {
	// Compaction usually folds most children of a node; then building a
	// fresh, right-sized map from the few kept ones is much cheaper than
	// deleting the many folded ones, and lets the old map's memory go.
	rebuildMap := 2*countMarked(node.children) > len(node.children)
	// Only folding a member of topChildren invalidates it (the bucket is
	// never a member); checking its few entries first skips most rebuilds.
	rebuildTop := countMarked(node.topChildren) > 0
	removed := 0
	var foldedTotal, foldedHeight uint64
	kept := node.children[:0]
	for _, child := range node.children {
		if child.mark != markFold {
			kept = append(kept, child)
			continue
		}
		removed += countTrieNodes(child)
		foldedTotal += child.total
		foldedHeight += child.heightTotal
		if !rebuildMap {
			delete(node.childMap, child.name)
		}
	}
	// Clear the dropped tail so the folded subtrees can be collected.
	clear(node.children[len(kept):])
	node.children = kept
	if rebuildMap {
		node.childMap = make(map[string]*trieNode, len(kept))
		for _, child := range kept {
			if child != node.bucket {
				node.childMap[child.name] = child
			}
		}
	}

	if node.bucket == nil {
		node.bucket = &trieNode{name: liveTrieOtherFrame}
		node.children = append(node.children, node.bucket)
		removed--
	}
	node.bucket.value += foldedTotal
	node.bucket.heightValue += foldedHeight
	node.bucket.total += foldedTotal
	node.bucket.heightTotal += foldedHeight
	if rebuildTop {
		node.topChildren = appendLargestChildren(node.topChildren[:0], node.children, node.bucket, trieTopChildren)
	}
	return removed
}

// countMarked returns how many of nodes are marked markFold.
func countMarked(nodes []*trieNode) int {
	marked := 0
	for _, node := range nodes {
		if node.mark == markFold {
			marked++
		}
	}
	return marked
}

// setMarks sets the compaction mark of every node in nodes.
func setMarks(nodes []*trieNode, mark compactMark) {
	for _, node := range nodes {
		node.mark = mark
	}
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
