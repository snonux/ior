package flamegraph

import (
	"cmp"
	"slices"
	"strings"
)

// trieTopChildren is how many of its largest children a node tracks. It is
// the LiveTrie snapshot fallback size, the only consumer of the list.
const trieTopChildren = liveTrieMinVisibleChildrenWhenPruned

// insertTriePath follows or creates nodes for frames, adds the values at the
// leaf and to the subtree totals of every node on the path (root included),
// and returns how many nodes it created. It is the batch trie's insert; the
// batch trie never reads topChildren, so it does not pay for their upkeep.
func insertTriePath(root *trieNode, frames []string, value, heightValue uint64) int {
	return insertPath(root, frames, value, heightValue, false)
}

// insertLiveTriePath is insertTriePath plus the per-node topChildren upkeep
// (see promoteTopChild) that LiveTrie snapshots and compaction rely on.
func insertLiveTriePath(root *trieNode, frames []string, value, heightValue uint64) int {
	return insertPath(root, frames, value, heightValue, true)
}

// insertPath implements both inserts.
//
// Keeping subtree totals current on every insert is what lets LiveTrie
// snapshots decide pruning from cached totals instead of re-summing the whole
// history under the read lock; compaction ranks nodes by them. The batch
// trie's computeTotals recomputes the same totals.
//
// A new node's name is cloned: frames can be substrings of a much longer
// record string (see appendPathFrames), and a long-lived trie node must not
// pin that whole string in memory. Child maps are created lazily, on the
// first child, because most nodes of a high-cardinality trie are leaves.
// A compaction bucket is never in childMap, so no frame, not even one named
// liveTrieOtherFrame, is ever inserted into a bucket.
func insertPath(root *trieNode, frames []string, value, heightValue uint64, trackTop bool) int {
	created := 0
	node := root
	node.total += value
	node.heightTotal += heightValue
	for _, frame := range frames {
		if node.childMap == nil {
			node.childMap = make(map[string]*trieNode)
		}
		child, ok := node.childMap[frame]
		if !ok {
			child = &trieNode{name: strings.Clone(frame)}
			node.children = append(node.children, child)
			node.childMap[frame] = child
			created++
		}
		child.total += value
		child.heightTotal += heightValue
		if trackTop {
			node.topChildren = promoteTopChild(node.topChildren, child)
		}
		node = child
	}
	node.value += value
	node.heightValue += heightValue
	return created
}

// promoteTopChild updates top, a node's list of its largest children ordered
// by compareLargestFirst, after child's total grew, and returns it.
//
// The list stays exact because totals only grow between compactions (which
// rebuild it, see appendLargestChildren): every child outside the list orders after every child in it.
// A member that grows can only move forward; a non-member that grows past
// the last member replaces it, and the evicted member still orders before
// all remaining non-members. Empty children never enter, matching the
// snapshot fallback, which ignores them; neither does a compaction bucket,
// which inserts never reach. Cost: at most trieTopChildren
// comparisons per path level.
func promoteTopChild(top []*trieNode, child *trieNode) []*trieNode {
	if child.total == 0 {
		return top
	}
	idx := slices.Index(top, child)
	if idx < 0 {
		switch {
		case len(top) < trieTopChildren:
			top = append(top, child)
		case compareLargestFirst(child, top[len(top)-1]) < 0:
			top[len(top)-1] = child
		default:
			return top
		}
		idx = len(top) - 1
	}
	for ; idx > 0 && compareLargestFirst(top[idx], top[idx-1]) < 0; idx-- {
		top[idx], top[idx-1] = top[idx-1], top[idx]
	}
	return top
}

// appendLargestChildren appends up to limit non-empty children, largest
// subtree total first and ties broken by name, to dst. It selects in one pass
// over children with an insertion-sorted window of at most limit entries, so
// a node with a huge fan-out is neither copied nor fully sorted. skip (the
// parent's compaction bucket, or nil) is never selected. Compaction uses it
// to rebuild topChildren from scratch.
func appendLargestChildren(dst, children []*trieNode, skip *trieNode, limit int) []*trieNode {
	base := len(dst)
	for _, child := range children {
		if child.total == 0 || child == skip {
			continue
		}
		window := dst[base:]
		pos, _ := slices.BinarySearchFunc(window, child, compareLargestFirst)
		if pos >= limit {
			continue
		}
		if len(window) < limit {
			dst = append(dst, nil)
			window = dst[base:]
		}
		copy(window[pos+1:], window[pos:len(window)-1])
		window[pos] = child
	}
	return dst
}

// compareLargestFirst orders nodes by descending subtree total, then by name.
func compareLargestFirst(left, right *trieNode) int {
	if left.total != right.total {
		return cmp.Compare(right.total, left.total)
	}
	return cmp.Compare(left.name, right.name)
}
