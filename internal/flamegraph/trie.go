package flamegraph

import (
	"cmp"
	"slices"
)

// trieNode is one frame of a trie. value/heightValue are the node's own
// (self) values; total/heightTotal are its subtree sums, kept current by
// insertTriePath on every insert (and recomputed by trie.computeTotals).
// topChildren holds the trieTopChildren largest non-empty children, largest
// total first and ties by name, also maintained on every insert. It lets a
// LiveTrie snapshot handle a wide fan-out in constant time: its first entry
// bounds every child's total, and it is exactly the fallback set.
type trieNode struct {
	name        string
	value       uint64
	heightValue uint64
	total       uint64
	heightTotal uint64
	children    []*trieNode
	topChildren []*trieNode
	childMap    map[string]*trieNode
}

type trie struct {
	root     *trieNode
	maxDepth int
}

func newTrie() *trie {
	return &trie{
		root: &trieNode{
			childMap: make(map[string]*trieNode),
		},
	}
}

func (t *trie) add(frames []string, value uint64) {
	_ = insertTriePath(t.root, frames, value, value)
}

func (t *trie) computeTotals() {
	t.maxDepth = 0
	var walk func(node *trieNode, depth int) (uint64, uint64)
	walk = func(node *trieNode, depth int) (uint64, uint64) {
		if depth > t.maxDepth {
			t.maxDepth = depth
		}

		slices.SortFunc(node.children, func(a, b *trieNode) int {
			return cmp.Compare(a.name, b.name)
		})

		total := node.value
		heightTotal := node.heightValue
		for _, child := range node.children {
			childTotal, childHeightTotal := walk(child, depth+1)
			total += childTotal
			heightTotal += childHeightTotal
		}
		node.total = total
		node.heightTotal = heightTotal
		node.childMap = nil
		return total, heightTotal
	}

	walk(t.root, 0)
}
