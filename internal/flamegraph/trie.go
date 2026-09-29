package flamegraph

import (
	"cmp"
	"slices"
)

type trieNode struct {
	name        string
	value       uint64
	heightValue uint64
	total       uint64
	heightTotal uint64
	children    []*trieNode
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
	insertTriePath(t.root, frames, value, value)
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
