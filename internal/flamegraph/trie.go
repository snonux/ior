package flamegraph

import "sort"

type trieNode struct {
	name     string
	value    uint64
	total    uint64
	children []*trieNode
	childMap map[string]*trieNode
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
	node := t.root
	for _, frame := range frames {
		child, ok := node.childMap[frame]
		if !ok {
			child = &trieNode{
				name:     frame,
				childMap: make(map[string]*trieNode),
			}
			node.children = append(node.children, child)
			node.childMap[frame] = child
		}
		node = child
	}
	node.value += value
}

func (t *trie) computeTotals() {
	t.maxDepth = 0
	var walk func(node *trieNode, depth int) uint64
	walk = func(node *trieNode, depth int) uint64 {
		if depth > t.maxDepth {
			t.maxDepth = depth
		}

		sort.Slice(node.children, func(i, j int) bool {
			return node.children[i].name < node.children[j].name
		})

		total := node.value
		for _, child := range node.children {
			total += walk(child, depth+1)
		}
		node.total = total
		node.childMap = nil
		return total
	}

	walk(t.root, 0)
}
