package flamegraph

// insertTriePath follows or creates nodes for frames and adds value at the leaf.
func insertTriePath(root *trieNode, frames []string, value uint64) {
	node := root
	for _, frame := range frames {
		if node.childMap == nil {
			node.childMap = make(map[string]*trieNode)
		}
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
