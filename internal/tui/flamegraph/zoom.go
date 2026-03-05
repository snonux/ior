package flamegraph

import "strings"

func findNodeByPath(root *snapshotNode, path string) *snapshotNode {
	if root == nil {
		return nil
	}
	if path == "" {
		return root
	}
	parts := strings.Split(path, pathSeparator)
	if len(parts) == 0 {
		return root
	}
	rootName := frameName(root.Name, 0)
	if parts[0] == rootName {
		parts = parts[1:]
	}

	node := root
	for _, part := range parts {
		next := findChildByName(node, part)
		if next == nil {
			return nil
		}
		node = next
	}
	return node
}

func findChildByName(node *snapshotNode, name string) *snapshotNode {
	for _, child := range node.Children {
		if child.Name == name || frameName(child.Name, 1) == name {
			return child
		}
	}
	return nil
}
