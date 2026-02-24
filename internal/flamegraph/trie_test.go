package flamegraph

import "testing"

func findChild(node *trieNode, name string) *trieNode {
	for _, child := range node.children {
		if child.name == name {
			return child
		}
	}
	return nil
}

func TestTrieSingleStack(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a", "b", "c"}, 10)
	tr.computeTotals()

	a := findChild(tr.root, "a")
	if a == nil {
		t.Fatal("expected node a")
	}
	b := findChild(a, "b")
	if b == nil {
		t.Fatal("expected node b")
	}
	c := findChild(b, "c")
	if c == nil {
		t.Fatal("expected node c")
	}

	if tr.root.total != 10 || a.total != 10 || b.total != 10 || c.total != 10 {
		t.Fatalf("expected total propagation to be 10, got root=%d a=%d b=%d c=%d",
			tr.root.total, a.total, b.total, c.total)
	}
}

func TestTrieMultipleStacks(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a", "b"}, 5)
	tr.add([]string{"a", "c"}, 3)
	tr.computeTotals()

	a := findChild(tr.root, "a")
	if a == nil {
		t.Fatal("expected node a")
	}
	if a.total != 8 {
		t.Fatalf("expected a.total=8, got %d", a.total)
	}
}

func TestTrieOverlappingPaths(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a", "b"}, 5)
	tr.add([]string{"a", "b"}, 3)
	tr.computeTotals()

	a := findChild(tr.root, "a")
	if a == nil {
		t.Fatal("expected node a")
	}
	b := findChild(a, "b")
	if b == nil {
		t.Fatal("expected node b")
	}

	if b.value != 8 {
		t.Fatalf("expected merged leaf value=8, got %d", b.value)
	}
	if tr.root.total != 8 {
		t.Fatalf("expected root total=8, got %d", tr.root.total)
	}
}

func TestTrieEmpty(t *testing.T) {
	tr := newTrie()
	tr.computeTotals()

	if tr.root.total != 0 {
		t.Fatalf("expected root.total=0, got %d", tr.root.total)
	}
}

func TestTrieDeterministicChildOrder(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"root", "z"}, 1)
	tr.add([]string{"root", "a"}, 1)
	tr.add([]string{"root", "m"}, 1)
	tr.computeTotals()

	root := findChild(tr.root, "root")
	if root == nil {
		t.Fatal("expected node root")
	}
	if len(root.children) != 3 {
		t.Fatalf("expected 3 children, got %d", len(root.children))
	}

	if root.children[0].name != "a" || root.children[1].name != "m" || root.children[2].name != "z" {
		t.Fatalf("expected alphabetical child order [a m z], got [%s %s %s]",
			root.children[0].name, root.children[1].name, root.children[2].name)
	}
}

func TestTrieMaxDepth(t *testing.T) {
	tr := newTrie()
	tr.add([]string{"a"}, 1)
	tr.add([]string{"a", "b", "c", "d"}, 1)
	tr.computeTotals()

	if tr.maxDepth != 4 {
		t.Fatalf("expected maxDepth=4, got %d", tr.maxDepth)
	}
}

func TestTrieEmptyFramesAccumulateAtRoot(t *testing.T) {
	tr := newTrie()
	tr.add(nil, 2)
	tr.add([]string{}, 3)
	tr.computeTotals()

	if tr.root.value != 5 {
		t.Fatalf("expected root.value=5, got %d", tr.root.value)
	}
	if tr.root.total != 5 {
		t.Fatalf("expected root.total=5, got %d", tr.root.total)
	}
}
