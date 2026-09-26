package flamegraph

import (
	"maps"
	"testing"

	tea "charm.land/bubbletea/v2"
)

// jumpMatchFrames is a small tree: root -> {a -> a1, b}.
func jumpMatchFrames() []tuiFrame {
	sep := pathSeparator
	return []tuiFrame{
		{Name: "root", Depth: 0, Path: "root"},
		{Name: "a", Depth: 1, Path: "root" + sep + "a"},
		{Name: "a1", Depth: 2, Path: "root" + sep + "a" + sep + "a1"},
		{Name: "b", Depth: 1, Path: "root" + sep + "b"},
	}
}

func TestJumpMatchNoMatchesKeepsSelectionAndSubtree(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)
	subtree := subtreeSetUsingAncestry(frames, 1, ancestry, nil)
	want := maps.Clone(subtree)

	for _, matches := range []map[int]bool{nil, {}} {
		for _, dir := range []int{1, -1} {
			gotIdx, gotSet := jumpMatch(frames, matches, ancestry, 1, dir, subtree)
			if gotIdx != 1 {
				t.Fatalf("dir=%d: expected selection to stay at 1, got %d", dir, gotIdx)
			}
			if gotSet == nil {
				t.Fatalf("dir=%d: subtree highlight dropped to nil with no matches", dir)
			}
			if !maps.Equal(gotSet, want) {
				t.Fatalf("dir=%d: subtree changed with no matches: got %v want %v", dir, gotSet, want)
			}
		}
	}
}

func TestJumpMatchRefillsSubtreeForNewSelection(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)
	// Current selection is "a" (subtree root, a, a1); the only match is "b".
	subtree := subtreeSetUsingAncestry(frames, 1, ancestry, nil)

	gotIdx, gotSet := jumpMatch(frames, map[int]bool{3: true}, ancestry, 1, 1, subtree)
	if gotIdx != 3 {
		t.Fatalf("expected jump to match 3, got %d", gotIdx)
	}
	want := map[int]bool{0: true, 3: true}
	if !maps.Equal(gotSet, want) {
		t.Fatalf("expected subtree %v for new selection, got %v (stale entries must be cleared)", want, gotSet)
	}
}

func TestJumpMatchAllocatesWhenCallerSetIsNil(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)

	gotIdx, gotSet := jumpMatch(frames, map[int]bool{2: true}, ancestry, 0, -1, nil)
	if gotIdx != 2 {
		t.Fatalf("expected jump to match 2, got %d", gotIdx)
	}
	want := map[int]bool{0: true, 1: true, 2: true}
	if !maps.Equal(gotSet, want) {
		t.Fatalf("expected subtree %v, got %v", want, gotSet)
	}
}

// TestNextPrevMatchKeysWithoutMatchesKeepSubtreeHighlight drives the real key
// path: select a frame, commit a query with no matches, then press n and N.
// The selection does not move, so the subtree highlight must survive.
func TestNextPrevMatchKeysWithoutMatchesKeepSubtreeHighlight(t *testing.T) {
	m := NewModel(nil)
	m.frames = jumpMatchFrames()

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: 'k', Text: "k"})
	if m.selectedIdx != 1 {
		t.Fatalf("expected 'k' to select child frame 1, got %d", m.selectedIdx)
	}
	want := map[int]bool{0: true, 1: true, 2: true}
	if !maps.Equal(m.subtreeSet, want) {
		t.Fatalf("precondition: expected subtree %v, got %v", want, m.subtreeSet)
	}

	// n/N with no search at all.
	for _, key := range []string{"n", "N"} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: rune(key[0]), Text: key})
		if m.selectedIdx != 1 {
			t.Fatalf("%q without search moved selection to %d", key, m.selectedIdx)
		}
		if !maps.Equal(m.subtreeSet, want) {
			t.Fatalf("%q without search dropped subtree highlight: got %v want %v", key, m.subtreeSet, want)
		}
	}

	// n/N after committing a query that matches nothing.
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	for _, r := range "zzz" {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.matchIndices) != 0 {
		t.Fatalf("precondition: expected no matches for 'zzz', got %d", len(m.matchIndices))
	}
	for _, key := range []string{"n", "N"} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: rune(key[0]), Text: key})
		if m.selectedIdx != 1 {
			t.Fatalf("%q with no matches moved selection to %d", key, m.selectedIdx)
		}
		if !maps.Equal(m.subtreeSet, want) {
			t.Fatalf("%q with no matches dropped subtree highlight: got %v want %v", key, m.subtreeSet, want)
		}
	}
}
