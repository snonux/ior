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
	m.anim.frames = jumpMatchFrames()

	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: 'k', Text: "k"})
	if m.sel.selectedIdx != 1 {
		t.Fatalf("expected 'k' to select child frame 1, got %d", m.sel.selectedIdx)
	}
	want := map[int]bool{0: true, 1: true, 2: true}
	if !maps.Equal(m.sel.subtreeSet, want) {
		t.Fatalf("precondition: expected subtree %v, got %v", want, m.sel.subtreeSet)
	}

	// n/N with no search at all.
	for _, key := range []string{"n", "N"} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: rune(key[0]), Text: key})
		if m.sel.selectedIdx != 1 {
			t.Fatalf("%q without search moved selection to %d", key, m.sel.selectedIdx)
		}
		if !maps.Equal(m.sel.subtreeSet, want) {
			t.Fatalf("%q without search dropped subtree highlight: got %v want %v", key, m.sel.subtreeSet, want)
		}
	}

	// n/N after committing a query that matches nothing.
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: '/', Text: "/"})
	for _, r := range "zzz" {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: r, Text: string(r)})
	}
	m = pressFlameKey(t, m, tea.KeyPressMsg{Code: tea.KeyEnter})
	if len(m.search.matchIndices) != 0 {
		t.Fatalf("precondition: expected no matches for 'zzz', got %d", len(m.search.matchIndices))
	}
	for _, key := range []string{"n", "N"} {
		m = pressFlameKey(t, m, tea.KeyPressMsg{Code: rune(key[0]), Text: key})
		if m.sel.selectedIdx != 1 {
			t.Fatalf("%q with no matches moved selection to %d", key, m.sel.selectedIdx)
		}
		if !maps.Equal(m.sel.subtreeSet, want) {
			t.Fatalf("%q with no matches dropped subtree highlight: got %v want %v", key, m.sel.subtreeSet, want)
		}
	}
}

func TestSearchControllerNavigableFollowsQuery(t *testing.T) {
	frames := jumpMatchFrames() // root -> {a -> a1, b}
	ancestry := buildFrameAncestry(frames)
	sc := newSearchController(true)

	if sc.navigable() != nil {
		t.Fatal("navigable filter without a query, want nil (all frames)")
	}

	msg, dir := sc.applyQuery("  A1 ", frames, ancestry)
	if sc.query() != "a1" || dir != 1 || msg == "" {
		t.Fatalf("applyQuery: query=%q dir=%d msg=%q", sc.query(), dir, msg)
	}
	if want := map[int]bool{2: true}; !maps.Equal(sc.matches(), want) {
		t.Fatalf("matches = %v, want %v", sc.matches(), want)
	}
	nav := sc.navigable()
	if nav == nil {
		t.Fatal("navigable is nil with an active filter")
	}
	for idx, want := range map[int]bool{0: true, 1: true, 2: true, 3: false} {
		if got := nav.admits(idx); got != want {
			t.Fatalf("navigable(%d) = %t, want %t", idx, got, want)
		}
	}
	if !maps.Equal(sc.visibleSet(), map[int]bool{0: true, 1: true, 2: true}) {
		t.Fatalf("visibleSet = %v", sc.visibleSet())
	}

	if _, dir := sc.applyQuery("zzz", frames, ancestry); dir != 0 || len(sc.matches()) != 0 {
		t.Fatalf("no-match query: dir=%d matches=%v", dir, sc.matches())
	}
	if nav := sc.navigable(); nav == nil || nav.admits(0) {
		t.Fatal("a query without matches must leave nothing navigable")
	}
}

func TestSearchControllerCommitClosesInput(t *testing.T) {
	frames := jumpMatchFrames()
	sc := newSearchController(true)
	sc.open()
	if !sc.isActive() {
		t.Fatal("open did not activate search")
	}
	if _, dir := sc.commit("b", frames, buildFrameAncestry(frames)); dir != 1 {
		t.Fatalf("commit jump direction = %d, want 1", dir)
	}
	if sc.isActive() || sc.query() != "b" {
		t.Fatalf("after commit: active=%t query=%q", sc.isActive(), sc.query())
	}
}

func TestSearchControllerDiscardResults(t *testing.T) {
	frames := jumpMatchFrames()
	ancestry := buildFrameAncestry(frames)
	sc := newSearchController(true)
	sc.open()
	sc.applyQuery("a", frames, ancestry)

	sc.discardResults(false)
	if sc.query() != "a" || len(sc.matches()) != 0 || len(sc.visibleSet()) != 0 {
		t.Fatalf("discardResults(false): query=%q matches=%v visible=%v", sc.query(), sc.matches(), sc.visibleSet())
	}
	if !sc.isActive() {
		t.Fatal("discardResults must not close the search input")
	}

	sc.applyQuery("a", frames, ancestry)
	sc.discardResults(true)
	if sc.query() != "" || len(sc.matches()) != 0 || sc.navigable() != nil {
		t.Fatalf("discardResults(true): query=%q matches=%v", sc.query(), sc.matches())
	}
}
