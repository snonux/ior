package flamegraph

import (
	"maps"
	"slices"
	"strings"
	"testing"
)

// framesFromPaths builds frames whose Path joins the given semicolon-separated
// stacks with the real path separator, so tests read like folded stacks.
func framesFromPaths(stacks ...string) []tuiFrame {
	frames := make([]tuiFrame, len(stacks))
	for i, stack := range stacks {
		parts := strings.Split(stack, ";")
		frames[i] = tuiFrame{
			Name:  parts[len(parts)-1],
			Depth: len(parts) - 1,
			Path:  strings.Join(parts, pathSeparator),
		}
	}
	return frames
}

// matchIndicesByName returns the indices of frames whose Name contains query,
// mirroring SearchController.recompute's match rule.
func matchIndicesByName(frames []tuiFrame, query string) []int {
	var matches []int
	for idx, frame := range frames {
		if strings.Contains(frame.Name, query) {
			matches = append(matches, idx)
		}
	}
	return matches
}

// expectedFilterVisible is an independent path-based oracle: a frame is
// visible iff it is a match, a descendant of a match or an ancestor of a match.
func expectedFilterVisible(frames []tuiFrame, matches []int) map[int]bool {
	want := make(map[int]bool)
	for idx, frame := range frames {
		for _, m := range matches {
			mp := frames[m].Path
			if frame.Path == mp || hasPathBoundaryPrefix(frame.Path, mp) || hasPathBoundaryPrefix(mp, frame.Path) {
				want[idx] = true
				break
			}
		}
	}
	return want
}

// permutations returns every ordering of values.
func permutations(values []int) [][]int {
	if len(values) <= 1 {
		return [][]int{slices.Clone(values)}
	}
	var out [][]int
	for i := range values {
		rest := slices.Concat(values[:i], values[i+1:])
		for _, perm := range permutations(rest) {
			out = append(out, append([]int{values[i]}, perm...))
		}
	}
	return out
}

func pathsOf(frames []tuiFrame, set map[int]bool) []string {
	var paths []string
	for idx := range set {
		paths = append(paths, strings.ReplaceAll(frames[idx].Path, pathSeparator, ";"))
	}
	slices.Sort(paths)
	return paths
}

// TestMarkFilterVisibleIsIndependentOfMatchOrder feeds the matches in every
// possible order, over frame slices whose child adjacency lists come out in
// different orders, and checks each result against the path-based oracle.
// Before the fix, visiting a nested match before its enclosing match marked the
// enclosing match via the ancestor walk, and the later markSubtree of the
// enclosing match stopped at its already-marked root, hiding its other
// children (e.g. a;foo;x for the query "foo").
func TestMarkFilterVisibleIsIndependentOfMatchOrder(t *testing.T) {
	tests := []struct {
		name   string
		stacks []string
		query  string
	}{
		{
			name:   "audit repro plus a non-matching sibling",
			stacks: []string{"a", "a;foo", "a;foo;x", "a;foo;food", "a;bar"},
			query:  "foo",
		},
		{
			name: "three nested matches with siblings at every level",
			stacks: []string{
				"a", "a;foo", "a;foo;x", "a;foo;food", "a;foo;food;y",
				"a;foo;food;foody", "a;foo;food;foody;z", "a;bar", "a;bar;q", "b",
			},
			query: "foo",
		},
		{
			name: "nested and disjoint matches in separate roots",
			stacks: []string{
				"a", "a;foo", "a;foo;p", "a;foo;foo2", "a;foo;foo2;r",
				"b", "b;s", "b;s;foo3", "b;s;foo3;t", "b;u",
			},
			query: "foo",
		},
	}

	for _, tt := range tests {
		// Reversing the frames reverses every children list built by
		// buildFrameAncestry, so markSubtree pops children in the other order.
		reversed := slices.Clone(tt.stacks)
		slices.Reverse(reversed)
		frameOrders := map[string][]string{
			"forward": tt.stacks,
			"reverse": reversed,
		}
		for orderName, stacks := range frameOrders {
			t.Run(tt.name+"/"+orderName, func(t *testing.T) {
				frames := framesFromPaths(stacks...)
				ancestry := buildFrameAncestry(frames)
				matches := matchIndicesByName(frames, tt.query)
				if len(matches) < 2 {
					t.Fatalf("fixture needs nested matches, got %d", len(matches))
				}
				want := expectedFilterVisible(frames, matches)
				// Guard the oracle: some frames must stay hidden, or the test
				// could not tell a correct filter from "show everything".
				if len(want) == len(frames) {
					t.Fatalf("fixture has no hidden frames; oracle would not catch over-marking")
				}

				for _, perm := range permutations(matches) {
					got := make(map[int]bool)
					markFilterVisible(ancestry, slices.Values(perm), got)
					if !maps.Equal(got, want) {
						t.Fatalf("match order %v:\n got  %v\n want %v",
							perm, pathsOf(frames, got), pathsOf(frames, want))
					}
				}
			})
		}
	}
}

// TestFilterVisibleSetUsingAncestryShowsChildrenOfNestedMatches drives the
// map-based entry point used by SearchController many times, so random map
// iteration order visits the nested match first in a good share of runs.
func TestFilterVisibleSetUsingAncestryShowsChildrenOfNestedMatches(t *testing.T) {
	frames := framesFromPaths("a", "a;foo", "a;foo;x", "a;foo;food", "a;bar", "b")
	ancestry := buildFrameAncestry(frames)
	matchSet := map[int]bool{}
	for _, idx := range matchIndicesByName(frames, "foo") {
		matchSet[idx] = true
	}
	want := []string{"a", "a;foo", "a;foo;food", "a;foo;x"}

	// Reuse one output set to also cover clearing of stale entries.
	set := map[int]bool{4: true, 5: true}
	for i := range 500 {
		set = filterVisibleSetUsingAncestry(frames, matchSet, ancestry, set)
		if got := pathsOf(frames, set); !slices.Equal(got, want) {
			t.Fatalf("iteration %d: got %v, want %v", i, got, want)
		}
	}
}

func TestFilterVisibleSetUsingAncestryEdgeCases(t *testing.T) {
	frames := framesFromPaths("a", "a;foo", "a;foo;x", "a;bar", "b")
	ancestry := buildFrameAncestry(frames)

	tests := []struct {
		name     string
		matchSet map[int]bool
		ancestry frameAncestry
		want     []string
	}{
		{
			name:     "no matches clears a reused set",
			matchSet: map[int]bool{},
			ancestry: ancestry,
			want:     nil,
		},
		{
			name:     "out-of-range indices are ignored",
			matchSet: map[int]bool{-1: true, len(frames): true, 99: true},
			ancestry: ancestry,
			want:     nil,
		},
		{
			name:     "out-of-range indices do not hide valid matches",
			matchSet: map[int]bool{-1: true, 1: true, 99: true},
			ancestry: ancestry,
			want:     []string{"a", "a;foo", "a;foo;x"},
		},
		{
			name:     "leaf match shows only its ancestor chain",
			matchSet: map[int]bool{2: true},
			ancestry: ancestry,
			want:     []string{"a", "a;foo", "a;foo;x"},
		},
		{
			name:     "stale ancestry is rebuilt",
			matchSet: map[int]bool{1: true},
			ancestry: buildFrameAncestry(frames[:2]),
			want:     []string{"a", "a;foo", "a;foo;x"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := map[int]bool{3: true, 4: true}
			set = filterVisibleSetUsingAncestry(frames, tt.matchSet, tt.ancestry, set)
			if got := pathsOf(frames, set); !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
