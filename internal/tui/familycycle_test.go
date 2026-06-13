package tui

import (
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/types"
)

func TestCurrentFamilyRank(t *testing.T) {
	if got := currentFamilyRank(globalfilter.Filter{}); got != familyCycleAll {
		t.Fatalf("nil Family should be the 'all' state (%d), got %d", familyCycleAll, got)
	}
	for rank, family := range types.AllSyscallFamilies() {
		filter := globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: string(family)}}
		if got := currentFamilyRank(filter); got != rank {
			t.Fatalf("family %q: want rank %d, got %d", family, rank, got)
		}
	}
}

func TestStepFamilyRankCyclesWithWrap(t *testing.T) {
	families := types.AllSyscallFamilies()
	last := len(families) - 1

	// Forward: all -> 0 -> 1 ... -> last -> all (wrap).
	cases := []struct {
		name        string
		start, want int
	}{
		{"all->first", familyCycleAll, 0},
		{"first->second", 0, 1},
		{"last->all (forward wrap)", last, familyCycleAll},
	}
	for _, tc := range cases {
		if got := stepFamilyRank(tc.start, +1); got != tc.want {
			t.Fatalf("%s: stepFamilyRank(%d, +1) = %d, want %d", tc.name, tc.start, got, tc.want)
		}
	}

	// Reverse: all -> last -> ... -> 0 -> all (wrap).
	revCases := []struct {
		name        string
		start, want int
	}{
		{"all->last (reverse wrap)", familyCycleAll, last},
		{"first->all", 0, familyCycleAll},
		{"second->first", 1, 0},
	}
	for _, tc := range revCases {
		if got := stepFamilyRank(tc.start, -1); got != tc.want {
			t.Fatalf("%s: stepFamilyRank(%d, -1) = %d, want %d", tc.name, tc.start, got, tc.want)
		}
	}
}

func TestStepFamilyRankFullForwardLoop(t *testing.T) {
	families := types.AllSyscallFamilies()
	cycleLen := len(families) + 1 // families plus the "all" state

	// Walking forward cycleLen times from "all" must return to "all" and visit
	// every family exactly once in display order.
	rank := familyCycleAll
	seen := make([]int, 0, cycleLen)
	for i := 0; i < cycleLen; i++ {
		rank = stepFamilyRank(rank, +1)
		seen = append(seen, rank)
	}
	if rank != familyCycleAll {
		t.Fatalf("full forward loop did not return to 'all': ended at %d", rank)
	}
	for i := range families {
		if seen[i] != i {
			t.Fatalf("forward order: position %d = %d, want %d", i, seen[i], i)
		}
	}
}

func TestFamilyForRank(t *testing.T) {
	if got := familyForRank(familyCycleAll); got != "" {
		t.Fatalf("'all' rank should map to empty family, got %q", got)
	}
	families := types.AllSyscallFamilies()
	if got := familyForRank(len(families)); got != "" {
		t.Fatalf("out-of-range rank should map to empty family, got %q", got)
	}
	if got := familyForRank(0); got != string(families[0]) {
		t.Fatalf("rank 0 should map to %q, got %q", families[0], got)
	}
}
