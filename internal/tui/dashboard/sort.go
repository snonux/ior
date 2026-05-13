package dashboard

import "slices"

type tableSortState[K comparable] struct {
	active  bool
	key     K
	reverse bool
}

func (s tableSortState[K]) toggled(key K, reverse bool) tableSortState[K] {
	if s.active && s.key == key && s.reverse == reverse {
		return tableSortState[K]{}
	}
	return tableSortState[K]{active: true, key: key, reverse: reverse}
}

func (s tableSortState[K]) apply(cmp int) int {
	if !s.reverse {
		return cmp
	}
	return -cmp
}

func sortDirectionLabel(defaultAscending, reverse bool) string {
	if defaultAscending != reverse {
		return "asc"
	}
	return "desc"
}

func sortLabelWithDirection(name string, defaultAscending, reverse bool) string {
	return name + " " + sortDirectionLabel(defaultAscending, reverse)
}

func compareUint64Desc(left, right uint64) int {
	switch {
	case left > right:
		return -1
	case left < right:
		return 1
	default:
		return 0
	}
}

func compareUint64Asc(left, right uint64) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func compareFloat64Desc(left, right float64) int {
	switch {
	case left > right:
		return -1
	case left < right:
		return 1
	default:
		return 0
	}
}

func compareStringAsc(left, right string) int {
	switch {
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

// sortedWithState is the shared sort helper for all sortable dashboard tables.
// It avoids four near-identical functions (files, dirs, syscalls, processes)
// that each guard on empty/inactive, clone the slice, sort with a key
// comparator, fall back to a tiebreaker, and apply the reverse flag.
//
//   - rows       – the input slice (not modified; nil is returned when empty)
//   - sortState  – carries the active flag, selected key, and reverse flag
//   - byKey      – per-key comparator for the active sort column
//   - tiebreak   – stable fallback comparator used when byKey returns 0
func sortedWithState[T any, K comparable](
	rows []T,
	sortState tableSortState[K],
	byKey func(left, right T, key K) int,
	tiebreak func(left, right T) int,
) []T {
	if len(rows) == 0 {
		return nil
	}
	if !sortState.active {
		return rows
	}
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(left, right T) int {
		cmp := byKey(left, right, sortState.key)
		if cmp == 0 {
			cmp = tiebreak(left, right)
		}
		return sortState.apply(cmp)
	})
	return sorted
}
