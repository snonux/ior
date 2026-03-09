package dashboard

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
