package dashboard

type tableSortState[K comparable] struct {
	active bool
	key    K
}

func (s tableSortState[K]) toggled(key K) tableSortState[K] {
	if s.active && s.key == key {
		return tableSortState[K]{}
	}
	return tableSortState[K]{active: true, key: key}
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
