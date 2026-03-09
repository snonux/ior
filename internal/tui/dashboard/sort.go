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
