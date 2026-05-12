package flamegraph

import (
	"sort"
	"strings"
)

// orderedMatchIndices returns the keys of matchSet as a sorted int slice.
// Used by search navigation and the search footer to determine match position.
func orderedMatchIndices(matchSet map[int]bool) []int {
	matches := make([]int, 0, len(matchSet))
	for idx := range matchSet {
		matches = append(matches, idx)
	}
	sort.Ints(matches)
	return matches
}

// openSearch activates search mode on the Model by delegating to SearchController.
func (m *Model) openSearch() {
	m.SearchController.open()
}

// clearSearch deactivates search mode and clears all search state.
// Delegates to SearchController and updates the Model status message.
func (m *Model) clearSearch() {
	m.statusMessage = m.SearchController.clear()
}

// applySearchQuery applies a new search query, rebuilds filter state, and jumps
// to the first match. Delegates to SearchController.applyQuery, then applies
// any resulting selection change via the shared jumpMatch helper.
func (m *Model) applySearchQuery(raw string) {
	statusMsg, jumpDir := m.SearchController.applyQuery(raw, m.frames, m.ancestry)
	m.statusMessage = statusMsg
	if jumpDir != 0 {
		m.selectedIdx, m.subtreeSet = jumpMatch(
			m.frames, m.matchIndices, m.ancestry, m.selectedIdx, jumpDir,
		)
	} else {
		m.SelectionManager.ensureNavigable(m.frames, m.matchIndices, m.searchQuery, m.filterVisible)
	}
}

// recomputeFilterState rebuilds the match and filter-visible sets after a
// frame layout change. Delegates to SearchController.recomputeFilterState.
func (m *Model) recomputeFilterState() {
	m.SearchController.recomputeFilterState(m.frames, m.ancestry)
}

// searchFooter renders the search bar with match position info. Delegates to
// SearchController.footerLine.
func (m Model) searchFooter() string {
	return m.SearchController.footerLine(m.frames, m.selectedIdx)
}

func replaceFooterLine(content, footer string) string {
	if content == "" {
		return footer
	}
	lastNewline := strings.LastIndexByte(content, '\n')
	if lastNewline == -1 {
		return footer
	}
	return content[:lastNewline+1] + footer
}

func replaceHeaderLine(content, header string) string {
	if content == "" {
		return header
	}
	firstNewline := strings.IndexByte(content, '\n')
	if firstNewline == -1 {
		return header
	}
	return header + content[firstNewline:]
}

func clearBoolMap[K comparable](values map[K]bool) {
	for key := range values {
		delete(values, key)
	}
}
