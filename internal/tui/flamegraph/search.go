package flamegraph

import (
	"fmt"
	"sort"
	"strings"
)

func (m *Model) openSearch() {
	m.searchActive = true
	m.searchInput.SetValue(m.searchQuery)
	m.searchInput.CursorEnd()
	m.searchInput.Focus()
}

func (m *Model) clearSearch() {
	m.searchActive = false
	m.searchQuery = ""
	clearBoolMap(m.matchIndices)
	clearBoolMap(m.filterVisible)
	m.searchInput.SetValue("")
	m.searchInput.Blur()
	m.statusMessage = "Filter cleared"
}

func (m *Model) applySearchQuery(raw string) {
	m.searchQuery = strings.ToLower(strings.TrimSpace(raw))
	m.recomputeFilterState()
	query := m.searchQuery
	if query == "" {
		m.ensureSelectionNavigable()
		m.statusMessage = "Filter cleared"
		return
	}

	if len(m.matchIndices) > 0 {
		m.jumpMatch(1)
		m.statusMessage = fmt.Sprintf("Filter %q: %d matches", query, len(m.matchIndices))
		return
	}
	m.statusMessage = fmt.Sprintf("Filter %q: no matches", query)
}

func (m *Model) jumpMatch(direction int) {
	matches := orderedMatchIndices(m.matchIndices)
	if len(matches) == 0 {
		return
	}
	currentPos := indexOf(matches, m.selectedIdx)
	if currentPos == -1 {
		if direction < 0 {
			m.selectedIdx = matches[len(matches)-1]
		} else {
			m.selectedIdx = matches[0]
		}
		m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
		return
	}

	next := currentPos + direction
	if next < 0 {
		next = len(matches) - 1
	}
	if next >= len(matches) {
		next = 0
	}
	m.selectedIdx = matches[next]
	m.subtreeSet = subtreeSetUsingAncestry(m.frames, m.selectedIdx, m.ancestry, m.subtreeSet)
}

func (m *Model) recomputeFilterState() {
	if m.matchIndices == nil {
		m.matchIndices = make(map[int]bool)
	} else {
		clearBoolMap(m.matchIndices)
	}
	if m.filterVisible == nil {
		m.filterVisible = make(map[int]bool)
	} else {
		clearBoolMap(m.filterVisible)
	}
	if m.searchQuery == "" {
		return
	}

	for idx, frame := range m.frames {
		if strings.Contains(strings.ToLower(frame.Name), m.searchQuery) {
			m.matchIndices[idx] = true
		}
	}
	m.filterVisible = filterVisibleSetUsingAncestry(m.frames, m.matchIndices, m.ancestry, m.filterVisible)
}

func orderedMatchIndices(matchSet map[int]bool) []int {
	matches := make([]int, 0, len(matchSet))
	for idx := range matchSet {
		matches = append(matches, idx)
	}
	sort.Ints(matches)
	return matches
}

func (m Model) searchFooter() string {
	matches := orderedMatchIndices(m.matchIndices)
	pos := 0
	if len(matches) > 0 {
		idx := indexOf(matches, m.selectedIdx)
		if idx >= 0 {
			pos = idx + 1
		}
	}
	return fmt.Sprintf("%s  %d/%d matches", m.searchInput.View(), pos, len(matches))
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
