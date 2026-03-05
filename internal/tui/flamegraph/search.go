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
	m.matchIndices = make(map[int]bool)
	m.searchInput.SetValue("")
	m.searchInput.Blur()
}

func (m *Model) applySearchQuery(raw string) {
	query := strings.ToLower(strings.TrimSpace(raw))
	m.searchQuery = query
	m.matchIndices = make(map[int]bool)
	if query == "" {
		return
	}

	for idx, frame := range m.frames {
		if strings.Contains(strings.ToLower(frame.Name), query) {
			m.matchIndices[idx] = true
		}
	}
	if len(m.matchIndices) > 0 {
		m.jumpMatch(1)
	}
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
		m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
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
	m.subtreeSet = computeSubtreeSet(m.frames, m.selectedIdx)
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
	lines := strings.Split(content, "\n")
	if len(lines) == 0 {
		return footer
	}
	lines[len(lines)-1] = footer
	return strings.Join(lines, "\n")
}
