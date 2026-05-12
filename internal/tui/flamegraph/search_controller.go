package flamegraph

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
)

// SearchController owns all search/filter state and operations. It manages the
// text input widget, the current query string, the set of matching frame indices,
// and the filter-visible set that drives navigation when a filter is active.
type SearchController struct {
	searchActive  bool
	searchInput   textinput.Model
	searchQuery   string
	matchIndices  map[int]bool
	filterVisible map[int]bool
}

// newSearchController constructs a SearchController with a configured text input.
func newSearchController(isDark bool) SearchController {
	input := textinput.New()
	input.Prompt = "/"
	input.CharLimit = 0
	input.SetWidth(32)
	input.SetStyles(textinput.DefaultStyles(isDark))
	return SearchController{
		matchIndices:  make(map[int]bool),
		filterVisible: make(map[int]bool),
		searchInput:   input,
	}
}

// open activates search mode, restoring the current query into the text input.
func (sc *SearchController) open() {
	sc.searchActive = true
	sc.searchInput.SetValue(sc.searchQuery)
	sc.searchInput.CursorEnd()
	sc.searchInput.Focus()
}

// clear deactivates search mode and wipes the query and index maps.
// Returns a status message.
func (sc *SearchController) clear() string {
	sc.searchActive = false
	sc.searchQuery = ""
	clearBoolMap(sc.matchIndices)
	clearBoolMap(sc.filterVisible)
	sc.searchInput.SetValue("")
	sc.searchInput.Blur()
	return "Filter cleared"
}

// applyQuery stores a new search query and rebuilds the match/filter sets.
// Returns the status message to display and the direction to jump (0 = no jump).
func (sc *SearchController) applyQuery(raw string, frames []tuiFrame, ancestry frameAncestry) (statusMsg string, jumpDir int) {
	sc.searchQuery = strings.ToLower(strings.TrimSpace(raw))
	sc.recomputeFilterState(frames, ancestry)
	query := sc.searchQuery
	if query == "" {
		return "Filter cleared", 0
	}
	if len(sc.matchIndices) > 0 {
		return fmt.Sprintf("Filter %q: %d matches", query, len(sc.matchIndices)), 1
	}
	return fmt.Sprintf("Filter %q: no matches", query), 0
}

// handleInput processes a key event while search mode is active. Returns the
// updated text input command, plus booleans for whether the search was committed
// or cancelled. The committed value carries the final query string.
func (sc *SearchController) handleInput(msg tea.KeyPressMsg) (cmd tea.Cmd, committed bool, query string, cancelled bool) {
	switch msg.String() {
	case "esc":
		return nil, false, "", true
	case "enter":
		return nil, true, sc.searchInput.Value(), false
	}
	var c tea.Cmd
	sc.searchInput, c = sc.searchInput.Update(msg)
	return c, false, "", false
}

// recomputeFilterState rebuilds matchIndices and filterVisible from the current
// query and the provided frame slice + ancestry index.
func (sc *SearchController) recomputeFilterState(frames []tuiFrame, ancestry frameAncestry) {
	if sc.matchIndices == nil {
		sc.matchIndices = make(map[int]bool)
	} else {
		clearBoolMap(sc.matchIndices)
	}
	if sc.filterVisible == nil {
		sc.filterVisible = make(map[int]bool)
	} else {
		clearBoolMap(sc.filterVisible)
	}
	if sc.searchQuery == "" {
		return
	}
	for idx, frame := range frames {
		if strings.Contains(strings.ToLower(frame.Name), sc.searchQuery) {
			sc.matchIndices[idx] = true
		}
	}
	sc.filterVisible = filterVisibleSetUsingAncestry(frames, sc.matchIndices, ancestry, sc.filterVisible)
}

// footerLine renders the search bar with the match count. Called by View when
// search is active.
func (sc *SearchController) footerLine(frames []tuiFrame, selectedIdx int) string {
	matches := orderedMatchIndices(sc.matchIndices)
	pos := 0
	if len(matches) > 0 {
		idx := indexOf(matches, selectedIdx)
		if idx >= 0 {
			pos = idx + 1
		}
	}
	return fmt.Sprintf("%s  %d/%d matches", sc.searchInput.View(), pos, len(matches))
}

// jumpMatch moves the selection to the next or previous match (direction +1/-1).
// Returns the new selectedIdx (unchanged if there are no matches).
func jumpMatch(frames []tuiFrame, matchIndices map[int]bool, ancestry frameAncestry, selectedIdx, direction int) (int, map[int]bool) {
	matches := orderedMatchIndices(matchIndices)
	if len(matches) == 0 {
		return selectedIdx, nil
	}
	currentPos := indexOf(matches, selectedIdx)
	var nextIdx int
	if currentPos == -1 {
		if direction < 0 {
			nextIdx = matches[len(matches)-1]
		} else {
			nextIdx = matches[0]
		}
	} else {
		next := currentPos + direction
		if next < 0 {
			next = len(matches) - 1
		}
		if next >= len(matches) {
			next = 0
		}
		nextIdx = matches[next]
	}
	subtree := subtreeSetUsingAncestry(frames, nextIdx, ancestry, nil)
	return nextIdx, subtree
}

// setDarkMode updates the text input style for the given theme.
func (sc *SearchController) setDarkMode(isDark bool) {
	sc.searchInput.SetStyles(textinput.DefaultStyles(isDark))
}

// reset clears all search state, keeping the text input widget.
func (sc *SearchController) reset(clearQuery bool) {
	sc.searchActive = false
	if clearQuery {
		sc.searchQuery = ""
		sc.searchInput.SetValue("")
	}
	clearBoolMap(sc.matchIndices)
	clearBoolMap(sc.filterVisible)
	sc.searchInput.Blur()
}
