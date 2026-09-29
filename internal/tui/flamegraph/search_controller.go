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

// isActive reports whether the search input is open and receiving keys.
func (sc *SearchController) isActive() bool {
	return sc.searchActive
}

// query returns the applied (trimmed, lower-cased) filter query, or "" when
// no filter is applied.
func (sc *SearchController) query() string {
	return sc.searchQuery
}

// inputValue returns the text currently typed into the search input. It
// differs from query() while the input is open: query() is only updated on
// commit, whereas the input value changes on every keystroke.
func (sc *SearchController) inputValue() string {
	return sc.searchInput.Value()
}

// inputCursor returns the cursor position inside the search input. Cursor
// moves (left/right/home/end) change the rendered footer without changing the
// value, so the view cache must see them too.
func (sc *SearchController) inputCursor() int {
	return sc.searchInput.Position()
}

// matches returns the set of frame indices whose name matches the query. The
// map is owned by the controller and is refilled in place on every recompute,
// so callers must not retain or mutate it.
func (sc *SearchController) matches() map[int]bool {
	return sc.matchIndices
}

// visibleSet returns the frames an active filter keeps visible: every match
// plus its subtree and ancestors. Same ownership rules as matches.
func (sc *SearchController) visibleSet() map[int]bool {
	return sc.filterVisible
}

// navigable returns the selection filter implied by the current query: nil
// (every frame navigable) when no filter is applied, otherwise membership in
// the filter-visible set.
func (sc *SearchController) navigable() frameFilter {
	if !filterActive(sc.searchQuery) {
		return nil
	}
	visible := sc.filterVisible
	return func(idx int) bool { return visible[idx] }
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

// commit closes the search input and applies raw as the filter query. It
// returns the same status message and jump direction as applyQuery.
func (sc *SearchController) commit(raw string, frames []tuiFrame, ancestry frameAncestry) (statusMsg string, jumpDir int) {
	sc.searchActive = false
	return sc.applyQuery(raw, frames, ancestry)
}

// handleInput processes a key event while search mode is active. It reports
// whether the search was committed or cancelled; the committed value carries
// the final query string.
//
// The text input's command is discarded, as in the stream search, stream
// export and recording modals: it only schedules the cursor blink, and no
// parent routes the blink message back to this input (the flamegraph's Update
// handles keys, mouse clicks, resizes and its own ticks only), so returning
// it would leave orphan timers while the cursor still never blinks.
func (sc *SearchController) handleInput(msg tea.KeyPressMsg) (committed bool, query string, cancelled bool) {
	switch msg.String() {
	case "esc":
		return false, "", true
	case "enter":
		return true, sc.searchInput.Value(), false
	}
	var cmd tea.Cmd
	sc.searchInput, cmd = sc.searchInput.Update(msg)
	_ = cmd
	return false, "", false
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
func (sc *SearchController) footerLine(selectedIdx int) string {
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

// jumpMatch moves the selection to the next or previous match (direction +1/-1)
// and returns the new selectedIdx together with its subtree highlight set.
// `subtree` is the caller's current highlight set: with no matches the
// selection does not move, so both selectedIdx and subtree are returned
// unchanged, keeping the highlight in sync with the selection (a nil set was
// only papered over by the renderer's recompute fallback). Otherwise subtree
// is refilled in place for the new selection, like subtreeSetUsingAncestry.
func jumpMatch(frames []tuiFrame, matchIndices map[int]bool, ancestry frameAncestry, selectedIdx, direction int, subtree map[int]bool) (int, map[int]bool) {
	matches := orderedMatchIndices(matchIndices)
	if len(matches) == 0 {
		return selectedIdx, subtree
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
	return nextIdx, subtreeSetUsingAncestry(frames, nextIdx, ancestry, subtree)
}

// setDarkMode updates the text input style for the given theme.
func (sc *SearchController) setDarkMode(isDark bool) {
	sc.searchInput.SetStyles(textinput.DefaultStyles(isDark))
}

// discardResults empties the match and filter-visible sets, and the applied
// query when clearQuery is set, as done when the snapshot state is cleared.
// Unlike reset it leaves the input widget and search mode alone.
func (sc *SearchController) discardResults(clearQuery bool) {
	sc.matchIndices = resetBoolSet(sc.matchIndices)
	sc.filterVisible = resetBoolSet(sc.filterVisible)
	if clearQuery {
		sc.searchQuery = ""
	}
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
