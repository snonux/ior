package dashboard

import (
	common "ior/internal/tui/common"
)

// tableTabState is the state every table tab carries: the selected row and
// column, the live sort state, the alternative-visualization mode, and the
// bubble chart instance. The table tabs differ only in their row and sort-key
// types (and in how their data is fed, which stays per-tab for the same
// reason rendering does); everything that is generically "a table tab" lives
// here, once.
//
// This component is what lets the tab registry keep its no-switch promise:
// adding a table tab means one tableTabState field on Model plus a registry
// entry whose hooks are closures over that field - not a new arm in every
// switch in model.go (which is what the ~24 case-Tab switches this replaced
// demanded; see the audit finding behind this extraction).
type tableTabState[SortKey comparable] struct {
	// offset is the selected row index; it is always used through
	// selectedIndex/selected, which clamp it against the live row count.
	offset int
	// col is the selected table column index.
	col int
	// sort is the live sort state applied by the tab's sorted*Rows helper.
	sort tableSortState[SortKey]
	// mode is the active visualization mode for this tab; the zero value is
	// tabVizModeTable, so a freshly constructed state starts in table mode.
	mode tabVizMode
	// bubble is the tab's bubble-chart instance.
	bubble bubbleChart
}

// tableTab is the tab-agnostic behaviour every tableTabState exposes to the
// paths that must not care which tab is active: viz-mode cycling, bubble
// dispatch and mode queries. Each tab's TableState registry hook (reached
// through Model.tableTabFor) is the single place that maps tab identity to
// this interface; the paths behind it (tabVizModeFor,
// setTabVizMode, bubbleChartFor, bubbleEnabledForTab, cycleVisualizationMode)
// are generic over tableTab instead of switching on the tab again.
type tableTab interface {
	currentVizMode() tabVizMode
	setVizMode(tabVizMode)
	bubbleChart() *bubbleChart
}

func (t *tableTabState[SortKey]) currentVizMode() tabVizMode {
	return t.mode
}

func (t *tableTabState[SortKey]) setVizMode(mode tabVizMode) {
	t.mode = mode
}

func (t *tableTabState[SortKey]) bubbleChart() *bubbleChart {
	return &t.bubble
}

// selectedIndex returns the selected row index clamped to rows.
func (t *tableTabState[SortKey]) selectedIndex(rows int) int {
	return clampOffset(t.offset, rows)
}

// selected returns the clamped selected row index for a non-empty view.
func (t *tableTabState[SortKey]) selected(rows int) (int, bool) {
	if rows == 0 {
		return 0, false
	}
	return t.selectedIndex(rows), true
}

// navigate applies one navigation key press to the selection, clamping the
// row against maxRows and the column against columns.
func (t *tableTabState[SortKey]) navigate(keyStr string, maxRows, columns, pageStep int) bool {
	return common.HandleTableNavigationKey(keyStr, &t.offset, &t.col, maxRows, columns, pageStep)
}

// applySort toggles the sort for the given column and hands the new offset
// to reanchor, which is expected to keep the pre-sort selection in view:
// the per-tab closure captures the selected row BEFORE this call (see
// selected) and finds its index in the freshly sorted rows, falling back to
// clamping the current offset. Returns false when the tab is not in table
// mode or the column has no sort key, so a registry hook can pass the
// verdict straight through.
func (t *tableTabState[SortKey]) applySort(reverse bool, col int,
	sortKeyForColumn func(int) (SortKey, bool), reanchor func(current int) int) bool {
	if t.mode != tabVizModeTable {
		return false
	}
	key, ok := sortKeyForColumn(col)
	if !ok {
		return false
	}
	current := t.offset
	t.sort = t.sort.toggled(key, reverse)
	t.offset = reanchor(current)
	return true
}
