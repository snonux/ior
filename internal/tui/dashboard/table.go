package dashboard

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

// renderSelectableTable renders spec's rows as a selectable table at most
// width cells wide (width <= 0: unbounded): the header, the visible window of
// rows around selectedRow, and the "[Row x/N Col y/M] [hint]..." line. The
// columns are fitted to the width by fitTableColumns (task cz2), which keeps
// the natural layout whenever it fits; below the table's minimum width the
// whole table is its "terminal too narrow" notice. selectedCol is a logical
// column index (spec.columns), so the hint and the sort and filter keys keep
// their meaning whichever columns are shown. A line wider than the terminal
// is clipped by bubbletea v2's renderer (or soft-wrapped by any renderer that
// does not clip, breaking the frame's height budget), so neither the rows nor
// the hint line may exceed the width: the hint keeps whole segments only
// (fitHintSegments).
func renderSelectableTable(spec tableSpec, rows [][]string, width, height, selectedRow, selectedCol int, rowHint string, extraHints ...string) string {
	if len(rows) == 0 {
		return ""
	}

	selectedRow = clampOffset(selectedRow, len(rows))
	selectedCol = common.ClampTableCol(selectedCol, len(spec.columns))
	fit, ok := fitTableColumns(spec, width, selectedCol)
	if !ok {
		return spec.tooNarrowNotice(width)
	}
	columns := fit.columns(spec)
	shownCol := fit.visibleIndex(selectedCol)
	start, end := common.VisibleTableWindow(selectedRow, len(rows), tableRowBudget(height))

	lines := make([]string, 0, end-start+2)
	lines = append(lines, common.RenderTableHeader(columns))
	for idx := start; idx < end; idx++ {
		col := -1
		if idx == selectedRow {
			col = shownCol
		}
		lines = append(lines, common.RenderTableRow(columns, fit.cells(spec, rows[idx]), idx == selectedRow, col, lipgloss.Style{}))
	}

	hints := []string{fmt.Sprintf("Row %d/%d Col %d/%d", selectedRow+1, len(rows), selectedCol+1, len(spec.columns))}
	if rowHint != "" {
		hints = append(hints, rowHint)
	}
	hints = append(hints, extraHints...)
	lines = append(lines, fitHintSegments(hints, width))
	return strings.Join(lines, "\n")
}

func tablePageStep(height int) int {
	rows := tableRowBudget(height)
	if rows <= 1 {
		return 1
	}
	return rows - 1
}
