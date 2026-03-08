package dashboard

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

func renderSelectableTable(columns []common.TableColumn, rows [][]string, height, selectedRow, selectedCol int, rowHint string, extraHints ...string) string {
	if len(rows) == 0 {
		return ""
	}

	selectedRow = clampOffset(selectedRow, len(rows))
	selectedCol = common.ClampTableCol(selectedCol, len(columns))
	start, end := common.VisibleTableWindow(selectedRow, len(rows), syscallTableHeight(height))

	lines := make([]string, 0, end-start+2)
	lines = append(lines, common.RenderTableHeader(columns))
	for idx := start; idx < end; idx++ {
		col := -1
		if idx == selectedRow {
			col = selectedCol
		}
		lines = append(lines, common.RenderTableRow(columns, rows[idx], idx == selectedRow, col, lipgloss.Style{}))
	}

	hints := []string{fmt.Sprintf("Row %d/%d Col %d/%d", selectedRow+1, len(rows), selectedCol+1, len(columns))}
	if rowHint != "" {
		hints = append(hints, rowHint)
	}
	hints = append(hints, extraHints...)
	lines = append(lines, "["+strings.Join(hints, "] [")+"]")
	return strings.Join(lines, "\n")
}

func tablePageStep(height int) int {
	rows := syscallTableHeight(height)
	if rows <= 1 {
		return 1
	}
	return rows - 1
}
