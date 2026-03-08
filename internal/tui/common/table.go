package common

import (
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

// TableColumn defines one shared TUI table column.
type TableColumn struct {
	Title string
	Width int
}

// RenderTableHeader renders a shared table header row.
func RenderTableHeader(columns []TableColumn) string {
	cells := make([]string, 0, len(columns))
	for _, col := range columns {
		cells = append(cells, renderTableCell(col.Title, col.Width))
	}
	return TableHeaderStyle.Render(strings.Join(cells, " "))
}

// RenderTableRow renders one shared TUI table row.
func RenderTableRow(columns []TableColumn, cells []string, selected bool, selectedCol int, baseStyle lipgloss.Style) string {
	rendered := make([]string, 0, len(columns))
	for idx, col := range columns {
		value := ""
		if idx < len(cells) {
			value = cells[idx]
		}
		cell := renderTableCell(value, col.Width)
		switch {
		case selected && idx == selectedCol:
			cell = TableSelectedCellStyle.Render(cell)
		case selected:
			cell = TableSelectedRowStyle.Render(cell)
		}
		rendered = append(rendered, cell)
	}
	row := strings.Join(rendered, " ")
	if selected {
		return row
	}
	return baseStyle.Render(row)
}

// HandleTableNavigationKey applies shared row/column movement for table views.
func HandleTableNavigationKey(keyStr string, row, col *int, rowCount, colCount, pageStep int) bool {
	switch keyStr {
	case "down", "j":
		*row = clampIndex(*row+1, rowCount)
		return true
	case "up", "k":
		*row = clampIndex(*row-1, rowCount)
		return true
	case "left", "h":
		*col = clampIndex(*col-1, colCount)
		return true
	case "right", "l":
		*col = clampIndex(*col+1, colCount)
		return true
	case "g":
		*row = clampIndex(0, rowCount)
		return true
	case "G":
		*row = clampIndex(rowCount-1, rowCount)
		return true
	case "pgup", "pageup":
		if pageStep < 1 {
			pageStep = 1
		}
		*row = clampIndex(*row-pageStep, rowCount)
		return true
	case "pgdown", "pgdn", "pagedown":
		if pageStep < 1 {
			pageStep = 1
		}
		*row = clampIndex(*row+pageStep, rowCount)
		return true
	default:
		return false
	}
}

// VisibleTableWindow returns a centered visible row range for the selection.
func VisibleTableWindow(selectedRow, rowCount, visibleRows int) (int, int) {
	if rowCount <= 0 {
		return 0, 0
	}
	if visibleRows <= 0 || visibleRows >= rowCount {
		return 0, rowCount
	}
	selectedRow = clampIndex(selectedRow, rowCount)
	start := selectedRow - visibleRows/2
	if start < 0 {
		start = 0
	}
	maxStart := rowCount - visibleRows
	if start > maxStart {
		start = maxStart
	}
	return start, start + visibleRows
}

// ClampTableCol clamps a selected column index for the current table shape.
func ClampTableCol(col, colCount int) int {
	return clampIndex(col, colCount)
}

func renderTableCell(value string, width int) string {
	if width <= 0 {
		return ""
	}
	value = sanitizeTableCell(value)
	value = truncateTableCell(value, width)
	cellWidth := utf8.RuneCountInString(value)
	if cellWidth >= width {
		return value
	}
	return value + strings.Repeat(" ", width-cellWidth)
}

func sanitizeTableCell(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\t", " ")
	return value
}

func truncateTableCell(value string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(value) <= width {
		return value
	}
	if width <= 3 {
		return string([]rune(value)[:width])
	}
	runes := []rune(value)
	return string(runes[:width-3]) + "..."
}

func clampIndex(value, count int) int {
	if count <= 0 {
		return 0
	}
	if value < 0 {
		return 0
	}
	if value >= count {
		return count - 1
	}
	return value
}
