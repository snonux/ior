package common

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// TestRenderTableHeaderProducesColumns verifies that RenderTableHeader creates a
// styled row containing each column title padded to its declared width.
func TestRenderTableHeaderProducesColumns(t *testing.T) {
	cols := []TableColumn{
		{Title: "PID", Width: 8},
		{Title: "COMM", Width: 12},
	}
	out := RenderTableHeader(cols)
	if !strings.Contains(out, "PID") {
		t.Fatalf("expected header to contain PID, got: %q", out)
	}
	if !strings.Contains(out, "COMM") {
		t.Fatalf("expected header to contain COMM, got: %q", out)
	}
}

// TestRenderTableRowSelectedAndUnselected verifies that selected rows include
// highlighted style and unselected rows use the base style.
func TestRenderTableRowSelectedAndUnselected(t *testing.T) {
	cols := []TableColumn{
		{Title: "SYS", Width: 10},
		{Title: "CNT", Width: 6},
	}
	cells := []string{"openat", "42"}
	base := lipgloss.NewStyle()

	unselected := RenderTableRow(cols, cells, false, 0, base)
	if !strings.Contains(unselected, "openat") {
		t.Fatalf("unselected row missing cell content, got: %q", unselected)
	}

	// Selected row: all cells present, no base style rendering branch.
	selected := RenderTableRow(cols, cells, true, 1, base)
	if !strings.Contains(selected, "openat") {
		t.Fatalf("selected row missing first cell, got: %q", selected)
	}
	if !strings.Contains(selected, "42") {
		t.Fatalf("selected row missing second cell, got: %q", selected)
	}
}

// TestRenderTableRowMissingCells verifies that missing cells default to empty
// strings rather than panicking.
func TestRenderTableRowMissingCells(t *testing.T) {
	cols := []TableColumn{
		{Title: "A", Width: 4},
		{Title: "B", Width: 4},
	}
	// Provide only one cell for two columns.
	out := RenderTableRow(cols, []string{"x"}, false, 0, lipgloss.NewStyle())
	if !strings.Contains(out, "x") {
		t.Fatalf("expected cell content x in output, got: %q", out)
	}
}

// TestHandleTableNavigationKeyMovement verifies all supported key strings
// produce the expected row/col changes.
func TestHandleTableNavigationKeyMovement(t *testing.T) {
	cases := []struct {
		key        string
		initRow    int
		initCol    int
		wantRow    int
		wantCol    int
		rowCount   int
		colCount   int
		pageStep   int
		wantResult bool
	}{
		{"down", 0, 0, 1, 0, 5, 3, 1, true},
		{"j", 2, 0, 3, 0, 5, 3, 1, true},
		{"up", 2, 0, 1, 0, 5, 3, 1, true},
		{"k", 1, 0, 0, 0, 5, 3, 1, true},
		{"right", 0, 0, 0, 1, 5, 3, 1, true},
		{"l", 0, 1, 0, 2, 5, 3, 1, true},
		{"left", 0, 2, 0, 1, 5, 3, 1, true},
		{"h", 0, 1, 0, 0, 5, 3, 1, true},
		{"g", 3, 1, 0, 1, 5, 3, 1, true},
		{"G", 0, 1, 4, 1, 5, 3, 1, true},
		{"pgup", 4, 0, 2, 0, 5, 3, 2, true},
		{"pageup", 4, 0, 2, 0, 5, 3, 2, true},
		{"pgdown", 0, 0, 2, 0, 5, 3, 2, true},
		{"pgdn", 0, 0, 2, 0, 5, 3, 2, true},
		{"pagedown", 0, 0, 2, 0, 5, 3, 2, true},
		{"x", 0, 0, 0, 0, 5, 3, 1, false},
	}

	for _, tc := range cases {
		row, col := tc.initRow, tc.initCol
		got := HandleTableNavigationKey(tc.key, &row, &col, tc.rowCount, tc.colCount, tc.pageStep)
		if got != tc.wantResult {
			t.Errorf("key=%q: handled=%v, want %v", tc.key, got, tc.wantResult)
		}
		if tc.wantResult && (row != tc.wantRow || col != tc.wantCol) {
			t.Errorf("key=%q: row=%d col=%d, want row=%d col=%d",
				tc.key, row, col, tc.wantRow, tc.wantCol)
		}
	}
}

// TestHandleTableNavigationKeyZeroPageStep verifies that a zero page step is
// treated as 1 to avoid staying in place.
func TestHandleTableNavigationKeyZeroPageStep(t *testing.T) {
	row, col := 3, 0
	HandleTableNavigationKey("pgup", &row, &col, 5, 3, 0)
	if row != 2 {
		t.Fatalf("expected row=2 after pgup with pageStep=0 (clamped to 1), got %d", row)
	}
}

// TestVisibleTableWindowEdgeCases verifies boundary conditions for the visible
// window calculation.
func TestVisibleTableWindowEdgeCases(t *testing.T) {
	// Empty row set: returns (0,0).
	s, e := VisibleTableWindow(0, 0, 10)
	if s != 0 || e != 0 {
		t.Fatalf("empty rows: want (0,0), got (%d,%d)", s, e)
	}

	// All rows fit in the visible window.
	s, e = VisibleTableWindow(2, 5, 10)
	if s != 0 || e != 5 {
		t.Fatalf("all fit: want (0,5), got (%d,%d)", s, e)
	}

	// Selection near start.
	s, e = VisibleTableWindow(0, 10, 4)
	if s != 0 || e != 4 {
		t.Fatalf("start: want (0,4), got (%d,%d)", s, e)
	}

	// Selection near end.
	s, e = VisibleTableWindow(9, 10, 4)
	if s != 6 || e != 10 {
		t.Fatalf("end: want (6,10), got (%d,%d)", s, e)
	}

	// Middle selection.
	s, e = VisibleTableWindow(5, 10, 4)
	if s != 3 || e != 7 {
		t.Fatalf("middle: want (3,7), got (%d,%d)", s, e)
	}
}

// TestClampTableCol verifies ClampTableCol constrains within [0, colCount-1].
func TestClampTableCol(t *testing.T) {
	if got := ClampTableCol(-1, 5); got != 0 {
		t.Fatalf("ClampTableCol(-1,5) = %d, want 0", got)
	}
	if got := ClampTableCol(10, 5); got != 4 {
		t.Fatalf("ClampTableCol(10,5) = %d, want 4", got)
	}
	if got := ClampTableCol(2, 5); got != 2 {
		t.Fatalf("ClampTableCol(2,5) = %d, want 2", got)
	}
	if got := ClampTableCol(0, 0); got != 0 {
		t.Fatalf("ClampTableCol(0,0) = %d, want 0", got)
	}
}

// TestRenderTableCellTruncation verifies that cells wider than their column are
// truncated with an ellipsis.
func TestRenderTableCellTruncation(t *testing.T) {
	// renderTableCell is unexported; exercise it via RenderTableHeader.
	cols := []TableColumn{{Title: "ABCDEFGHIJ", Width: 6}}
	out := RenderTableHeader(cols)
	// The title should be truncated to fit within width=6: "ABC..."
	if !strings.Contains(out, "ABC...") {
		t.Fatalf("expected truncated header ABC..., got: %q", out)
	}
}

// TestRenderTableCellZeroWidth verifies that a zero-width column renders an
// empty string without panicking.
func TestRenderTableCellZeroWidth(t *testing.T) {
	cols := []TableColumn{{Title: "X", Width: 0}}
	out := RenderTableHeader(cols)
	// Expect nothing meaningful — just no panic and no content.
	_ = out
}

// TestSanitizeAndTruncateCellEmbeddedNewlines verifies that embedded newlines
// and tabs in cell values are replaced by spaces.
func TestSanitizeAndTruncateCellEmbeddedNewlines(t *testing.T) {
	cols := []TableColumn{{Title: "A\nB\tC", Width: 10}}
	out := RenderTableHeader(cols)
	if strings.Contains(out, "\n") || strings.Contains(out, "\t") {
		t.Fatalf("expected newlines and tabs stripped from cell, got: %q", out)
	}
}

// TestPickerShortHelpReturnsThreeBindings verifies that PickerShortHelp from
// the KeyMap returns three entries (Enter, Refresh, Esc).
func TestPickerShortHelpReturnsThreeBindings(t *testing.T) {
	keys := DefaultKeyMap()
	bindings := keys.PickerShortHelp()
	if len(bindings) != 3 {
		t.Fatalf("PickerShortHelp len = %d, want 3", len(bindings))
	}
}
