package tracefilter

import (
	"fmt"

	common "ior/internal/tui/common"
)

const (
	// filterTitle is the modal's heading line.
	filterTitle = "Filter"
	// filterHelp is the key help, " • "-separated so a compact layout keeps
	// whole segments (common.FitHint).
	filterHelp = "j/k move • Enter edit/apply • Tab op • Space toggle errors • c clear (keeps family) • Esc apply+close"
	// The case rule is spelled out because it differs by anchor mode (see
	// globalfilter.StringFilter): only the fully anchored ^exact$ and the
	// directory-children ^dir/* - the forms dashboard row filters round-trip
	// through this modal - are case-sensitive. ^dir/* is listed because it is
	// the one form whose meaning is not the obvious anchored substring.
	filterStringsNote = "strings: substring by default, use ^prefix, suffix$ (any case), or ^exact$ (case-sensitive)"
	filterDirNote     = "         ^dir/* = files directly in dir (case-sensitive, no subdirs)"

	// filterBoxWidth and filterMinBoxWidth are the preferred box width and
	// the narrowest it shrinks to while the view has room
	// (common.ModalBoxWidth); filterInputWidth is the widest the field
	// being edited is drawn.
	filterBoxWidth    = 64
	filterMinBoxWidth = 40
	filterInputWidth  = 24
	// rowPrefixWidth is the cells a field row spends before its value: the
	// "> " selection marker and the label padded to nine cells ("%-8s ");
	// opWidth is the "[>=] " compare op of a numeric field.
	rowPrefixWidth = 2 + 9
	opWidth        = 5
)

// Resize fits the field input to the box drawn in a view width cells wide,
// so Update scrolls the typed text with the width View draws it at. The TUI
// calls it on every size change; zero or negative widths are ignored.
func (m Model) Resize(width int) Model {
	if width > 0 {
		m.width = width
		m = m.fitInput()
	}
	return m
}

// fitInput fits the field input's width and window to the active field at
// the width the last Resize stored (common.FitTextInput).
func (m Model) fitInput() Model {
	m.inputStart = common.FitTextInput(&m.textInput, m.inputStart, m.inputWidth(m.viewWidth()))
	return m
}

// viewWidth is the view width the last Resize stored, or 80.
func (m Model) viewWidth() int {
	if m.width <= 0 {
		return 80
	}
	return m.width
}

// textWidth is the cells of a text line of the modal in a view width cells
// wide (the box's text width, or the whole view where it is drawn bare).
func textWidth(width int) int {
	return common.ModalTextWidth(common.ModalBoxWidth(filterBoxWidth, filterMinBoxWidth, width), width)
}

// fieldPrefixWidth is the cells the active field's row spends before its
// value: the marker and label, plus the compare op of a numeric field.
func (m Model) fieldPrefixWidth() int {
	if m.isNumericField(m.activeField) {
		return rowPrefixWidth + opWidth
	}
	return rowPrefixWidth
}

// inputWidth is the edited field's input width in a view width cells wide:
// at most filterInputWidth and one cell less (the cursor cell) than the row
// has after the field's prefix; when that leaves no cell for the text, the
// row is drawn as the bare input (editRow) and has the whole text line.
func (m Model) inputWidth(width int) int {
	text := textWidth(width)
	if room := text - m.fieldPrefixWidth() - 1; room >= 1 {
		return min(filterInputWidth, room)
	}
	return max(text-1, 1)
}

// View renders the modal centred in a width x height view, exactly that size
// (zero or negative sizes fall back to 80x24). It used to be a fixed
// 64-column box, at least 40 wide, placed with lipgloss.Place, which only
// pads: the box came out 23 rows tall on a 5-row terminal and 40 columns
// wide on a 20-column one, so the terminal scrolled (task rz2). Now the box
// is at most the view's width (every line cut to it, the help and the notes
// wrapped at spaces) and sheds, in order (filterLayouts): its vertical
// padding, the two string-matching notes, the blank line above the help, the
// help's wrapping (then whole " • " segments on one line), the title and the
// Family line, and then field rows, keeping a window of rows centred on the
// active field above the key hint inside a whole border down to four rows.
// Below that, or under seven columns, it is drawn bare: the active field
// first, then the hint and the fields nearest the active one
// (filterBareLines). The field being edited keeps its cursor and typed text
// in view (inputWidth, common.FitTextInput).
func (m Model) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	text := textWidth(width)
	// m is a copy: the input's window is fitted to this width for this
	// render only, for a caller that skipped Resize; after Resize it is
	// already the remembered one, so this keeps it.
	common.FitTextInput(&m.textInput, m.inputStart, m.inputWidth(width))
	rows := m.fieldRows(text)
	boxWidth := common.ModalBoxWidth(filterBoxWidth, filterMinBoxWidth, width)
	return common.PlaceModal(width, height, boxWidth, m.filterLayouts(rows, text), m.filterBareLines(rows, text))
}

// fieldRows renders every field's row for a text line text cells wide, the
// Family line (when a family scope is active) last.
func (m Model) fieldRows(text int) []string {
	rows := make([]string, 0, len(m.fields)+1)
	for i, field := range m.fields {
		rows = append(rows, m.fieldRow(field, i, text))
	}
	return rows
}

// fieldRow is one field's row: the selection marker and the field
// (renderField). The field being edited is drawn as its bare input when the
// line has no room for the input after the label (editRow).
func (m Model) fieldRow(field filterField, index, text int) string {
	active := index == m.activeField
	if active && m.editing && field.fieldKey != fieldErrorsOnly && text-m.fieldPrefixWidth()-1 < 1 {
		return common.InputView(m.textInput, text)
	}
	prefix := "  "
	if active {
		prefix = "> "
	}
	return prefix + m.renderField(field, active)
}

// familyLine is the read-only Family line, or "" without a family scope.
// Family has no editable field here (it is set outside the modal: the [ / ]
// family cycle or the Syscalls-tab Family row filter) and is kept by Esc and
// by "c", so it is shown to make that carried-over constraint visible.
func (m Model) familyLine() string {
	family := m.filter.Family
	if family == nil || family.Pattern == "" {
		return ""
	}
	return fmt.Sprintf("  %-8s %s ([ / ] to change)", "Family:", common.Sanitize(family.Pattern))
}

// filterLayouts lists the modal's boxes from roomy to compact (see View):
// rows are the field rows, text the text line's cells.
func (m Model) filterLayouts(rows []string, text int) []common.ModalLayout {
	fields := append([]string(nil), rows...)
	if family := m.familyLine(); family != "" {
		fields = append(fields, family)
	}
	help := common.FitWrapped(filterHelp, text)
	notes := append(common.FitWrapped(filterStringsNote, text), common.FitWrapped(filterDirNote, text)...)
	hint := common.FitHint(filterHelp, text)
	join := func(parts ...[]string) []string { return joinParts(parts) }
	title, blank := []string{filterTitle}, []string{""}
	full := join(title, fields, blank, help, notes)
	layouts := []common.ModalLayout{
		{Lines: full, VPad: true},
		{Lines: full},
		{Lines: join(title, fields, blank, help)},
		{Lines: join(title, fields, help)},
		{Lines: join(title, fields, []string{hint})},
		{Lines: join(fields, []string{hint})},
	}
	for n := len(rows); n >= 1; n-- {
		layouts = append(layouts, common.ModalLayout{Lines: join(fieldWindow(rows, m.activeField, n), []string{hint})})
	}
	return layouts
}

// joinParts flattens parts into one list of lines.
func joinParts(parts [][]string) []string {
	var out []string
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// fieldWindow is the n rows of rows centred on active (as near as the ends
// allow).
func fieldWindow(rows []string, active, n int) []string {
	n = min(n, len(rows))
	start := max(min(active-(n-1)/2, len(rows)-n), 0)
	return rows[start : start+n]
}

// filterBareLines is the modal drawn without a box, ranked for a view too
// small for one: the active field (the input, when editing) first, then the
// key hint, then the other fields by their distance from the active one,
// then the Family line and the title.
func (m Model) filterBareLines(rows []string, text int) []common.RankedLine {
	lines := []common.RankedLine{{Text: filterTitle, Rank: len(rows) + 2}}
	for i, row := range rows {
		lines = append(lines, common.RankedLine{Text: row, Rank: rowRank(i, m.activeField)})
	}
	if family := m.familyLine(); family != "" {
		lines = append(lines, common.RankedLine{Text: family, Rank: len(rows) + 1})
	}
	return append(lines, common.RankedLine{Text: common.FitHint(filterHelp, text), Rank: 1})
}

// rowRank is a field row's bare rank: 0 for the active row, else one more
// than its distance from it, so the hint (rank 1) comes right after it.
func rowRank(index, active int) int {
	if index == active {
		return 0
	}
	return 1 + abs(index-active)
}

// abs is the absolute value of n.
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
