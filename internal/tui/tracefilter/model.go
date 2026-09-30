package tracefilter

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/parser"
	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type fieldKey int

const (
	fieldSyscall fieldKey = iota
	fieldComm
	fieldFile
	fieldPID
	fieldTID
	fieldFD
	fieldLatency
	fieldGap
	fieldBytes
	fieldReturn
	fieldErrorsOnly
)

type filterField struct {
	label    string
	fieldKey fieldKey
	value    string
	opIndex  int
}

// Model is the filter modal. Every method takes a value receiver and every
// mutator returns the updated Model, exactly like the Open/Close/Update flow
// the modal is driven through (and like the sibling modals in tui/probes and
// tui/export): the receiver-style rule is what keeps a mutation from being
// silently lost when a caller holds the modal by value. The only methods
// that write into m.fields elements without returning are the plain
// setStringField/setNumericField/applyFilterToFields helpers, which take the
// fields slice explicitly so the shared-backing-array write is visible
// instead of implied by an addressable receiver.
type Model struct {
	visible bool
	fields  []filterField
	// opened is a private copy of the field values as Open initialised
	// them from the opened filter; buildFilterFromFields compares against
	// it to tell user edits from untouched fields (see fieldUnchanged).
	opened      []filterField
	activeField int
	editing     bool
	textInput   textinput.Model
	filter      globalfilter.Filter
}

var compareOps = []globalfilter.CompareOp{
	globalfilter.OpGt,
	globalfilter.OpLt,
	globalfilter.OpEq,
	globalfilter.OpGte,
	globalfilter.OpLte,
	globalfilter.OpNeq,
}

var compareOpLabels = []string{">", "<", "=", ">=", "<=", "!="}

// NewModel constructs a filter modal with the default field layout.
func NewModel() Model {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(24)
	input.SetStyles(textinput.DefaultStyles(true))

	model := Model{textInput: input}
	model.fields = defaultFilterFields()
	return model
}

// Visible reports whether the filter modal is shown.
func (m Model) Visible() bool {
	return m.visible
}

// Filter returns the filter built from the last applied modal edit. It
// carries over any dimension the modal has no field for (Family, set outside
// the modal) from the filter passed to Open.
func (m Model) Filter() globalfilter.Filter {
	return m.filter
}

// SetDarkMode restyles the text input for the given colour scheme.
func (m Model) SetDarkMode(isDark bool) Model {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// Open shows the modal with its fields initialised from initial.
func (m Model) Open(initial globalfilter.Filter) Model {
	m.visible = true
	m.activeField = 0
	m.editing = false
	m.textInput.Blur()
	m.fields = defaultFilterFields()
	applyFilterToFields(m.fields, initial)
	// Snapshot into a fresh backing array: m.fields elements are written in
	// place later, and the snapshot must keep the as-opened values.
	m.opened = append([]filterField(nil), m.fields...)
	m.filter = initial.Clone()
	return m
}

// Close hides the modal; the applied filter is left as it was.
func (m Model) Close() Model {
	m.visible = false
	m.editing = false
	m.textInput.Blur()
	return m
}

// Update processes a Bubble Tea message and returns the updated model.
// Key handling is split between an active text-edit state and navigation state.
func (m Model) Update(msg tea.Msg) Model {
	if !m.visible {
		return m
	}
	keyMsg, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m
	}
	if m.editing {
		return m.updateEditing(keyMsg)
	}
	return m.updateNavigating(keyMsg)
}

// updateEditing handles key presses while the user is typing into the text
// input for the active field. Esc commits and closes; Enter confirms the value.
func (m Model) updateEditing(keyMsg tea.KeyPressMsg) Model {
	switch keyMsg.String() {
	case "esc":
		m = m.commitEdit()
		m.filter = m.buildFilterFromFields()
		return m.Close()
	case "enter":
		if m.fields[m.activeField].fieldKey == fieldErrorsOnly {
			return m.toggleBoolField(m.activeField)
		}
		return m.commitEdit()
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(keyMsg)
	_ = cmd
	return m
}

// updateNavigating handles key presses while the user is navigating the field
// list (not actively editing a text input).
func (m Model) updateNavigating(keyMsg tea.KeyPressMsg) Model {
	switch keyMsg.String() {
	case "esc":
		m.filter = m.buildFilterFromFields()
		return m.Close()
	case "c":
		return m.clearAll()
	case "j", "down":
		if m.activeField < len(m.fields)-1 {
			m.activeField++
		}
		return m
	case "k", "up":
		if m.activeField > 0 {
			m.activeField--
		}
		return m
	case "tab":
		if m.isNumericField(m.activeField) {
			m.fields[m.activeField].opIndex = (m.fields[m.activeField].opIndex + 1) % len(compareOps)
		}
		return m
	case " ", "space":
		if m.fields[m.activeField].fieldKey == fieldErrorsOnly {
			return m.toggleBoolField(m.activeField)
		}
		return m
	case "enter":
		if m.fields[m.activeField].fieldKey == fieldErrorsOnly {
			return m.toggleBoolField(m.activeField)
		}
		return m.startEdit()
	}
	return m
}

// toggleBoolField flips the string "true"/"false" value for a boolean field.
// Value receiver returning Model, like every mutator on this type.
func (m Model) toggleBoolField(index int) Model {
	if strings.TrimSpace(m.fields[index].value) == "true" {
		m.fields[index].value = "false"
	} else {
		m.fields[index].value = "true"
	}
	return m
}

// View renders the centered modal box within the given viewport.
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

	modalWidth := 64
	if width < modalWidth+4 {
		modalWidth = width - 4
		if modalWidth < 40 {
			modalWidth = 40
		}
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(m.bodyLines(), "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// bodyLines renders the modal content: the editable fields, a read-only
// Family line when a family scope is active, and the key help. Family has no
// editable field here (it is set outside the modal: the [ / ] family cycle
// or the Syscalls-tab Family row filter) and is kept by Esc and by "c", so
// it is shown to make that carried-over constraint visible.
func (m Model) bodyLines() []string {
	lines := []string{"Filter"}
	for i, field := range m.fields {
		prefix := "  "
		if i == m.activeField {
			prefix = "> "
		}
		lines = append(lines, prefix+m.renderField(field, i == m.activeField))
	}
	if family := m.filter.Family; family != nil && family.Pattern != "" {
		lines = append(lines, fmt.Sprintf("  %-8s %s ([ / ] to change)", "Family:", family.Pattern))
	}
	lines = append(lines, "", "j/k move • Enter edit/apply • Tab op • Space toggle errors • c clear (keeps family) • Esc apply+close")
	// The case rule is spelled out because it differs by anchor mode (see
	// globalfilter.StringFilter): only the fully anchored ^exact$ and the
	// directory-children ^dir/* - the forms dashboard row filters round-trip
	// through this modal - are case-sensitive. ^dir/* is listed because it is
	// the one form whose meaning is not the obvious anchored substring.
	return append(lines,
		"strings: substring by default, use ^prefix, suffix$ (any case), or ^exact$ (case-sensitive)",
		"         ^dir/* = files directly in dir (case-sensitive, no subdirs)")
}

func (m Model) clearAll() Model {
	for i := range m.fields {
		m.fields[i].value = ""
		if m.isNumericField(i) {
			m.fields[i].opIndex = 2
		}
	}
	m.fields[len(m.fields)-1].value = "false"
	m.editing = false
	m.textInput.Blur()
	return m
}

func (m Model) startEdit() Model {
	m.editing = true
	m.textInput.SetValue(m.fields[m.activeField].value)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

func (m Model) commitEdit() Model {
	m.fields[m.activeField].value = strings.TrimSpace(m.textInput.Value())
	m.editing = false
	m.textInput.Blur()
	return m
}

func (m Model) renderField(field filterField, active bool) string {
	if field.fieldKey == fieldErrorsOnly {
		checked := "[ ]"
		if strings.TrimSpace(field.value) == "true" {
			checked = "[x]"
		}
		return fmt.Sprintf("%-8s %s", field.label+":", checked)
	}

	// Field values are seeded from the active filter, whose patterns are often
	// pushed from traced comm/file values, so they are sanitised for display
	// (the stored value stays raw so the filter still matches).
	value := common.Sanitize(field.value)
	if active && m.editing {
		value = m.textInput.View()
	}
	if field.fieldKey == fieldLatency || field.fieldKey == fieldGap || m.isNumericFieldByKey(field.fieldKey) {
		return fmt.Sprintf("%-8s [%2s] %s", field.label+":", compareOpLabels[field.opIndex], value)
	}
	return fmt.Sprintf("%-8s %s", field.label+":", value)
}

// buildFilterFromFields converts the current field values into a globalfilter.Filter.
// String fields use substring matching; numeric fields use the selected compare op.
//
// The result starts from a clone of the filter the modal was opened with, so
// dimensions the modal has no field for (currently Family, which is set
// outside the modal: the [ / ] family cycle or the Syscalls-tab Family row
// filter) survive an open+Esc or an edit+apply unchanged. Without that,
// closing the modal would silently drop Family, and the caller would see an
// unequal filter and reset the stats baseline and push an undo level even
// though the user changed nothing.
//
// For the same reason a field the user did not change keeps the opened
// dimension verbatim instead of being rebuilt from its text: rebuilding is
// not an identity for every filter the modal can be opened with. An
// untrimmed pattern ("foo ", e.g. the Stream tab's Enter-on-cell filter on a
// comm or path with trailing blanks) would come back trimmed, and an empty
// non-nil pattern would come back nil; neither is Equal to the original even
// though both match identically (every matcher trims the pattern and treats
// blank as "no constraint"). Keeping the original, rather than trimming
// patterns where filters are created, leaves the filter exactly as its
// producer made it. (Dashboard row filters are anchored - ^value$, ^dir/*,
// which no trim alters - or, for a process's Comm, already trimmed, so they
// would survive a rebuild anyway.)
// Every changed modal-owned dimension is then overwritten unconditionally by
// applyFieldToFilter, so a blanked or invalid field removes the constraint
// it replaced instead of inheriting it.
func (m Model) buildFilterFromFields() globalfilter.Filter {
	out := m.filter.Clone()
	for i, field := range m.fields {
		if i < len(m.opened) && fieldUnchanged(field, m.opened[i]) {
			continue
		}
		applyFieldToFilter(field, strings.TrimSpace(field.value), &out)
	}
	return out
}

// fieldUnchanged reports whether field still holds the value (and, for a
// numeric field, the compare op) it was opened with. Values are compared
// trimmed because commitEdit trims what the user typed: opening a field
// holding "foo " and confirming it unedited yields "foo", which is no edit.
func fieldUnchanged(field, opened filterField) bool {
	return field.opIndex == opened.opIndex &&
		strings.TrimSpace(field.value) == strings.TrimSpace(opened.value)
}

// applyFieldToFilter writes a single field value into the appropriate slot of
// out. It always assigns (nil / false when the value is empty or invalid):
// out starts as a clone of the opened filter, so skipping the write would
// leak the old constraint through a field the user just cleared. It is split
// out of buildFilterFromFields to keep each function concise.
func applyFieldToFilter(field filterField, value string, out *globalfilter.Filter) {
	switch field.fieldKey {
	case fieldSyscall:
		out.Syscall = stringFilterOrNil(value)
	case fieldComm:
		out.Comm = stringFilterOrNil(value)
	case fieldFile:
		out.File = stringFilterOrNil(value)
	case fieldPID:
		out.PID, _ = parseNumericFilter(value, field.opIndex, false)
	case fieldTID:
		out.TID, _ = parseNumericFilter(value, field.opIndex, false)
	case fieldFD:
		out.FD, _ = parseNumericFilter(value, field.opIndex, false)
	case fieldLatency:
		out.LatencyNs, _ = parseNumericFilter(value, field.opIndex, true)
	case fieldGap:
		out.GapNs, _ = parseNumericFilter(value, field.opIndex, true)
	case fieldBytes:
		out.Bytes, _ = parseNumericFilter(value, field.opIndex, false)
	case fieldReturn:
		out.RetVal, _ = parseNumericFilter(value, field.opIndex, false)
	case fieldErrorsOnly:
		out.ErrorsOnly = strings.EqualFold(value, "true")
	}
}

// stringFilterOrNil returns a substring filter for value, or nil (no
// constraint) when value is empty.
func stringFilterOrNil(value string) *globalfilter.StringFilter {
	if value == "" {
		return nil
	}
	return &globalfilter.StringFilter{Pattern: value}
}

// parseNumericFilter parses value into a numeric filter with the op at
// opIndex. It returns (nil, false) for an empty or unparsable value, which
// callers store as "no constraint".
func parseNumericFilter(value string, opIndex int, duration bool) (*globalfilter.NumericFilter, bool) {
	if value == "" {
		return nil, false
	}
	if opIndex < 0 || opIndex >= len(compareOps) {
		opIndex = 2
	}

	var (
		number int64
		err    error
	)
	if duration {
		number, err = parser.ParseDurationNs(value)
	} else {
		number, err = strconv.ParseInt(value, 10, 64)
	}
	if err != nil {
		return nil, false
	}
	return &globalfilter.NumericFilter{Op: compareOps[opIndex], Value: number}, true
}

// applyFilterToFields overwrites the field values in fields from filter.
// It takes the slice explicitly instead of a Model receiver so the
// element writes are visible slice semantics, not a pointer-receiver side
// effect. fields[i].fieldKey == i for every i (see defaultFilterFields), so
// indexing by fieldKey is indexing by position.
func applyFilterToFields(fields []filterField, filter globalfilter.Filter) {
	setStringField(fields, fieldSyscall, filter.Syscall)
	setStringField(fields, fieldComm, filter.Comm)
	setStringField(fields, fieldFile, filter.File)
	setNumericField(fields, fieldPID, filter.PID, false)
	setNumericField(fields, fieldTID, filter.TID, false)
	setNumericField(fields, fieldFD, filter.FD, false)
	setNumericField(fields, fieldLatency, filter.LatencyNs, true)
	setNumericField(fields, fieldGap, filter.GapNs, true)
	setNumericField(fields, fieldBytes, filter.Bytes, false)
	setNumericField(fields, fieldReturn, filter.RetVal, false)
	if filter.ErrorsOnly {
		fields[fieldErrorsOnly].value = "true"
	} else {
		fields[fieldErrorsOnly].value = "false"
	}
}

func setStringField(fields []filterField, key fieldKey, filter *globalfilter.StringFilter) {
	if filter == nil {
		fields[key].value = ""
		return
	}
	fields[key].value = filter.Pattern
}

func setNumericField(fields []filterField, key fieldKey, filter *globalfilter.NumericFilter, duration bool) {
	if filter == nil {
		fields[key].value = ""
		fields[key].opIndex = 2
		return
	}
	fields[key].opIndex = opToIndex(filter.Op)
	if duration {
		fields[key].value = formatDurationField(filter.Value)
		return
	}
	fields[key].value = strconv.FormatInt(filter.Value, 10)
}

func formatDurationField(value int64) string {
	if value%1_000_000 == 0 {
		return fmt.Sprintf("%dms", value/1_000_000)
	}
	if value%1_000 == 0 {
		return fmt.Sprintf("%dus", value/1_000)
	}
	return fmt.Sprintf("%dns", value)
}

func opToIndex(op globalfilter.CompareOp) int {
	for i, candidate := range compareOps {
		if candidate == op {
			return i
		}
	}
	return 2
}

func (m Model) isNumericField(index int) bool {
	if index < 0 || index >= len(m.fields) {
		return false
	}
	return m.isNumericFieldByKey(m.fields[index].fieldKey)
}

func (m Model) isNumericFieldByKey(key fieldKey) bool {
	switch key {
	case fieldPID, fieldTID, fieldFD, fieldLatency, fieldGap, fieldBytes, fieldReturn:
		return true
	default:
		return false
	}
}

func defaultFilterFields() []filterField {
	fields := []filterField{
		{label: "Syscall", fieldKey: fieldSyscall},
		{label: "Comm", fieldKey: fieldComm},
		{label: "File", fieldKey: fieldFile},
		{label: "PID", fieldKey: fieldPID},
		{label: "TID", fieldKey: fieldTID},
		{label: "FD", fieldKey: fieldFD},
		{label: "Latency", fieldKey: fieldLatency},
		{label: "Gap", fieldKey: fieldGap},
		{label: "Bytes", fieldKey: fieldBytes},
		{label: "Return", fieldKey: fieldReturn},
		{label: "Errors", fieldKey: fieldErrorsOnly, value: "false"},
	}
	for i := range fields {
		if fields[i].fieldKey != fieldErrorsOnly {
			fields[i].opIndex = 2
		}
	}
	return fields
}
