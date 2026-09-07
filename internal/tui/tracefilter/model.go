package tracefilter

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/parser"

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
	visible     bool
	fields      []filterField
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

func (m Model) Visible() bool {
	return m.visible
}

func (m Model) Filter() globalfilter.Filter {
	return m.filter
}

func (m Model) SetDarkMode(isDark bool) Model {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

func (m Model) Open(initial globalfilter.Filter) Model {
	m.visible = true
	m.activeField = 0
	m.editing = false
	m.textInput.Blur()
	m.fields = defaultFilterFields()
	applyFilterToFields(m.fields, initial)
	m.filter = initial.Clone()
	return m
}

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

	lines := []string{"Filter"}
	for i, field := range m.fields {
		prefix := "  "
		if i == m.activeField {
			prefix = "> "
		}
		lines = append(lines, prefix+m.renderField(field, i == m.activeField))
	}
	lines = append(lines, "", "j/k move • Enter edit/apply • Tab op • Space toggle errors • c clear • Esc apply+close")
	lines = append(lines, "strings: substring by default, use ^prefix, suffix$, or ^exact$")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
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

	value := field.value
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
func (m Model) buildFilterFromFields() globalfilter.Filter {
	var out globalfilter.Filter
	for _, field := range m.fields {
		value := strings.TrimSpace(field.value)
		applyFieldToFilter(field, value, &out)
	}
	return out
}

// applyFieldToFilter writes a single field value into the appropriate slot of
// out. It is split out of buildFilterFromFields to keep each function concise.
func applyFieldToFilter(field filterField, value string, out *globalfilter.Filter) {
	switch field.fieldKey {
	case fieldSyscall:
		if value != "" {
			out.Syscall = &globalfilter.StringFilter{Pattern: value}
		}
	case fieldComm:
		if value != "" {
			out.Comm = &globalfilter.StringFilter{Pattern: value}
		}
	case fieldFile:
		if value != "" {
			out.File = &globalfilter.StringFilter{Pattern: value}
		}
	case fieldPID:
		if f, ok := parseNumericFilter(value, field.opIndex, false); ok {
			out.PID = f
		}
	case fieldTID:
		if f, ok := parseNumericFilter(value, field.opIndex, false); ok {
			out.TID = f
		}
	case fieldFD:
		if f, ok := parseNumericFilter(value, field.opIndex, false); ok {
			out.FD = f
		}
	case fieldLatency:
		if f, ok := parseNumericFilter(value, field.opIndex, true); ok {
			out.LatencyNs = f
		}
	case fieldGap:
		if f, ok := parseNumericFilter(value, field.opIndex, true); ok {
			out.GapNs = f
		}
	case fieldBytes:
		if f, ok := parseNumericFilter(value, field.opIndex, false); ok {
			out.Bytes = f
		}
	case fieldReturn:
		if f, ok := parseNumericFilter(value, field.opIndex, false); ok {
			out.RetVal = f
		}
	case fieldErrorsOnly:
		out.ErrorsOnly = strings.EqualFold(value, "true")
	}
}

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
