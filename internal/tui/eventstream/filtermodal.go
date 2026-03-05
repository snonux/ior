package eventstream

import (
	"fmt"
	"strconv"
	"strings"

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

type FilterModal struct {
	visible     bool
	fields      []filterField
	activeField int
	editing     bool
	textInput   textinput.Model
	filter      Filter
}

var compareOps = []CompareOp{OpGt, OpLt, OpEq, OpGte, OpLte, OpNeq}
var compareOpLabels = []string{">", "<", "=", ">=", "<=", "!="}

func NewFilterModal() FilterModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(24)

	m := FilterModal{textInput: input}
	m.fields = defaultFilterFields()
	return m
}

func (m FilterModal) Visible() bool {
	return m.visible
}

func (m FilterModal) Filter() Filter {
	return m.filter
}

func (m FilterModal) Open(initial Filter) FilterModal {
	m.visible = true
	m.activeField = 0
	m.editing = false
	m.textInput.Blur()
	m.fields = defaultFilterFields()
	m.applyFilterToFields(initial)
	m.filter = initial
	return m
}

func (m FilterModal) Close() FilterModal {
	m.visible = false
	m.editing = false
	m.textInput.Blur()
	return m
}

func (m FilterModal) Update(msg tea.Msg) FilterModal {
	if !m.visible {
		return m
	}

	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			if m.editing {
				m.commitEdit()
			}
			m.filter = m.buildFilterFromFields()
			return m.Close()
		case "c":
			m.clearAll()
			return m
		case "j", "down":
			if !m.editing && m.activeField < len(m.fields)-1 {
				m.activeField++
			}
			return m
		case "k", "up":
			if !m.editing && m.activeField > 0 {
				m.activeField--
			}
			return m
		case "tab":
			if !m.editing && m.isNumericField(m.activeField) {
				m.fields[m.activeField].opIndex = (m.fields[m.activeField].opIndex + 1) % len(compareOps)
			}
			return m
		case " ", "space":
			if !m.editing && m.fields[m.activeField].fieldKey == fieldErrorsOnly {
				if strings.TrimSpace(m.fields[m.activeField].value) == "true" {
					m.fields[m.activeField].value = "false"
				} else {
					m.fields[m.activeField].value = "true"
				}
			}
			return m
		case "enter":
			if m.fields[m.activeField].fieldKey == fieldErrorsOnly {
				if strings.TrimSpace(m.fields[m.activeField].value) == "true" {
					m.fields[m.activeField].value = "false"
				} else {
					m.fields[m.activeField].value = "true"
				}
				return m
			}
			if m.editing {
				m.commitEdit()
				return m
			}
			m.startEdit()
			return m
		}
	}

	if m.editing {
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		_ = cmd
	}
	return m
}

func (m FilterModal) View(width, height int) string {
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
	for i, f := range m.fields {
		prefix := "  "
		if i == m.activeField {
			prefix = "> "
		}
		lines = append(lines, prefix+m.renderField(f, i == m.activeField))
	}
	lines = append(lines, "", "j/k move • Enter edit/apply • Tab op • Space toggle errors • c clear • Esc apply+close")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func (m *FilterModal) clearAll() {
	for i := range m.fields {
		m.fields[i].value = ""
		if m.isNumericField(i) {
			m.fields[i].opIndex = 2
		}
	}
	m.fields[len(m.fields)-1].value = "false"
	m.editing = false
	m.textInput.Blur()
}

func (m *FilterModal) startEdit() {
	m.editing = true
	m.textInput.SetValue(m.fields[m.activeField].value)
	m.textInput.CursorEnd()
	m.textInput.Focus()
}

func (m *FilterModal) commitEdit() {
	m.fields[m.activeField].value = strings.TrimSpace(m.textInput.Value())
	m.editing = false
	m.textInput.Blur()
}

func (m FilterModal) renderField(f filterField, active bool) string {
	if f.fieldKey == fieldErrorsOnly {
		checked := "[ ]"
		if strings.TrimSpace(f.value) == "true" {
			checked = "[x]"
		}
		return fmt.Sprintf("%-8s %s", f.label+":", checked)
	}

	value := f.value
	if active && m.editing {
		value = m.textInput.View()
	}
	if f.fieldKey == fieldLatency || f.fieldKey == fieldGap || m.isNumericFieldByKey(f.fieldKey) {
		return fmt.Sprintf("%-8s [%2s] %s", f.label+":", compareOpLabels[f.opIndex], value)
	}
	return fmt.Sprintf("%-8s %s", f.label+":", value)
}

func (m FilterModal) buildFilterFromFields() Filter {
	out := Filter{}
	for _, f := range m.fields {
		value := strings.TrimSpace(f.value)
		switch f.fieldKey {
		case fieldSyscall:
			if value != "" {
				out.Syscall = &StringFilter{Pattern: value}
			}
		case fieldComm:
			if value != "" {
				out.Comm = &StringFilter{Pattern: value}
			}
		case fieldFile:
			if value != "" {
				out.File = &StringFilter{Pattern: value}
			}
		case fieldPID:
			if nf, ok := parseNumericFilter(value, f.opIndex, false); ok {
				out.PID = nf
			}
		case fieldTID:
			if nf, ok := parseNumericFilter(value, f.opIndex, false); ok {
				out.TID = nf
			}
		case fieldLatency:
			if nf, ok := parseNumericFilter(value, f.opIndex, true); ok {
				out.LatencyNs = nf
			}
		case fieldGap:
			if nf, ok := parseNumericFilter(value, f.opIndex, true); ok {
				out.GapNs = nf
			}
		case fieldBytes:
			if nf, ok := parseNumericFilter(value, f.opIndex, false); ok {
				out.Bytes = nf
			}
		case fieldReturn:
			if nf, ok := parseNumericFilter(value, f.opIndex, false); ok {
				out.RetVal = nf
			}
		case fieldErrorsOnly:
			out.ErrorsOnly = strings.EqualFold(value, "true")
		}
	}
	return out
}

func parseNumericFilter(value string, opIndex int, duration bool) (*NumericFilter, bool) {
	if value == "" {
		return nil, false
	}
	if opIndex < 0 || opIndex >= len(compareOps) {
		opIndex = 2
	}

	var n int64
	var err error
	if duration {
		n, err = ParseDurationNs(value)
	} else {
		n, err = strconv.ParseInt(value, 10, 64)
	}
	if err != nil {
		return nil, false
	}
	return &NumericFilter{Op: compareOps[opIndex], Value: n}, true
}

func (m *FilterModal) applyFilterToFields(f Filter) {
	m.setStringField(fieldSyscall, f.Syscall)
	m.setStringField(fieldComm, f.Comm)
	m.setStringField(fieldFile, f.File)
	m.setNumericField(fieldPID, f.PID, false)
	m.setNumericField(fieldTID, f.TID, false)
	m.setNumericField(fieldLatency, f.LatencyNs, true)
	m.setNumericField(fieldGap, f.GapNs, true)
	m.setNumericField(fieldBytes, f.Bytes, false)
	m.setNumericField(fieldReturn, f.RetVal, false)
	if f.ErrorsOnly {
		m.fields[fieldErrorsOnly].value = "true"
	} else {
		m.fields[fieldErrorsOnly].value = "false"
	}
}

func (m *FilterModal) setStringField(k fieldKey, sf *StringFilter) {
	if sf == nil {
		m.fields[k].value = ""
		return
	}
	m.fields[k].value = sf.Pattern
}

func (m *FilterModal) setNumericField(k fieldKey, nf *NumericFilter, duration bool) {
	if nf == nil {
		m.fields[k].value = ""
		m.fields[k].opIndex = 2
		return
	}
	m.fields[k].opIndex = opToIndex(nf.Op)
	if duration {
		m.fields[k].value = formatDurationField(nf.Value)
		return
	}
	m.fields[k].value = strconv.FormatInt(nf.Value, 10)
}

func formatDurationField(v int64) string {
	if v%1_000_000 == 0 {
		return fmt.Sprintf("%dms", v/1_000_000)
	}
	if v%1_000 == 0 {
		return fmt.Sprintf("%dus", v/1_000)
	}
	return fmt.Sprintf("%dns", v)
}

func opToIndex(op CompareOp) int {
	for i, o := range compareOps {
		if o == op {
			return i
		}
	}
	return 2
}

func (m FilterModal) isNumericField(i int) bool {
	if i < 0 || i >= len(m.fields) {
		return false
	}
	return m.isNumericFieldByKey(m.fields[i].fieldKey)
}

func (m FilterModal) isNumericFieldByKey(k fieldKey) bool {
	switch k {
	case fieldPID, fieldTID, fieldLatency, fieldGap, fieldBytes, fieldReturn:
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
