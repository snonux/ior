package eventstream

import (
	"strings"

	"ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// ExportModal is the stream tab's filename-entry modal for CSV export.
// Like the sibling modals it is value-flow: every mutator returns the
// updated ExportModal.
type ExportModal struct {
	visible   bool
	textInput textinput.Model
	err       string
}

// NewExportModal constructs a dark-mode export modal with an empty input.
func NewExportModal() ExportModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(44)
	input.SetStyles(textinput.DefaultStyles(true))
	return ExportModal{textInput: input}
}

// Visible reports whether the modal is shown.
func (m ExportModal) Visible() bool {
	return m.visible
}

// SetDarkMode updates export modal text input styles.
func (m ExportModal) SetDarkMode(isDark bool) ExportModal {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// Open shows the modal with defaultName pre-filled and focused.
func (m ExportModal) Open(defaultName string) ExportModal {
	m.visible = true
	m.err = ""
	m.textInput.SetValue(defaultName)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

// Close hides the modal; the entered filename stays in the input and is
// replaced by the next Open.
func (m ExportModal) Close() ExportModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

// Reject reopens the modal with the rejected filename still in the input and
// err shown as its error, so a name the export refused (empty after trimming,
// a directory, a missing folder, ...) can be corrected instead of retyped.
//
// Close leaves the typed text and the cursor in the input, so when the input
// still holds filename (modulo the surrounding space Update trimmed off) it
// is reopened untouched and the cursor stays where the user left it, in the
// middle of the name if that is where they were editing. Only for any other
// filename is the input replaced, via Open, with the cursor at the end.
func (m ExportModal) Reject(filename string, err error) ExportModal {
	if strings.TrimSpace(m.textInput.Value()) != filename {
		m = m.Open(filename)
	}
	m.visible = true
	m.textInput.Focus()
	m.err = err.Error()
	return m
}

// Update returns updated modal, submitted filename, and whether submit occurred.
//
// An error (the empty-name message here, or the reason a Reject gave) stays
// until the user edits the text: it describes the name that was submitted, so
// the first keystroke that changes the input makes it stale and clears it.
// Cursor movement alone leaves it, as the name is still the rejected one.
func (m ExportModal) Update(msg tea.Msg) (ExportModal, string, bool) {
	if !m.visible {
		return m, "", false
	}
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			return m.Close(), "", false
		case "enter":
			filename := strings.TrimSpace(m.textInput.Value())
			if filename == "" {
				m.err = "filename is required"
				return m, "", false
			}
			return m.Close(), filename, true
		}
	}
	before := m.textInput.Value()
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	_ = cmd
	if m.textInput.Value() != before {
		m.err = ""
	}
	return m, "", false
}

// View renders the centered modal box within the given viewport.
func (m ExportModal) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	modalWidth := 74
	if width < modalWidth+4 {
		modalWidth = width - 4
		if modalWidth < 44 {
			modalWidth = 44
		}
	}

	lines := []string{
		"Export Stream CSV",
		"",
		"Filename:",
		m.textInput.View(),
	}
	if m.err != "" {
		lines = append(lines, "Error: "+common.Sanitize(m.err))
	}
	lines = append(lines, "", "Enter save • Esc cancel")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
