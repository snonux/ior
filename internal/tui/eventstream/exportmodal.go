package eventstream

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type ExportModal struct {
	visible   bool
	textInput textinput.Model
	err       string
}

func NewExportModal() ExportModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(44)
	return ExportModal{textInput: input}
}

func (m ExportModal) Visible() bool {
	return m.visible
}

func (m ExportModal) Open(defaultName string) ExportModal {
	m.visible = true
	m.err = ""
	m.textInput.SetValue(defaultName)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

func (m ExportModal) Close() ExportModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

// Update returns updated modal, submitted filename, and whether submit occurred.
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
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	_ = cmd
	return m, "", false
}

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
		lines = append(lines, "Error: "+m.err)
	}
	lines = append(lines, "", "Enter save • Esc cancel")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
