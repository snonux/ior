package tui

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type recordingModal struct {
	visible   bool
	textInput textinput.Model
	err       string
}

func newRecordingModal() recordingModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(44)
	input.SetStyles(textinput.DefaultStyles(true))
	return recordingModal{textInput: input}
}

func (m recordingModal) Visible() bool {
	return m.visible
}

func (m recordingModal) SetDarkMode(isDark bool) recordingModal {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

func (m recordingModal) Open(defaultPath string) recordingModal {
	m.visible = true
	m.err = ""
	m.textInput.SetValue(defaultPath)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

func (m recordingModal) Close() recordingModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

func (m recordingModal) SetError(err error) recordingModal {
	if err == nil {
		m.err = ""
		return m
	}
	m.err = err.Error()
	m.visible = true
	m.textInput.Focus()
	return m
}

func (m recordingModal) Update(msg tea.Msg) (recordingModal, string, bool) {
	if !m.visible {
		return m, "", false
	}
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			return m.Close(), "", false
		case "enter":
			path := strings.TrimSpace(m.textInput.Value())
			if path == "" {
				m.err = "filename is required"
				return m, "", false
			}
			return m, path, true
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	_ = cmd
	return m, "", false
}

func (m recordingModal) View(width, height int) string {
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
		"Start Parquet Recording",
		"",
		"Filename:",
		m.textInput.View(),
	}
	if m.err != "" {
		lines = append(lines, "Error: "+m.err)
	}
	lines = append(lines, "", "Enter start • Esc cancel")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
