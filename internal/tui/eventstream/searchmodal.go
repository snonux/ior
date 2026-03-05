package eventstream

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type SearchDirection int

const (
	SearchForward  SearchDirection = 1
	SearchBackward SearchDirection = -1
)

type SearchModal struct {
	visible   bool
	textInput textinput.Model
	err       string
	direction SearchDirection
}

func NewSearchModal() SearchModal {
	input := textinput.New()
	input.Prompt = ""
	input.CharLimit = 0
	input.SetWidth(44)
	input.SetStyles(textinput.DefaultStyles(true))
	return SearchModal{textInput: input, direction: SearchForward}
}

func (m SearchModal) Visible() bool {
	return m.visible
}

func (m SearchModal) Direction() SearchDirection {
	return m.direction
}

// SetDarkMode updates search modal text input styles.
func (m SearchModal) SetDarkMode(isDark bool) SearchModal {
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

func (m SearchModal) Open(direction SearchDirection, defaultTerm string) SearchModal {
	m.visible = true
	m.err = ""
	m.direction = direction
	m.textInput.SetValue(defaultTerm)
	m.textInput.CursorEnd()
	m.textInput.Focus()
	return m
}

func (m SearchModal) Close() SearchModal {
	m.visible = false
	m.err = ""
	m.textInput.Blur()
	return m
}

// Update returns updated modal, submitted term, and whether submit occurred.
func (m SearchModal) Update(msg tea.Msg) (SearchModal, string, bool) {
	if !m.visible {
		return m, "", false
	}
	if keyMsg, ok := msg.(tea.KeyPressMsg); ok {
		switch keyMsg.String() {
		case "esc":
			return m.Close(), "", false
		case "enter":
			term := strings.TrimSpace(m.textInput.Value())
			if term == "" {
				m.err = "search term is required"
				return m, "", false
			}
			return m.Close(), term, true
		}
	}
	var cmd tea.Cmd
	m.textInput, cmd = m.textInput.Update(msg)
	_ = cmd
	return m, "", false
}

func (m SearchModal) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	modalWidth := 58
	if width < modalWidth+4 {
		modalWidth = width - 4
		if modalWidth < 40 {
			modalWidth = 40
		}
	}

	prefix := "/"
	if m.direction == SearchBackward {
		prefix = "?"
	}
	lines := []string{
		"Regex Search",
		"",
		"Pattern:",
		prefix + m.textInput.View(),
	}
	if m.err != "" {
		lines = append(lines, "Error: "+m.err)
	}
	lines = append(lines, "", "Enter search • Esc cancel")

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
