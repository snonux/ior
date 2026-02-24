package export

import (
	"errors"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Option is a selectable export target.
type Option int

const (
	OptionFlamegraph Option = iota
	OptionCSV
	OptionCancel
)

var optionLabels = []string{
	"CSV snapshot",
	"Cancel",
}

var optionValues = []Option{
	OptionCSV,
	OptionCancel,
}

// RequestMsg asks the parent model to perform an export.
type RequestMsg struct {
	Option Option
}

// CompletedMsg reports a finished export with output path.
type CompletedMsg struct {
	Path string
}

// FailedMsg reports an export error.
type FailedMsg struct {
	Err error
}

// Model is the export modal state machine.
type Model struct {
	visible   bool
	selected  int
	exporting bool
	status    string
}

// NewModel creates a closed export modal.
func NewModel() Model {
	return Model{}
}

func (m Model) Visible() bool { return m.visible }

func (m Model) Open() Model {
	m.visible = true
	m.selected = 0
	m.exporting = false
	m.status = ""
	return m
}

func (m Model) Close() Model {
	m.visible = false
	m.exporting = false
	m.status = ""
	return m
}

// Update handles modal key navigation and export completion messages.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if !m.visible {
			return m, nil
		}
		if m.exporting {
			if msg.String() == "esc" {
				return m.Close(), nil
			}
			return m, nil
		}

		switch msg.String() {
		case "esc":
			return m.Close(), nil
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
			return m, nil
		case "down", "j":
			if m.selected < len(optionValues)-1 {
				m.selected++
			}
			return m, nil
		case "enter":
			option := optionValues[m.selected]
			if option == OptionCancel {
				return m.Close(), nil
			}
			m.exporting = true
			m.status = fmt.Sprintf("Exporting %s...", optionLabels[m.selected])
			return m, func() tea.Msg { return RequestMsg{Option: option} }
		}
	case CompletedMsg:
		m.exporting = false
		if msg.Path == "" {
			msg.Path = "done"
		}
		m.status = "Exported: " + msg.Path
		return m, nil
	case FailedMsg:
		m.exporting = false
		if msg.Err == nil {
			msg.Err = errors.New("unknown export failure")
		}
		m.status = "Export failed: " + msg.Err.Error()
		return m, nil
	}

	return m, nil
}

// View renders a centered modal overlay.
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

	modalWidth := 48
	if width < modalWidth+4 {
		modalWidth = width - 4
		if modalWidth < 30 {
			modalWidth = 30
		}
	}

	lines := []string{"Export"}
	for i, label := range optionLabels {
		prefix := "  "
		if i == m.selected && !m.exporting {
			prefix = "> "
		}
		lines = append(lines, prefix+label)
	}
	if m.status != "" {
		lines = append(lines, "", m.status)
	}
	if !m.exporting {
		lines = append(lines, "", "Enter confirm • Esc cancel")
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
