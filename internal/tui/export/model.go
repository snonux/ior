package export

import (
	"errors"
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Option is a selectable export target.
type Option int

const (
	// OptionCSV exports the filtered stream snapshot as CSV.
	OptionCSV Option = iota
	// OptionCancel dismisses the modal without exporting.
	OptionCancel
)

var optionLabels = []string{
	"CSV stream rows",
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
	// livePaused is set when the modal was opened while the stream tab is
	// paused. The export always snapshots the live ring, so the table the user
	// is looking at (the frozen rows) differs from what gets written; the
	// modal says so and points at the stream tab's x/X, which write the frozen
	// rows (task 2r2).
	livePaused bool
}

// PausedNote is shown in the modal while the stream is paused.
const PausedNote = "Live ring, not the paused view - use x for the paused rows"

// NewModel creates a closed export modal.
func NewModel() Model {
	return Model{}
}

// Visible reports whether the export modal is shown.
func (m Model) Visible() bool { return m.visible }

// Open shows the export modal with the CSV option preselected, for a live
// (not paused) stream.
func (m Model) Open() Model {
	return m.OpenFor(false)
}

// OpenFor is Open for a stream tab that is paused (streamPaused true) or live.
// While paused the modal adds PausedNote: the export writes the live ring's
// current rows, which are not the frozen rows on screen.
func (m Model) OpenFor(streamPaused bool) Model {
	m.livePaused = streamPaused
	m.visible = true
	m.selected = 0
	m.exporting = false
	m.status = ""
	return m
}

// Close hides the export modal and clears its status.
func (m Model) Close() Model {
	m.visible = false
	m.exporting = false
	m.status = ""
	return m
}

// Update handles modal key navigation and export completion messages.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.handleKeyMsg(msg)
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

// handleKeyMsg processes key presses when the modal is visible. It delegates
// to the export-in-progress handler or the navigation handler as appropriate.
func (m Model) handleKeyMsg(msg tea.KeyPressMsg) (Model, tea.Cmd) {
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

	lines := []string{"Export Stream CSV"}
	for i, label := range optionLabels {
		prefix := "  "
		if i == m.selected && !m.exporting {
			prefix = "> "
		}
		lines = append(lines, prefix+label)
	}
	if m.livePaused {
		lines = append(lines, "", PausedNote)
	}
	if m.status != "" {
		// The status echoes the export path and error text; sanitise it.
		lines = append(lines, "", common.Sanitize(m.status))
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
