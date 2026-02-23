package pidpicker

import (
	"fmt"
	"ior/internal/tui"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const allPIDsLabel = "All PIDs"

type processesLoadedMsg struct {
	processes []ProcessInfo
	err       error
}

// Model is the Bubble Tea model for the PID picker screen.
type Model struct {
	input         textinput.Model
	processes     []ProcessInfo
	filtered      []ProcessInfo
	selectedIndex int
	width         int
	height        int
	keys          tui.KeyMap
	lastErr       error
}

// New creates a PID picker model with default shared key bindings.
func New() Model {
	return NewWithKeys(tui.Keys)
}

// NewWithKeys creates a PID picker model with the provided key bindings.
func NewWithKeys(keys tui.KeyMap) Model {
	input := textinput.New()
	input.Prompt = "Filter: "
	input.Placeholder = "pid, comm, or cmdline"
	input.Focus()
	input.CharLimit = 0
	input.Width = 40

	return Model{
		input:    input,
		keys:     keys,
		filtered: []ProcessInfo{},
	}
}

// Init starts the initial process scan.
func (m Model) Init() tea.Cmd {
	return scanProcessesCmd
}

// Update handles key presses and async process-scan responses.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.Width = clamp(msg.Width-16, 10, 100)
		return m, nil
	case processesLoadedMsg:
		m.processes = msg.processes
		m.lastErr = msg.err
		m.applyFilter()
		return m, nil
	case tea.KeyMsg:
		return m.updateKey(msg)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m Model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Esc):
		return m, tea.Quit
	case msg.Type == tea.KeyCtrlR:
		return m, scanProcessesCmd
	case key.Matches(msg, m.keys.Enter):
		return m, m.emitSelection()
	case msg.Type == tea.KeyUp:
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}
		m.input.Blur()
		return m, nil
	case msg.Type == tea.KeyDown:
		maxIndex := len(m.filtered)
		if m.selectedIndex < maxIndex {
			m.selectedIndex++
		}
		m.input.Blur()
		return m, nil
	}

	if msg.Type == tea.KeyRunes && !m.input.Focused() {
		if key.Matches(msg, m.keys.Refresh) {
			return m, scanProcessesCmd
		}
		m.input.Focus()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m Model) emitSelection() tea.Cmd {
	if m.selectedIndex <= 0 {
		return func() tea.Msg { return tui.PidSelectedMsg{Pid: 0} }
	}

	idx := m.selectedIndex - 1
	if idx < 0 || idx >= len(m.filtered) {
		return func() tea.Msg { return tui.PidSelectedMsg{Pid: 0} }
	}

	pid := m.filtered[idx].Pid
	return func() tea.Msg { return tui.PidSelectedMsg{Pid: pid} }
}

func (m *Model) applyFilter() {
	query := strings.TrimSpace(strings.ToLower(m.input.Value()))
	if query == "" {
		m.filtered = cloneProcesses(m.processes)
		if m.selectedIndex > len(m.filtered) {
			m.selectedIndex = len(m.filtered)
		}
		return
	}

	filtered := make([]ProcessInfo, 0, len(m.processes))
	for _, process := range m.processes {
		if matchesQuery(process, query) {
			filtered = append(filtered, process)
		}
	}

	m.filtered = filtered
	if m.selectedIndex > len(m.filtered) {
		m.selectedIndex = len(m.filtered)
	}
}

func matchesQuery(process ProcessInfo, query string) bool {
	pidStr := fmt.Sprintf("%d", process.Pid)
	if strings.Contains(strings.ToLower(pidStr), query) {
		return true
	}
	if strings.Contains(strings.ToLower(process.Comm), query) {
		return true
	}
	return strings.Contains(strings.ToLower(process.Cmdline), query)
}

func cloneProcesses(in []ProcessInfo) []ProcessInfo {
	if len(in) == 0 {
		return []ProcessInfo{}
	}
	out := make([]ProcessInfo, len(in))
	copy(out, in)
	return out
}

// View renders the PID picker with filter input, list, and help bar.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(tui.HeaderStyle.Render("Select PID"))
	b.WriteString("\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")

	rows := m.renderRows()
	b.WriteString(rows)

	if m.lastErr != nil {
		b.WriteString("\n")
		b.WriteString(tui.ErrorStyle.Render("scan error: " + m.lastErr.Error()))
	}

	b.WriteString("\n")
	b.WriteString(tui.HelpBarStyle.Render(renderHelp(m.keys.PickerShortHelp())))
	return tui.ScreenStyle.Render(b.String())
}

func (m Model) renderRows() string {
	lines := make([]string, 0, len(m.filtered)+1)
	lines = append(lines, m.renderRow(0, allPIDsLabel))
	for i, process := range m.filtered {
		label := formatProcess(process)
		lines = append(lines, m.renderRow(i+1, label))
	}

	maxRows := m.visibleRows()
	if maxRows > 0 && len(lines) > maxRows {
		start := m.selectedIndex - (maxRows / 2)
		if start < 0 {
			start = 0
		}
		limit := len(lines) - maxRows
		if start > limit {
			start = limit
		}
		lines = lines[start : start+maxRows]
	}
	return strings.Join(lines, "\n")
}

func (m Model) renderRow(index int, label string) string {
	prefix := "  "
	style := lipgloss.NewStyle()
	if index == m.selectedIndex {
		prefix = "> "
		style = tui.HighlightStyle
	}
	return style.Render(prefix + label)
}

func (m Model) visibleRows() int {
	if m.height <= 0 {
		return 0
	}
	const reservedLines = 6
	rows := m.height - reservedLines
	if rows < 1 {
		return 1
	}
	return rows
}

func renderHelp(bindings []key.Binding) string {
	parts := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		help := binding.Help()
		parts = append(parts, fmt.Sprintf("%s %s", help.Key, help.Desc))
	}
	return strings.Join(parts, " • ")
}

func scanProcessesCmd() tea.Msg {
	processes, err := ScanProcesses()
	return processesLoadedMsg{
		processes: processes,
		err:       err,
	}
}

func clamp(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func formatProcess(process ProcessInfo) string {
	if process.Cmdline == "" {
		return fmt.Sprintf("%d  %s", process.Pid, process.Comm)
	}
	return fmt.Sprintf("%d  %s  %s", process.Pid, process.Comm, process.Cmdline)
}
