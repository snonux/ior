package pidpicker

import (
	"fmt"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
	"strings"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const allPIDsLabel = "All PIDs"
const allTIDsLabel = "All TIDs"

type PickerMode int

const (
	PickerModePID PickerMode = iota
	PickerModeTID
)

// KeyMap defines picker-specific key bindings.
type KeyMap struct {
	Enter   key.Binding
	Esc     key.Binding
	Refresh key.Binding
}

// DefaultKeyMap returns picker defaults.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Enter:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		Esc:     key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Refresh: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "refresh")),
	}
}

func (k KeyMap) PickerShortHelp() []key.Binding {
	return []key.Binding{k.Enter, k.Refresh, k.Esc}
}

var (
	screenStyle    = common.ScreenStyle
	headerStyle    = common.HeaderStyle
	helpBarStyle   = common.HelpBarStyle
	highlightStyle = common.HighlightStyle
	errorStyle     = common.ErrorStyle
)

func syncPickerStyles() {
	screenStyle = common.ScreenStyle
	headerStyle = common.HeaderStyle
	helpBarStyle = common.HelpBarStyle
	highlightStyle = common.HighlightStyle
	errorStyle = common.ErrorStyle
}

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
	mode          PickerMode
	targetPID     int
	width         int
	height        int
	keys          KeyMap
	lastErr       error
	isDark        bool
}

// New creates a PID picker model with default shared key bindings.
func New() Model {
	return NewPIDWithKeys(DefaultKeyMap())
}

// NewWithKeys creates a PID picker model with the provided key bindings.
func NewWithKeys(keys KeyMap) Model {
	return NewPIDWithKeys(keys)
}

// NewPIDWithKeys creates a PID picker model with the provided key bindings.
func NewPIDWithKeys(keys KeyMap) Model {
	syncPickerStyles()
	input := textinput.New()
	input.Prompt = "Filter: "
	input.Placeholder = "pid, comm, or cmdline"
	input.Focus()
	input.CharLimit = 0
	input.SetWidth(40)
	input.SetStyles(textinput.DefaultStyles(true))

	return Model{
		input:     input,
		keys:      keys,
		filtered:  []ProcessInfo{},
		mode:      PickerModePID,
		targetPID: -1,
		isDark:    true,
	}
}

// NewTIDWithKeys creates a TID picker model scoped to one PID.
func NewTIDWithKeys(targetPID int, keys KeyMap) Model {
	m := NewPIDWithKeys(keys)
	m.mode = PickerModeTID
	m.targetPID = targetPID
	m.input.Placeholder = "tid, comm, or cmdline"
	return m
}

// Init starts the initial process scan.
func (m Model) Init() tea.Cmd {
	return m.scanCmd()
}

// Update handles key presses and async process-scan responses.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.input.SetWidth(clamp(msg.Width-16, 10, 100))
		return m, nil
	case processesLoadedMsg:
		m.processes = msg.processes
		m.lastErr = msg.err
		m.applyFilter()
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m Model) updateKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Esc):
		return m, tea.Quit
	case msg.Key().Mod&tea.ModCtrl != 0 && (msg.Key().Code == 'r' || msg.Key().Code == 'R'):
		return m, m.scanCmd()
	case key.Matches(msg, m.keys.Enter):
		return m, m.emitSelection()
	case msg.Key().Code == tea.KeyUp:
		if m.selectedIndex > 0 {
			m.selectedIndex--
		}
		m.input.Blur()
		return m, nil
	case msg.Key().Code == tea.KeyDown:
		maxIndex := len(m.filtered)
		if m.selectedIndex < maxIndex {
			m.selectedIndex++
		}
		m.input.Blur()
		return m, nil
	}

	if msg.Key().Text != "" && !m.input.Focused() {
		if key.Matches(msg, m.keys.Refresh) {
			return m, m.scanCmd()
		}
		m.input.Focus()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m.applyFilter()
	return m, cmd
}

func (m Model) emitSelection() tea.Cmd {
	if m.mode == PickerModeTID {
		if m.selectedIndex <= 0 {
			return func() tea.Msg { return messages.TidSelectedMsg{Pid: 0, Tid: 0} }
		}
		idx := m.selectedIndex - 1
		if idx < 0 || idx >= len(m.filtered) {
			return func() tea.Msg { return messages.TidSelectedMsg{Pid: 0, Tid: 0} }
		}
		thread := m.filtered[idx]
		return func() tea.Msg { return messages.TidSelectedMsg{Pid: thread.ParentPID, Tid: thread.Pid} }
	}

	if m.selectedIndex <= 0 {
		return func() tea.Msg { return messages.PidSelectedMsg{Pid: 0} }
	}

	idx := m.selectedIndex - 1
	if idx < 0 || idx >= len(m.filtered) {
		return func() tea.Msg { return messages.PidSelectedMsg{Pid: 0} }
	}

	pid := m.filtered[idx].Pid
	return func() tea.Msg { return messages.PidSelectedMsg{Pid: pid} }
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
func (m Model) View() tea.View {
	var b strings.Builder
	if m.mode == PickerModeTID {
		if m.targetPID > 0 {
			b.WriteString(headerStyle.Render(fmt.Sprintf("Select TID for PID %d", m.targetPID)))
		} else {
			b.WriteString(headerStyle.Render("Select TID"))
		}
	} else {
		b.WriteString(headerStyle.Render("Select PID"))
	}
	b.WriteString("\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")

	rows := m.renderRows()
	b.WriteString(rows)

	if m.lastErr != nil {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render("scan error: " + m.lastErr.Error()))
	}

	b.WriteString("\n")
	b.WriteString(helpBarStyle.Render(renderHelp(m.keys.PickerShortHelp())))
	return tea.NewView(screenStyle.Render(b.String()))
}

// SetDarkMode updates picker theme and text input styles.
func (m Model) SetDarkMode(isDark bool) Model {
	m.isDark = isDark
	syncPickerStyles()
	m.input.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

func (m Model) renderRows() string {
	lines := make([]string, 0, len(m.filtered)+1)
	allLabel := allPIDsLabel
	if m.mode == PickerModeTID {
		allLabel = allTIDsLabel
	}
	lines = append(lines, m.renderRow(0, allLabel))
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
		style = highlightStyle
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

func (m Model) scanCmd() tea.Cmd {
	if m.mode == PickerModeTID {
		if m.targetPID <= 0 {
			return func() tea.Msg {
				processes, err := ScanAllThreads()
				return processesLoadedMsg{
					processes: processes,
					err:       err,
				}
			}
		}
		return func() tea.Msg {
			processes, err := ScanThreads(m.targetPID)
			return processesLoadedMsg{
				processes: processes,
				err:       err,
			}
		}
	}
	return scanProcessesCmd
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
	if process.ParentPID > 0 && process.ParentPID != process.Pid {
		if process.Cmdline == "" {
			return fmt.Sprintf("%d (pid:%d)  %s", process.Pid, process.ParentPID, process.Comm)
		}
		return fmt.Sprintf("%d (pid:%d)  %s  %s", process.Pid, process.ParentPID, process.Comm, process.Cmdline)
	}
	if process.Cmdline == "" {
		return fmt.Sprintf("%d  %s", process.Pid, process.Comm)
	}
	return fmt.Sprintf("%d  %s  %s", process.Pid, process.Comm, process.Cmdline)
}
