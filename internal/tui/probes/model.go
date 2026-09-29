package probes

import (
	"fmt"
	"strings"

	"ior/internal/probemanager"
	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Manager defines the probe operations used by the modal.
type Manager interface {
	States() []probemanager.ProbeState
	Toggle(syscall string) error
	ActiveCount() (int, int)
}

// ProbeToggledMsg reports completion of an async toggle operation.
type ProbeToggledMsg struct {
	Syscall string
	Err     error
}

// Model is the probe toggle modal state. It is value-flow: every method has a
// value receiver and every mutator returns the updated Model (see the TUI
// Model receiver policy in AGENTS.md).
type Model struct {
	visible bool
	probes  []probemanager.ProbeState

	cursor int
	offset int

	search    string
	searching bool
	textInput textinput.Model

	lastErr string
	manager Manager
	height  int
	isDark  bool
}

// NewModel constructs a probes modal listing manager's probe states.
func NewModel(manager Manager) Model {
	ti := textinput.New()
	ti.Prompt = "/ "
	ti.CharLimit = 0
	ti.SetWidth(28)
	ti.SetStyles(textinput.DefaultStyles(true))
	return Model{
		manager:   manager,
		textInput: ti,
		isDark:    true,
	}
}

// Visible reports whether the probes modal is shown.
func (m Model) Visible() bool { return m.visible }

// Open shows the probes modal and reloads the probe list.
func (m Model) Open() Model {
	m.visible = true
	m.searching = false
	m.lastErr = ""
	m.textInput.Blur()
	m = m.reload()
	m = m.clampCursor()
	return m
}

// Close hides the probes modal.
func (m Model) Close() Model {
	m.visible = false
	m.searching = false
	m.textInput.Blur()
	m.lastErr = ""
	return m
}

// SetDarkMode updates probe modal text input styles.
func (m Model) SetDarkMode(isDark bool) Model {
	m.isDark = isDark
	m.textInput.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// SetHeight records the terminal height the modal is rendered into so the
// scroll offset kept by Update matches the rows View will draw.
func (m Model) SetHeight(height int) Model {
	m.height = height
	return m.clampCursor()
}

// Update dispatches Bubble Tea messages to the appropriate handler.
// ProbeToggledMsg refreshes the probe list; key presses are forwarded to
// the search or navigation handlers.
func (m Model) Update(msg tea.Msg) (Model, tea.Cmd) {
	if !m.visible {
		return m, nil
	}
	switch msg := msg.(type) {
	case ProbeToggledMsg:
		return m.handleProbeToggled(msg)
	case tea.KeyPressMsg:
		if m.searching {
			return m.updateSearch(msg)
		}
		return m.handleKeyPress(msg)
	}
	return m, nil
}

// handleProbeToggled refreshes probe state after an async toggle completes.
func (m Model) handleProbeToggled(msg ProbeToggledMsg) (Model, tea.Cmd) {
	m = m.reload()
	if msg.Err != nil {
		m.lastErr = msg.Err.Error()
	} else {
		m.lastErr = ""
	}
	m = m.clampCursor()
	return m, nil
}

// handleKeyPress processes navigation and toggle keys while not in search mode.
func (m Model) handleKeyPress(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.Close(), nil
	case "j", "down":
		m.cursor++
		return m.clampCursor(), nil
	case "k", "up":
		m.cursor--
		return m.clampCursor(), nil
	case "/", "f":
		m.searching = true
		m.textInput.SetValue(m.search)
		m.textInput.CursorEnd()
		m.textInput.Focus()
		return m, nil
	case " ", "space", "enter":
		selected := m.selectedSyscall()
		if selected == "" {
			return m, nil
		}
		return m, toggleCmd(m.manager, selected)
	case "a":
		return m, bulkToggleCmd(m.manager, m.probes, false)
	case "n":
		return m, bulkToggleCmd(m.manager, m.probes, true)
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searching = false
		m.textInput.Blur()
		return m, nil
	case "enter":
		m.search = strings.TrimSpace(m.textInput.Value())
		m.searching = false
		m.textInput.Blur()
		m = m.clampCursor()
		return m, nil
	default:
		var cmd tea.Cmd
		m.textInput, cmd = m.textInput.Update(msg)
		m.search = strings.TrimSpace(m.textInput.Value())
		m = m.clampCursor()
		return m, cmd
	}
}

// reload returns m with probes refreshed from the manager.
func (m Model) reload() Model {
	if m.manager == nil {
		m.probes = nil
		return m
	}
	m.probes = m.manager.States()
	return m
}

// clampCursor returns m with the cursor and scroll offset kept inside the
// filtered probe list.
func (m Model) clampCursor() Model {
	items := m.filtered()
	if len(items) == 0 {
		m.cursor = 0
		m.offset = 0
		return m
	}
	if m.cursor >= len(items) {
		m.cursor = len(items) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	rows := m.visibleRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if rows > 0 && m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
	return m
}

func (m Model) filtered() []probemanager.ProbeState {
	if m.search == "" {
		return m.probes
	}
	needle := strings.ToLower(m.search)
	out := make([]probemanager.ProbeState, 0, len(m.probes))
	for _, p := range m.probes {
		if strings.Contains(strings.ToLower(p.Syscall), needle) {
			out = append(out, p)
		}
	}
	return out
}

func (m Model) selectedSyscall() string {
	items := m.filtered()
	if len(items) == 0 || m.cursor < 0 || m.cursor >= len(items) {
		return ""
	}
	return items[m.cursor].Syscall
}

func (m Model) visibleRows() int {
	if m.height <= 0 {
		return 10
	}
	rows := m.height - 9
	if rows < 3 {
		return 3
	}
	return rows
}

// View renders the probe modal centered on the terminal. It returns an empty
// string when the modal is not visible.
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
	m.height = height

	modalWidth := probeModalWidth(width)
	lines := m.buildProbeLines()

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(modalWidth).
		Render(strings.Join(lines, "\n"))

	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// probeModalWidth returns the clamped modal width for the given terminal width.
func probeModalWidth(termWidth int) int {
	modalWidth := 66
	if termWidth < modalWidth+4 {
		modalWidth = termWidth - 4
		if modalWidth < 44 {
			modalWidth = 44
		}
	}
	return modalWidth
}

// buildProbeLines assembles the text lines that make up the modal content:
// header, optional search bar, probe rows, and the help footer.
func (m Model) buildProbeLines() []string {
	active, total := 0, len(m.probes)
	if m.manager != nil {
		active, total = m.manager.ActiveCount()
	}
	rows := m.visibleRows()
	items := m.filtered()

	lines := []string{fmt.Sprintf("Probes (%d/%d active)", active, total)}
	if m.searching {
		lines = append(lines, m.textInput.View())
	} else if m.search != "" {
		lines = append(lines, "Filter: "+m.search)
	}
	lines = append(lines, "")

	start := m.offset
	if start > len(items) {
		start = len(items)
	}
	end := start + rows
	if end > len(items) {
		end = len(items)
	}
	for i := start; i < end; i++ {
		lines = append(lines, m.renderProbeRow(items[i], i == m.cursor))
	}
	if len(items) == 0 {
		lines = append(lines, "  (no probes)")
	}
	if m.lastErr != "" {
		lines = append(lines, "", "Error: "+common.Sanitize(m.lastErr))
	}
	lines = append(lines, "", "j/k move • space|enter toggle • a all-on • n all-off • / search • esc close")
	return lines
}

// renderProbeRow formats a single probe entry with selection prefix, checkbox,
// syscall name, and an optional truncated error annotation.
func (m Model) renderProbeRow(p probemanager.ProbeState, selected bool) string {
	prefix := "  "
	if selected {
		prefix = "> "
	}
	check := "[ ]"
	if p.Active {
		check = "[x]"
	}
	// Use a Builder to avoid an extra allocation for the optional error suffix
	// emitted per probe row on every render call.
	var lb strings.Builder
	lb.WriteString(fmt.Sprintf("%s%s %-24s", prefix, check, p.Syscall))
	if p.Error != "" {
		lb.WriteString(" ! ")
		lb.WriteString(truncateText(common.Sanitize(p.Error), 28))
	}
	return lb.String()
}

func toggleCmd(manager Manager, syscall string) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return ProbeToggledMsg{Syscall: syscall, Err: fmt.Errorf("probe manager unavailable")}
		}
		return ProbeToggledMsg{Syscall: syscall, Err: manager.Toggle(syscall)}
	}
}

func bulkToggleCmd(manager Manager, probes []probemanager.ProbeState, sourceActive bool) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return ProbeToggledMsg{Err: fmt.Errorf("probe manager unavailable")}
		}
		var firstErr error
		for _, p := range probes {
			if p.Active != sourceActive {
				continue
			}
			if err := manager.Toggle(p.Syscall); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return ProbeToggledMsg{Err: firstErr}
	}
}

// truncateText shortens s to at most limit display cells, ending in "..." when
// cut; limits of three cells or fewer hard-cut instead. It measures terminal
// cells and cuts on grapheme boundaries (common.TruncateRight), so wide or
// multi-byte error text stays valid UTF-8 and within the column.
func truncateText(s string, limit int) string {
	return common.TruncateRight(s, limit, common.ASCIIEllipsis)
}

// --- compile-time interface satisfaction assertion ---
//
// *probemanager.Manager must satisfy the Manager interface defined in this
// package. The tui/probes package already imports probemanager, so this
// assertion adds no new dependency.

var _ Manager = (*probemanager.Manager)(nil)
