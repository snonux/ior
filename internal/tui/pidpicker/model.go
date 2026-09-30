package pidpicker

import (
	"fmt"
	"strconv"
	"strings"

	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const allPIDsLabel = "All PIDs"
const allTIDsLabel = "All TIDs"

// noSelection is the selectedIndex of a picker whose selected process
// vanished (exited, or stopped matching the typed filter) in PID mode. No row
// is highlighted and Enter does nothing, see relocateSelection.
const noSelection = -1

// PickerMode selects which id column the picker screen shows and emits.
type PickerMode int

const (
	// PickerModePID lists processes (tgids).
	PickerModePID PickerMode = iota
	// PickerModeTID lists threads of the selected process.
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

// PickerShortHelp returns the picker's key bindings in short-help order.
func (k KeyMap) PickerShortHelp() []key.Binding {
	return []key.Binding{k.Enter, k.Refresh, k.Esc}
}

type processesLoadedMsg struct {
	processes []ProcessInfo
	err       error
}

// Model is the Bubble Tea model for the PID picker screen. It is value-flow:
// every method has a value receiver and every mutator returns the updated
// Model (see the TUI Model receiver policy in AGENTS.md).
type Model struct {
	input     textinput.Model
	processes []ProcessInfo
	// search holds the lowercased searchable text of processes, index for
	// index, so a typed query never lowercases or formats a row again (task
	// 7r2). It is derived data: applyFilter rebuilds it whenever processes was
	// replaced (see ensureSearch), so writers of processes need not know it.
	search []searchText
	// searchBase is &processes[0] at the time search was built; ensureSearch
	// compares it to notice a replaced processes slice.
	searchBase *ProcessInfo
	filtered   []ProcessInfo
	// selectedIndex is the highlighted row: 0 is the "All" row, i>0 is
	// filtered[i-1], noSelection (PID mode only) highlights nothing.
	selectedIndex int
	// notice is the one-line explanation shown while selectedIndex is
	// noSelection; it is cleared by the next Up/Down.
	notice    string
	mode      PickerMode
	targetPID int
	width     int
	height    int
	keys      KeyMap
	lastErr   error
	isDark    bool
}

// TextInputFocused reports whether the process filter input is receiving
// typed text. It starts focused, is blurred by the Up/Down selection keys and
// is re-focused by the next printable key.
func (m Model) TextInputFocused() bool {
	return m.input.Focused()
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

// Init starts the initial process scan. It only reads the model: the scan
// result reaches Update as a processesLoadedMsg.
func (m Model) Init() tea.Cmd {
	return m.scanCmd()
}

// Update handles key presses and async process-scan responses.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		inputWidth := msg.Width - 16
		if inputWidth < 10 {
			inputWidth = 10
		}
		m.input.SetWidth(inputWidth)
		return m, nil
	case processesLoadedMsg:
		m.processes = msg.processes
		m.lastErr = msg.err
		m = m.applyFilter()
		return m, nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	case tea.PasteMsg:
		// Pasted text is typing: like a printable key it focuses a blurred
		// input (blurred by Up/Down), which would otherwise drop it silently.
		m.input.Focus()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m = m.applyFilter()
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
		return m.moveSelection(-1), nil
	case msg.Key().Code == tea.KeyDown:
		return m.moveSelection(1), nil
	}

	if msg.Key().Text != "" && !m.input.Focused() {
		if key.Matches(msg, m.keys.Refresh) {
			return m, m.scanCmd()
		}
		m.input.Focus()
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	m = m.applyFilter()
	return m, cmd
}

// moveSelection moves the highlight by delta (-1 up, +1 down), blurs the
// filter input and clears the lost-selection notice. From noSelection either
// direction lands on the "All" row, so the user then has to either press Enter
// on All deliberately or keep moving to a process; the move is what
// acknowledges the notice, even when it is clamped at the list edge.
func (m Model) moveSelection(delta int) Model {
	if m.selectedIndex == noSelection {
		m.selectedIndex = 0
	} else {
		m.selectedIndex = clamp(m.selectedIndex+delta, 0, len(m.filtered))
	}
	m.notice = ""
	m.input.Blur()
	return m
}

// emitSelection returns the command announcing the highlighted row. With
// noSelection it returns nil: Enter must not trace anything (in particular not
// the whole system, which the All row means in PID mode) while the picker is
// telling the user that their process is gone.
func (m Model) emitSelection() tea.Cmd {
	if m.selectedIndex == noSelection {
		return nil
	}
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

// applyFilter returns m with filtered rebuilt from processes for the current
// query. Like every Model method it takes and returns a value, so it only ever
// changes the copy the caller keeps.
//
// The selection follows the process, not the row number. selectedIndex is a row
// position (0 is the "All" row), but both a rescan (ctrl+r / r) and a changed
// query reorder, drop and insert rows, so keeping the number would leave the
// highlight (and the pid Enter emits) on whichever process now happens to sit
// there: a different pid than the one the user picked. relocateSelection looks
// the previously selected pid up in the rebuilt list instead.
func (m Model) applyFilter() Model {
	selectedPid, hadSelection := m.selectedProcessPid()
	query := strings.TrimSpace(strings.ToLower(m.input.Value()))
	if query == "" {
		// filtered is only ever read, so an empty query can share the scan
		// result instead of copying every row on each keystroke.
		m.filtered = shareProcesses(m.processes)
	} else {
		m = m.ensureSearch()
		filtered := make([]ProcessInfo, 0, len(m.processes))
		for i := range m.processes {
			if m.search[i].matches(query) {
				filtered = append(filtered, m.processes[i])
			}
		}
		m.filtered = filtered
	}
	return m.relocateSelection(selectedPid, hadSelection)
}

// searchText is the lowercased text a query is matched against, one field per
// searchable column. The fields stay separate (rather than one joined string)
// so a query can never match across a field boundary, exactly like the
// per-field matching it replaces.
type searchText struct {
	pid, comm, cmdline string
}

// buildSearchText lowercases the searchable columns of process once.
// strings.ToLower returns its argument unchanged (no allocation) when it has no
// upper-case letters, so typical lowercase command lines are not duplicated.
func buildSearchText(process ProcessInfo) searchText {
	return searchText{
		pid:     strconv.Itoa(process.Pid),
		comm:    strings.ToLower(process.Comm),
		cmdline: strings.ToLower(process.Cmdline),
	}
}

// matches reports whether the already lowercased and trimmed query occurs in
// the pid, the comm or the command line.
func (s searchText) matches(query string) bool {
	return strings.Contains(s.pid, query) ||
		strings.Contains(s.comm, query) ||
		strings.Contains(s.cmdline, query)
}

// ensureSearch (re)builds the lowercased search texts when m.processes is not
// the slice they were built for. Identity is the slice's length and first
// element address: the scan result is replaced wholesale (never edited in
// place), and tests assign m.processes directly.
func (m Model) ensureSearch() Model {
	if len(m.search) == len(m.processes) &&
		(len(m.processes) == 0 || m.searchBase == &m.processes[0]) {
		return m
	}
	search := make([]searchText, len(m.processes))
	for i, process := range m.processes {
		search[i] = buildSearchText(process)
	}
	m.search = search
	m.searchBase = nil
	if len(m.processes) > 0 {
		m.searchBase = &m.processes[0]
	}
	return m
}

// selectedProcessPid returns the Pid (the tid in TID mode; ProcessInfo.Pid is
// the thread id there) of the process row currently highlighted in filtered.
// ok is false when the "All" row is selected or the index does not point at a
// process row (e.g. before the first scan), so there is no identity to track.
func (m Model) selectedProcessPid() (pid int, ok bool) {
	idx := m.selectedIndex - 1
	if idx < 0 || idx >= len(m.filtered) {
		return 0, false
	}
	return m.filtered[idx].Pid, true
}

// relocateSelection points selectedIndex at the row of pid in the rebuilt
// filtered list. If the process is gone (it exited, or the new query no longer
// matches it) a neighbouring process must not take over, and neither should the
// "All" row silently: in PID mode All means "trace the whole system", so a
// reflexive Enter after the list changed under the user would start a
// system-wide trace without explanation. Instead the picker enters the
// noSelection state (no highlight, Enter is a no-op) and shows a notice until
// the user presses Up/Down. TID mode keeps the plain fallback to the All row:
// "All TIDs" stays within the process (handleTidSelected keeps the current
// pid), so it is never a surprise. When there was no process selected
// (hadSelection false) the index is only clamped into range; an existing
// noSelection state is sticky across rescans and edits until the user moves.
func (m Model) relocateSelection(pid int, hadSelection bool) Model {
	if m.selectedIndex == noSelection {
		return m
	}
	if !hadSelection {
		m.selectedIndex = clamp(m.selectedIndex, 0, len(m.filtered))
		return m
	}
	for i, process := range m.filtered {
		if process.Pid == pid {
			m.selectedIndex = i + 1
			return m
		}
	}
	if m.mode == PickerModeTID {
		m.selectedIndex = 0
		return m
	}
	m.selectedIndex = noSelection
	m.notice = m.lostSelectionNotice(pid)
	return m
}

// lostSelectionNotice words why pid left the list: a process still present in
// the latest scan but filtered out stopped matching the query, anything else
// exited.
func (m Model) lostSelectionNotice(pid int) string {
	for _, process := range m.processes {
		if process.Pid == pid {
			return fmt.Sprintf("pid %d no longer matches the filter - pick a process", pid)
		}
	}
	return fmt.Sprintf("pid %d exited - pick a process", pid)
}

// shareProcesses returns in for read-only use as the filtered list (never nil,
// so an empty scan still yields an empty, non-nil list).
func shareProcesses(in []ProcessInfo) []ProcessInfo {
	if len(in) == 0 {
		return []ProcessInfo{}
	}
	return in
}

// View renders the PID picker with filter input, list, and help bar.
func (m Model) View() tea.View {
	theme := common.Current()
	var b strings.Builder
	if m.mode == PickerModeTID {
		if m.targetPID > 0 {
			b.WriteString(theme.HeaderStyle.Render(fmt.Sprintf("Select TID for PID %d", m.targetPID)))
		} else {
			b.WriteString(theme.HeaderStyle.Render("Select TID"))
		}
	} else {
		b.WriteString(theme.HeaderStyle.Render("Select PID"))
	}
	b.WriteString("\n")
	b.WriteString(m.input.View())
	b.WriteString("\n\n")

	rows := m.renderRows()
	b.WriteString(rows)

	if m.notice != "" {
		b.WriteString("\n")
		b.WriteString(theme.ErrorStyle.Render(m.notice))
	}

	if m.lastErr != nil {
		b.WriteString("\n")
		b.WriteString(theme.ErrorStyle.Render("scan error: " + common.Sanitize(m.lastErr.Error())))
	}

	b.WriteString("\n")
	viewWidth, _ := common.EffectiveViewport(m.width, m.height)
	helpStyle := theme.HelpBarStyle.Width(viewWidth)
	b.WriteString(helpStyle.Render(renderHelp(m.footerBindings())))
	return tea.NewView(theme.ScreenStyle.Render(b.String()))
}

// SetDarkMode updates picker theme and text input styles.
func (m Model) SetDarkMode(isDark bool) Model {
	m.isDark = isDark
	m.input.SetStyles(textinput.DefaultStyles(isDark))
	return m
}

// renderRows renders only the rows inside the visible window. The list can hold
// every process (or, in the all-PIDs TID picker, every thread) on the system,
// each with a full command line, so formatting, sanitising and styling all of
// them on each View cost over 100ms at 50k rows (task 7r2); the window is
// computed from the row count alone and just its rows are formatted.
func (m Model) renderRows() string {
	allLabel := allPIDsLabel
	if m.mode == PickerModeTID {
		allLabel = allTIDsLabel
	}
	start, end := m.visibleWindow(len(m.filtered) + 1)
	lines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		if i == 0 {
			lines = append(lines, m.renderRow(0, allLabel))
			continue
		}
		lines = append(lines, m.renderRow(i, formatProcess(m.filtered[i-1])))
	}
	return strings.Join(lines, "\n")
}

// visibleWindow returns the half-open range [start, end) of the total rows
// (the "All" row plus the filtered processes) to draw. Without a known height
// every row is drawn; otherwise the window keeps the selected row near its
// middle and is clamped to the list, so noSelection (-1) shows the top.
func (m Model) visibleWindow(total int) (start, end int) {
	maxRows := m.visibleRows()
	if maxRows <= 0 || total <= maxRows {
		return 0, total
	}
	start = clamp(m.selectedIndex-maxRows/2, 0, total-maxRows)
	return start, start + maxRows
}

func (m Model) renderRow(index int, label string) string {
	prefix := "  "
	style := lipgloss.NewStyle()
	if index == m.selectedIndex {
		prefix = "> "
		style = common.Current().HighlightStyle
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

// footerBindings returns the footer key hints for the current focus state. The
// footer must name the key that actually refreshes: while the filter input is
// focused (the default) a plain r is text for the filter, so only ctrl+r
// rescans; once Up/Down has blurred the input, r rescans as well
// (keys.Refresh). Showing "r refresh" in the focused state would advertise a
// key that types into the filter instead.
func (m Model) footerBindings() []key.Binding {
	refresh := m.keys.Refresh
	if m.input.Focused() {
		refresh = key.NewBinding(key.WithKeys("ctrl+r"), key.WithHelp("ctrl+r", refresh.Help().Desc))
	}
	return []key.Binding{m.keys.Enter, refresh, m.keys.Esc}
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

// formatProcess renders one picker row label. Comm and Cmdline come from
// /proc and belong to arbitrary (possibly other users') processes, so the
// label goes through common.Sanitize: argv with embedded newlines stays on
// one row and planted escape sequences (OSC 8 links, SGR hidden text) never
// reach the terminal. ProcessInfo itself keeps the raw values for searching.
func formatProcess(process ProcessInfo) string {
	return common.Sanitize(rawProcessLabel(process))
}

// rawProcessLabel formats the unsanitised row label for formatProcess.
func rawProcessLabel(process ProcessInfo) string {
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
