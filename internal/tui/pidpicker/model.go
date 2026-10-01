package pidpicker

import (
	"fmt"
	"strconv"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const allPIDsLabel = "All PIDs"
const allTIDsLabel = "All TIDs"

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
	// filtered[i-1], noSelection highlights nothing.
	selectedIndex int
	// implicit is true while the filter, not the user, decides the selection:
	// the initial state, and the All row after the filter text changed. It is
	// cleared by Up/Down. See followFilter.
	implicit bool
	// scanned is true once the first scan result (even a failed or empty one)
	// has arrived. Until then an empty list means "not loaded yet", so a typed
	// filter must not claim that nothing matches (see followFilter); a failed
	// scan is no "no match" either (lastErr).
	scanned bool
	// heldPid is the pid of a derived process row that a failed scan emptied
	// out of the list (0: none). The failed scan shows nothing selected, and
	// the next successful scan tracks heldPid as if it were still highlighted,
	// so a move to another first match is announced (keepDerivedProcess)
	// instead of happening silently. It is only consulted while the selection
	// is derived (implicit); a real edit of the filter text drops it, as the new
	// text derives a new selection, and after Up/Down it is ignored until such
	// an edit makes the selection derived again.
	heldPid int
	// notice is the one-line explanation under the list: why selectedIndex is
	// noSelection, or that a rescan moved a derived selection (see
	// keepDerivedProcess). It is cleared by Up/Down and by every recompute of
	// the derived selection (followFilter: each edit and each rescan).
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
		implicit:  true,
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
		return m.applyScan(msg), nil
	case tea.KeyPressMsg:
		return m.updateKey(msg)
	case tea.PasteMsg:
		// Pasted text is typing: like a printable key it focuses a blurred
		// input (blurred by Up/Down), which would otherwise drop it silently.
		m.input.Focus()
	}

	m, cmd := m.editFilter(msg)
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

	m, cmd := m.editFilter(msg)
	return m, cmd
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
// the previously selected pid up in the rebuilt list instead. A selection the
// user has not made (m.implicit) is not a process to track: it is derived from
// the query instead (first match, see followFilter).
func (m Model) applyFilter() Model {
	selectedPid, hadSelection := m.selectedProcessPid()
	query := m.query()
	if query == "" {
		// filtered is only ever read, so an empty query can share the scan
		// result instead of copying every row on each keystroke.
		m.filtered = shareProcesses(m.processes)
		// A rescan with nothing typed must not leave the previous scan's
		// search texts (and, through searchBase, its whole backing array)
		// alive: drop a stale cache here, the next non-empty query rebuilds.
		if !m.searchCurrent() {
			m.search, m.searchBase = nil, nil
		}
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
	return m.relocateSelection(selectedPid, hadSelection, query == "")
}

// query is the normalised filter text matched against the search texts.
func (m Model) query() string {
	return strings.TrimSpace(strings.ToLower(m.input.Value()))
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

// searchCurrent reports whether m.search was built for the current m.processes.
// Identity is the slice's length and first element address: the scan result is
// replaced wholesale (never edited in place), and tests assign m.processes
// directly. The length check matters because a longer or shorter slice over
// the same backing array (an append into spare capacity, a reslice) keeps the
// first element's address yet has a different set of rows.
func (m Model) searchCurrent() bool {
	return len(m.search) == len(m.processes) &&
		(len(m.processes) == 0 || m.searchBase == &m.processes[0])
}

// ensureSearch (re)builds the lowercased search texts when m.processes is not
// the slice they were built for (see searchCurrent).
//
// Cost: one searchText (three string headers, 48 B) per row plus a lowercased
// copy of every comm and cmdline that contains an upper-case letter
// (strings.ToLower does not copy already-lowercase text). The worst case is
// roughly 50 MB at 50k rows with 1 KB command lines that all need lowercasing.
// searchBase points into processes, so a cache left over from an earlier scan
// would keep that scan's whole backing array alive: applyFilter therefore drops
// the cache when a rescan arrives while the query is empty (the next non-empty
// query rebuilds it lazily), and a rescan under an active query rebuilds it
// right here, replacing the old one.
func (m Model) ensureSearch() Model {
	if m.searchCurrent() {
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
