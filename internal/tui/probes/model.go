package probes

import (
	"context"
	"fmt"
	"strings"

	"ior/internal/probemanager"
	common "ior/internal/tui/common"
	"ior/internal/types"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// Manager defines the probe operations used by the modal. AttachFamily and
// DetachFamily back the Families view; they run off the Update goroutine
// (StartFamilyBatch) because a whole family takes seconds, and stop between
// probes once ctx - the trace session's - is cancelled.
type Manager interface {
	States() []probemanager.ProbeState
	Toggle(syscall string) error
	Attach(syscall string) error
	Detach(syscall string) error
	ActiveCount() (int, int)
	AttachFamily(ctx context.Context, family types.SyscallFamily, progress func(completed, total int)) (probemanager.BatchResult, error)
	DetachFamily(ctx context.Context, family types.SyscallFamily, progress func(completed, total int)) (probemanager.BatchResult, error)
}

// ProbeToggledMsg reports completion of an async toggle operation (one
// probe, or all-on/all-off when Syscall is empty).
//
// Session is the trace session the modal's manager belongs to (WithSession),
// so the TUI can tell a result that arrives after a trace restart - whose
// toggle hit a manager that is gone - from a current one. Intent is the
// attached set the toggle was meant to produce, captured before it ran; the
// TUI keeps it as the selection for later sessions when the result is stale
// instead of reading back the new session's manager. It is nil when the
// toggle could not run (no manager).
type ProbeToggledMsg struct {
	Syscall string
	Session uint64
	Intent  []string
	Err     error
}

// Model is the probe toggle modal state. It is value-flow: every method has a
// value receiver and every mutator returns the updated Model (see the TUI
// Model receiver policy in AGENTS.md).
//
// It has two views, switched with tab: Syscalls lists single probes (toggle,
// search, all-on/all-off) and Families lists the syscall families with their
// attached/total counts and attaches or detaches a whole family at once.
type Model struct {
	visible bool
	probes  []probemanager.ProbeState
	view    view

	// cursor/offset are the Syscalls view's selection and scroll offset,
	// famCursor/famOffset the Families view's.
	cursor    int
	offset    int
	famCursor int
	famOffset int

	search    string
	searching bool
	textInput textinput.Model

	// session tags toggle results with the trace session of manager.
	session uint64

	lastErr string
	// lastInfo is the outcome line of the last family batch; batch is the
	// batch still running, if any.
	lastInfo string
	batch    familyBatch
	manager  Manager
	// height and width are the terminal size the modal is laid out for, as
	// reported by SetSize. The row budget (visibleRows) depends on both:
	// height bounds the box and width decides how many lines the wrapped help
	// and error text take. Zero means "not reported yet" (see the defaults).
	height int
	width  int
	isDark bool
}

// defaultWidth and defaultHeight are the terminal size assumed when the
// caller has not reported one (View renders into the same default size).
// maxModalWidth is the preferred modal width and minModalWidth the narrowest
// it shrinks to before simply taking the whole (tiny) terminal width.
const (
	defaultWidth  = 80
	defaultHeight = 24
	maxModalWidth = 66
	minModalWidth = 24
)

// probesHelp is the Syscalls view footer key help. It is wider than the modal
// content area, so it wraps; the chrome measurement in layout accounts for
// that.
const probesHelp = "j/k move • space|enter toggle • a all-on • n all-off • / search • tab families • esc close"

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

// WithSession records the trace session whose probe manager the modal was
// built with; single and bulk toggle results carry it (ProbeToggledMsg).
func (m Model) WithSession(session uint64) Model {
	m.session = session
	return m
}

// Visible reports whether the probes modal is shown.
func (m Model) Visible() bool { return m.visible }

// TextInputFocused reports whether the modal's search line is open and
// receiving typed text, as opposed to the list keys (j/k, space, a, n, ...).
func (m Model) TextInputFocused() bool { return m.visible && m.searching }

// Open shows the probes modal and reloads the probe list.
func (m Model) Open() Model {
	m.visible = true
	m.searching = false
	m.lastErr = ""
	m.lastInfo = ""
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

// SetSize records the terminal size the modal is rendered into so the scroll
// offset kept by Update matches the rows View will draw. Callers must report
// the same size they later pass to View.
func (m Model) SetSize(width, height int) Model {
	m.width = width
	m.height = height
	return m.clampCursor()
}

// Update dispatches Bubble Tea messages to the appropriate handler.
// ProbeToggledMsg refreshes the probe list; key presses are forwarded to
// the search or navigation handlers. Family batch messages are not handled
// here: the TUI owns family batches and renders them into the modal with
// ShowBatchProgress and FinishBatch.
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

// handleKeyPress processes the keys shared by both views (close, move,
// switch view) and hands the rest to the active view's handler.
func (m Model) handleKeyPress(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m.Close(), nil
	case "j", "down":
		return m.moveCursor(1), nil
	case "k", "up":
		return m.moveCursor(-1), nil
	case "tab":
		return m.switchView(), nil
	}
	if m.view == viewFamilies {
		switch msg.String() {
		case " ", "space", "enter":
			return m.toggleSelectedFamily()
		}
		return m, nil
	}
	return m.handleSyscallKey(msg)
}

// moveCursor moves the active view's selection by delta rows.
func (m Model) moveCursor(delta int) Model {
	if m.view == viewFamilies {
		m.famCursor += delta
	} else {
		m.cursor += delta
	}
	return m.clampCursor()
}

// batchBusyNotice is shown when a Syscalls view change is refused because a
// family batch is running.
const batchBusyNotice = "family batch running - wait for it to finish"

// handleSyscallKey processes the Syscalls view keys: search, toggle one
// probe, and all-on/all-off. While a family batch runs, the probe changes are
// refused: the batch flips probes of its family one by one, and a toggle or
// all-on/all-off racing it would undo part of it or be undone by it. The TUI
// replays a running batch into every rebuilt modal (ShowBatchProgress), so
// the guard holds across reopening the modal.
func (m Model) handleSyscallKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case " ", "space", "enter", "a", "n":
		if m.batch.active {
			m.lastErr = batchBusyNotice
			return m.clampCursor(), nil
		}
	}
	switch key {
	case "/", "f":
		m.searching = true
		m.textInput.SetValue(m.search)
		m.textInput.CursorEnd()
		m.textInput.Focus()
		// The search line adds a chrome row, shrinking the row budget.
		return m.clampCursor(), nil
	case " ", "space", "enter":
		selected := m.selectedSyscall()
		if selected == "" {
			return m, nil
		}
		return m, toggleCmd(m.manager, selected, m.session)
	case "a":
		return m, setAllCmd(m.manager, true, m.session)
	case "n":
		return m, setAllCmd(m.manager, false, m.session)
	}
	return m, nil
}

func (m Model) updateSearch(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.searching = false
		m.textInput.Blur()
		// Leaving search may drop the search/filter line from the chrome.
		return m.clampCursor(), nil
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

// clampCursor returns m with the active view's cursor and scroll offset kept
// inside its list: the filtered probes (Syscalls) or the families (Families).
func (m Model) clampCursor() Model {
	rows := m.visibleRows()
	if m.view == viewFamilies {
		m.famCursor, m.famOffset = clampWindow(m.famCursor, m.famOffset, len(types.AllSyscallFamilies()), rows)
		return m
	}
	m.cursor, m.offset = clampWindow(m.cursor, m.offset, len(m.filtered()), rows)
	return m
}

// clampWindow keeps cursor inside a list of n items and the offset such that
// the rows-high window starting there shows the cursor. Besides that, the
// offset is pulled back when the row budget grows (terminal resized taller,
// search line or error dropped) so a list scrolled to its end still fills the
// window instead of leaving blank rows below the last item.
func clampWindow(cursor, offset, n, rows int) (int, int) {
	if n == 0 {
		return 0, 0
	}
	cursor = max(min(cursor, n-1), 0)
	if cursor < offset {
		offset = cursor
	}
	if rows > 0 && cursor >= offset+rows {
		offset = cursor - rows + 1
	}
	return cursor, min(offset, max(n-rows, 0))
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

// probeLayout is the modal layout for one size and state: the header and
// footer lines around the probe rows, the frame style, and how many rows fit.
type probeLayout struct {
	header, footer []string
	box            lipgloss.Style
	rows           int
}

// layout computes the modal layout for the current size and state. The row
// budget is the terminal height minus the chrome actually rendered around the
// rows: header and footer are rendered in the real box style and measured
// with lipgloss.Height. The chrome is measured rather than assumed because it
// varies with state — the search/filter line, the error block and the help
// footer, the latter two of which wrap depending on the modal width. At least
// one row is kept so the selection stays visible; View clips the degenerate
// tiny-terminal case.
func (m Model) layout() probeLayout {
	l := probeLayout{header: m.headerLines(), footer: m.footerLines(), box: m.boxStyle()}
	height := m.height
	if height <= 0 {
		height = defaultHeight // same fallback View renders into
	}
	chrome := make([]string, 0, len(l.header)+len(l.footer))
	chrome = append(append(chrome, l.header...), l.footer...)
	l.rows = max(height-lipgloss.Height(l.box.Render(strings.Join(chrome, "\n"))), 1)
	return l
}

// visibleRows returns how many probe rows fit on screen (see layout).
func (m Model) visibleRows() int {
	return m.layout().rows
}

// boxStyle returns the modal frame style sized for the current terminal width.
func (m Model) boxStyle() lipgloss.Style {
	width := m.width
	if width <= 0 {
		width = defaultWidth
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(probeModalWidth(width))
}

// contentWidth returns the cells available to a line inside the given frame.
// lipgloss v2 widths include border and padding, so the frame is subtracted.
func contentWidth(box lipgloss.Style) int {
	return box.GetWidth() - box.GetHorizontalFrameSize()
}

// View renders the probe modal centered on the terminal. It returns an empty
// string when the modal is not visible. The window of rows starts at the
// offset Update kept for the size reported via SetSize; width and height
// should be that same size. The output never exceeds width x height cells.
func (m Model) View(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = defaultWidth
	}
	if height <= 0 {
		height = defaultHeight
	}
	m.width = width
	m.height = height

	l := m.layout()
	box := l.box.Render(strings.Join(m.buildProbeLines(l, m.filtered()), "\n"))
	placed := lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
	// Terminals too small for even the chrome plus one row (or narrower than
	// the frame) would overflow; cut the excess rather than scroll the screen.
	return lipgloss.NewStyle().MaxHeight(height).MaxWidth(width).Render(placed)
}

// probeModalWidth returns the modal width for the given terminal width: the
// preferred width with a 2-cell margin each side when it fits, shrinking to
// minModalWidth, and below that the whole terminal width, so the box never
// grows wider than the terminal.
func probeModalWidth(termWidth int) int {
	return max(min(maxModalWidth, termWidth-4), min(minModalWidth, termWidth))
}

// headerLines returns the modal lines above the probe rows: the title, the
// search input or active filter (when any), and a spacer.
func (m Model) headerLines() []string {
	active, total := 0, len(m.probes)
	if m.manager != nil {
		active, total = m.manager.ActiveCount()
	}
	title := "Syscalls"
	if m.view == viewFamilies {
		title = "Families"
	}
	lines := []string{fmt.Sprintf("Probes (%d/%d active) - %s", active, total, title)}
	if m.view == viewFamilies {
		return append(lines, "")
	}
	if m.searching {
		lines = append(lines, m.textInput.View())
	} else if m.search != "" {
		lines = append(lines, "Filter: "+m.search)
	}
	return append(lines, "")
}

// footerLines returns the modal lines below the probe rows: the running
// family batch's progress or the last batch's outcome, the last toggle error
// (when any) and the active view's key help. All may wrap inside the modal.
func (m Model) footerLines() []string {
	var lines []string
	if line := m.batchLine(); line != "" {
		lines = append(lines, "", line)
	} else if m.lastInfo != "" {
		lines = append(lines, "", common.Sanitize(m.lastInfo))
	}
	if m.lastErr != "" {
		lines = append(lines, "", "Error: "+common.Sanitize(m.lastErr))
	}
	help := probesHelp
	if m.view == viewFamilies {
		help = familiesHelp
	}
	return append(lines, "", help)
}

// buildProbeLines assembles the text lines that make up the modal content
// from a precomputed layout and filtered item list: header, the l.rows-high
// window of rows starting at the scroll offset - probes, or in the Families
// view the families (items is then unused) - and the footer. Rows
// are cut to the content width so each takes exactly one line, as the row
// budget assumes.
func (m Model) buildProbeLines(l probeLayout, items []probemanager.ProbeState) []string {
	lines := make([]string, 0, len(l.header)+l.rows+len(l.footer))
	lines = append(lines, l.header...)
	if m.view == viewFamilies {
		lines = append(lines, m.familyRows(l)...)
		return append(lines, l.footer...)
	}

	start := min(m.offset, len(items))
	end := min(start+l.rows, len(items))
	width := contentWidth(l.box)
	for i := start; i < end; i++ {
		row := m.renderProbeRow(items[i], i == m.cursor)
		lines = append(lines, common.TruncateRight(row, width, common.ASCIIEllipsis))
	}
	if len(items) == 0 {
		lines = append(lines, "  (no probes)")
	}
	return append(lines, l.footer...)
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

// toggleCmd toggles syscall through manager. The result carries the
// modal's session and the intended attached set (see ProbeToggledMsg),
// captured before the toggle: the manager's active set with syscall flipped.
func toggleCmd(manager Manager, syscall string, session uint64) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return ProbeToggledMsg{Syscall: syscall, Session: session, Err: fmt.Errorf("probe manager unavailable")}
		}
		intent := intendedActive(manager.States(), func(p probemanager.ProbeState) bool {
			return p.Active != (p.Syscall == syscall)
		})
		return ProbeToggledMsg{Syscall: syscall, Session: session, Intent: intent, Err: manager.Toggle(syscall)}
	}
}

// setAllCmd attaches (active) or detaches every probe. It works from a fresh
// States() read and uses Attach/Detach rather than Toggle, so it only touches
// probes not yet in the requested state and is idempotent: pressing a twice,
// or after the list shown in the modal went stale, never flips a probe back.
// Its intent is every registered syscall, or none.
func setAllCmd(manager Manager, active bool, session uint64) tea.Cmd {
	return func() tea.Msg {
		if manager == nil {
			return ProbeToggledMsg{Session: session, Err: fmt.Errorf("probe manager unavailable")}
		}
		states := manager.States()
		intent := intendedActive(states, func(probemanager.ProbeState) bool { return active })
		change := manager.Detach
		if active {
			change = manager.Attach
		}
		var firstErr error
		for _, p := range states {
			if p.Active == active {
				continue
			}
			if err := change(p.Syscall); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return ProbeToggledMsg{Session: session, Intent: intent, Err: firstErr}
	}
}

// intendedActive returns the syscalls of states that want selects, as a
// non-nil slice (an empty intent means "attach nothing").
func intendedActive(states []probemanager.ProbeState, want func(probemanager.ProbeState) bool) []string {
	out := make([]string, 0, len(states))
	for _, p := range states {
		if want(p) {
			out = append(out, p.Syscall)
		}
	}
	return out
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
