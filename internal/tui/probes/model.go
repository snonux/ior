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
// Session is the trace session the toggle ran in, so the TUI can tell a
// result that arrives after a trace restart - whose toggle hit a manager that
// is gone - from a current one; it drops a stale result's error. A single
// toggle takes it from the modal (WithSession); all-on/all-off is started by
// the TUI (SetAllRequestMsg, SetAllCmd) with the session it runs in.
//
// Intent is the attached set a single toggle was meant to produce, captured
// before it ran; the TUI applies the toggle's delta to the selection for later
// sessions when the result is stale instead of reading back the new session's
// manager. It is nil when the toggle could not run (no manager), and always
// nil for all-on/all-off, whose intent the TUI records when the key is
// pressed (before the walk over every probe starts), not from the result.
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
	// inputStart is the rune the search input's drawn window starts at,
	// kept so the window stays put while the cursor is drawn in it
	// (common.FitTextInput, fitSearch).
	inputStart int

	// session tags toggle results with the trace session of manager.
	session uint64

	lastErr string
	// lastInfo is the outcome line of the last family batch; batch is the
	// batch still running, if any. bulkRunning is set while the TUI's
	// all-on/all-off walk runs in this modal's session (SetBulkRunning).
	lastInfo    string
	batch       familyBatch
	bulkRunning bool
	manager     Manager
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
	ti.SetWidth(searchInputWidth)
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

// SetBulkRunning tells the modal whether an all-on/all-off walk is in flight
// in its session. The TUI owns the walk (SetAllRequestMsg), so the modal
// cannot know on its own; while it runs, space/enter/a/n are refused with
// BulkBusyNotice, because a single toggle or second walk on the same manager
// would race it. The TUI sets it when the walk starts, clears it with the
// walk's result and re-applies it to every rebuilt modal.
func (m Model) SetBulkRunning(running bool) Model {
	m.bulkRunning = running
	return m
}

// Rebind points the modal at manager and session, the ones of a trace session
// that began while the modal was open, and reloads the probe list (empty for a
// nil manager: the session has not published one yet). Cursor, search and the
// info line (lastInfo: a family batch's "trace restarted" outcome, which is
// shown in the open modal on purpose) are kept. The error line is cleared: an
// error or refusal (a failed toggle, BulkBusyNotice) was about the old
// session's manager or walk and would otherwise still be shown against the new
// session until the next toggle result replaces it. Without the rebind the
// modal would keep toggling the old session's closed manager with results
// tagged by an ended session.
func (m Model) Rebind(manager Manager, session uint64) Model {
	m.manager = manager
	m.session = session
	m.lastErr = ""
	return m.reload().clampCursor()
}

// Session returns the trace session whose probe manager the modal was built
// with (WithSession).
func (m Model) Session() uint64 { return m.session }

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
	return m.fitSearch().clampCursor()
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
	case tea.PasteMsg:
		// Bracketed paste arrives as one message, not as key presses. It goes
		// into the search line when that is open; the list keys are commands
		// that pasted text must not trigger, so it is ignored otherwise.
		if m.searching {
			return m.typeIntoSearch(msg)
		}
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
// family batch is running; BulkBusyNotice when it is refused because an
// all-on/all-off walk is (the TUI uses the latter for its own refusals too).
const (
	batchBusyNotice = "family batch running - wait for it to finish"
	BulkBusyNotice  = "all-on/all-off running - wait for it to finish"
)

// handleSyscallKey processes the Syscalls view keys: search, toggle one
// probe, and all-on/all-off. The latter only requests the change
// (SetAllRequestMsg): the TUI owns the run, like a family batch, so it is
// scoped to the trace session. While a family batch or an all-on/all-off walk
// runs, the probe changes are refused: both flip probes one by one, and a
// single toggle or another walk racing them would undo part of them or be
// undone by them. The TUI replays a running batch or walk into every rebuilt
// modal (ShowBatchProgress, SetBulkRunning), so the guard holds across
// reopening the modal.
func (m Model) handleSyscallKey(msg tea.KeyPressMsg) (Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case " ", "space", "enter", "a", "n":
		if m.batch.active {
			m.lastErr = batchBusyNotice
			return m.clampCursor(), nil
		}
		if m.bulkRunning {
			m.lastErr = BulkBusyNotice
			return m.clampCursor(), nil
		}
	}
	switch key {
	case "/", "f":
		m.searching = true
		m.textInput.SetValue(m.search)
		m.textInput.CursorEnd()
		m.textInput.Focus()
		m.inputStart = len([]rune(m.search))
		m = m.fitSearch()
		// The search line adds a chrome row, shrinking the row budget.
		return m.clampCursor(), nil
	case " ", "space", "enter":
		selected := m.selectedSyscall()
		if selected == "" {
			return m, nil
		}
		return m, toggleCmd(m.manager, selected, m.session)
	case "a":
		return m, requestSetAll(true)
	case "n":
		return m, requestSetAll(false)
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
		return m.typeIntoSearch(msg)
	}
}

// typeIntoSearch feeds a typed key or a pasted text to the search input and
// re-applies the live filter from its value. It goes through
// common.UpdateTextInput, which keeps Alt+D on the last rune from panicking
// bubbles (task kz2), and re-fits the input's window so the cursor stays
// drawn (fitSearch).
func (m Model) typeIntoSearch(msg tea.Msg) (Model, tea.Cmd) {
	var cmd tea.Cmd
	m.textInput, cmd = common.UpdateTextInput(m.textInput, msg)
	m.search = strings.TrimSpace(m.textInput.Value())
	m = m.fitSearch()
	m = m.clampCursor()
	return m, cmd
}

// fitSearch fits the search input's width and window to the text line of
// the size SetSize reported (common.FitTextInput), remembering the window's
// start for the next edit and render.
func (m Model) fitSearch() Model {
	m.inputStart = common.FitTextInput(&m.textInput, m.inputStart, searchFieldWidth(m.layoutTextWidth()))
	return m
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
