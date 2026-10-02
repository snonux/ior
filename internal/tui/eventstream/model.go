package eventstream

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/common"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const (
	streamColGap = iota
	streamColLatency
	streamColComm
	streamColPID
	streamColTID
	streamColSyscall
	streamColFD
	streamColRet
	streamColBytes
	streamColFile
	streamColumnCount
)

// Source is the minimal stream buffer contract needed by the stream model.
type Source interface {
	Len() int
	Snapshot() []StreamEvent
}

// snapshotAppender is optionally implemented by a Source that can copy its
// rows into a caller-owned buffer (streamrow.RingBuffer does). Refresh runs
// on the Bubble Tea UI goroutine several times a second, so it prefers this
// path to re-snapshot a full 10k-row ring into the reused allEvents buffer
// instead of allocating a fresh multi-megabyte slice on every tick.
type snapshotAppender interface {
	AppendSnapshot(dst []StreamEvent) []StreamEvent
}

// Model is the stream tab: the live event view over a Source, with its own
// selection, filter, search and export modals. Receiver policy: every
// method takes *Model - this is the all-pointer template the other TUI
// models follow (see internal/tui/dashboard and AGENTS.md).
type Model struct {
	source Source

	// filtered and blankLines are owned by the model and their backing
	// arrays are reused across Refresh calls (see applyFilter and
	// blankContentLines), so no caller may retain them beyond a synchronous
	// use. allEvents is reused the same way (see takeSnapshot), but only
	// while ownsAllEvents is set: a Source's plain Snapshot result may alias
	// storage the source still uses, so it must never be written into.
	allEvents     []StreamEvent
	ownsAllEvents bool
	filtered      []StreamEvent
	blankLines    []string

	filter      Filter
	filterStack []string

	paused bool

	// exportEnabled gates the x/X/E stream export shortcuts and their hints.
	// It is wired from the shared key map's Export binding, which the top-level
	// model blanks when -tuiExport=false.
	exportEnabled bool

	scrollOffset    int
	autoScroll      bool
	selectedIdx     int
	selectedCol     int
	fdTraceView     fdTraceViewState
	exportModal     ExportModal
	searchModal     SearchModal
	warningModal    WarningModal
	searchPattern   string
	searchRegex     *regexp.Regexp
	searchDirection SearchDirection
	lastExportPath  string
	statusMessage   string
	exportDir       string
	isDark          bool

	width  int
	height int

	showFooter bool
	viewport   viewport.Model
}

type fdTraceViewState struct {
	visible bool
	pid     uint32
	fd      int32
	events  []StreamEvent
	offset  int
}

// NewModel constructs a stream model over source with its modals ready.
// The value return matches the field-embedding style of the parents that
// hold it; all methods are on *Model.
func NewModel(source Source) Model {
	m := Model{
		source:        source,
		exportModal:   NewExportModal(),
		searchModal:   NewSearchModal(),
		autoScroll:    true,
		selectedIdx:   -1,
		selectedCol:   0,
		exportDir:     ".",
		showFooter:    true,
		isDark:        true,
		viewport:      newStreamViewport(),
		exportEnabled: true,
	}
	m.SetDarkMode(true)
	return m
}

// SetExportEnabled gates the x/X/E stream export shortcuts and their hints.
// It is wired from the shared key map's Export binding, which the top-level
// model blanks when -tuiExport=false.
func (m *Model) SetExportEnabled(enabled bool) {
	m.exportEnabled = enabled
}

func newStreamViewport() viewport.Model {
	vp := viewport.New()
	keyMap := viewport.DefaultKeyMap()
	keyMap.Down.SetKeys("down", "j")
	keyMap.Up.SetKeys("up", "k")
	keyMap.Left.SetKeys("left", "h")
	keyMap.Right.SetKeys("right", "l")
	keyMap.PageDown.SetKeys("pgdown", "pgdn", "pagedown")
	keyMap.PageUp.SetKeys("pgup", "pageup")
	vp.KeyMap = keyMap
	vp.SoftWrap = true
	return vp
}

// SetViewport updates the render/scroll viewport dimensions used for
// max-scroll and page-step calculations during key handling.
func (m *Model) SetViewport(width, height int) {
	if width > 0 {
		m.width = width
		m.viewport.SetWidth(width)
		m.resizeModals(width)
	}
	if height > 0 {
		m.height = height
		m.viewport.SetHeight(m.visibleRows())
	}
}

// resizeModals keeps the search and export inputs sized to the boxes they
// are drawn in at view width, so typing scrolls their text by the width on
// screen and the cursor never falls outside the box (fitModalInput).
func (m *Model) resizeModals(width int) {
	m.exportModal = m.exportModal.Resize(width)
	m.searchModal = m.searchModal.Resize(width)
}

// SetFooterVisible controls whether the live stream shows its Row x/N footer
// (the dashboard's help-bar toggle). A status message is shown either way.
func (m *Model) SetFooterVisible(visible bool) {
	m.showFooter = visible
}

// footerShown reports whether View appends the Row/Sel footer below the
// table: the dashboard help bar turns it on (m.showFooter), and a paused
// stream always shows it because its selection/column line is interaction
// feedback. The status message does not depend on it (appendStreamFooter).
func (m *Model) footerShown() bool {
	return m.showFooter || m.paused
}

// SetSource updates the backing ring buffer and refreshes visible rows.
func (m *Model) SetSource(source Source) {
	m.source = source
	m.Refresh()
}

// SetFilter updates the active stream filter and immediately re-filters the
// current in-memory snapshot without mutating the underlying ring buffer.
func (m *Model) SetFilter(filter Filter) {
	targetSeq := m.currentSelectedSeq()
	m.filter = filter.Clone()
	m.applyFilter()
	m.restoreSelectionBySeq(targetSeq)
}

// SetFilterStack updates the visible shared filter stack summary.
func (m *Model) SetFilterStack(stack []string) {
	m.filterStack = append(m.filterStack[:0], stack...)
}

// SetDarkMode updates stream modal text input styles for the active theme.
func (m *Model) SetDarkMode(isDark bool) {
	m.isDark = isDark
	m.exportModal = m.exportModal.SetDarkMode(isDark)
	m.searchModal = m.searchModal.SetDarkMode(isDark)
}

// FilterModalVisible reports whether the filter modal is currently open.
func (m *Model) FilterModalVisible() bool {
	return false
}

// ExportModalVisible reports whether the stream export modal is currently open.
func (m *Model) ExportModalVisible() bool {
	return m.exportModal.Visible()
}

// SearchModalVisible reports whether the stream search modal is currently open.
func (m *Model) SearchModalVisible() bool {
	return m.searchModal.Visible()
}

// WarningModalVisible reports whether the modal showing a warning row's whole
// message is open. It owns the keyboard like the other two (HandleKey), so
// the parent must keep its global shortcuts, q in particular, off meanwhile.
func (m *Model) WarningModalVisible() bool {
	return m.warningModal.Visible()
}

// FDTraceVisible reports whether the FD-trace overlay is currently open. Like
// the two modals it owns the keyboard while open (see handleFDTraceKey), so the
// parent must not act on global shortcuts, q in particular, meanwhile.
func (m *Model) FDTraceVisible() bool {
	return m.fdTraceView.visible
}

// Paused reports whether stream refresh is currently paused.
func (m *Model) Paused() bool {
	return m.paused
}

// HandleKey dispatches keyStr to the active modal or live/paused stream handlers.
// keyStr is one key's name as tea.KeyPressMsg.String spells it; an open input
// modal gets the key press it names (keyMsgFromString) and ignores a string
// that names no key, rather than typing it; the warning modal, which has no
// input, takes the name itself. It reports whether the key was
// consumed (false means the caller should handle it) and returns a command
// for any request the stream cannot fulfil itself: it emits
// messages.GlobalFilterRequestedMsg, messages.GlobalFilterUndoRequestedMsg
// or messages.OpenEditorRequestedMsg for the parent to act on. The command
// is nil when the key only changed local stream state.
func (m *Model) HandleKey(keyStr string) (bool, tea.Cmd) {
	if m.inputModalVisible() {
		msg, ok := keyMsgFromString(keyStr)
		if !ok {
			// The modal owns the keyboard, so the unknown name is
			// consumed, not passed on as a dashboard shortcut.
			return true, nil
		}
		return m.handleModalKey(msg), nil
	}
	if m.warningModal.Visible() {
		// The warning modal owns the keyboard like the two input modals:
		// it takes every key, the ones it has no use for included, so none
		// resumes the stream or reaches the dashboard behind it.
		m.warningModal = m.warningModal.Update(keyStr, m.width, m.height)
		return true, nil
	}
	if m.fdTraceView.visible {
		return m.handleFDTraceKey(keyStr), nil
	}
	return m.handleStreamKey(keyStr)
}

// inputModalVisible reports whether the search or export-filename modal is open
// and owns the keyboard.
func (m *Model) inputModalVisible() bool {
	return m.searchModal.Visible() || m.exportModal.Visible()
}

// handleModalKey hands msg to the open search or export modal and reports
// that it was consumed: a modal takes every key.
func (m *Model) handleModalKey(msg tea.KeyPressMsg) bool {
	if m.searchModal.Visible() {
		return m.handleSearchModalKey(msg)
	}
	return m.handleExportModalKey(msg)
}

// HandlePaste inserts bracketed-paste text into the search or export-filename
// input while one of those modals is open, and reports whether it did. HandleKey
// takes key names and cannot carry a paste, so pasted text has its own entry
// point. Outside a modal every key is a stream command that pasted text must
// not trigger, so the paste is ignored (false).
func (m *Model) HandlePaste(msg tea.PasteMsg) bool {
	switch {
	case m.searchModal.Visible():
		m.statusMessage = ""
		m.searchModal, _, _ = m.searchModal.Update(msg)
		return true
	case m.exportModal.Visible():
		m.statusMessage = ""
		m.exportModal, _, _ = m.exportModal.Update(msg)
		return true
	}
	return false
}

// handleSearchModalKey routes a key press while the search modal is open.
func (m *Model) handleSearchModalKey(msg tea.KeyPressMsg) bool {
	m.statusMessage = ""
	var (
		term   string
		submit bool
	)
	m.searchModal, term, submit = m.searchModal.Update(msg)
	if !submit {
		return true
	}
	return m.submitSearch(term, m.searchModal.Direction())
}

// handleExportModalKey routes a key press while the export modal is open.
func (m *Model) handleExportModalKey(msg tea.KeyPressMsg) bool {
	m.statusMessage = ""
	var (
		filename string
		submit   bool
	)
	m.exportModal, filename, submit = m.exportModal.Update(msg)
	if !submit {
		return true
	}
	path, err := m.exportFilteredToCSV(filename)
	if err != nil {
		// A refused name keeps the modal open with the error beside the typed
		// name, rather than closing it and losing what was typed.
		m.exportModal = m.exportModal.Reject(filename, err)
		return true
	}
	m.lastExportPath = path
	m.statusMessage = "Exported: " + path
	return true
}

// handleFDTraceKey routes a key press while the FD-trace overlay is visible.
// Like the search and export modals the overlay owns the keyboard: every key
// is consumed (the default case), so a key it has no meaning for cannot fall
// through to the dashboard's tab, view or reset shortcuts and act on whatever
// is hidden behind the overlay. q and esc both close it; q reaches this switch
// because the parent re-routes it as esc while FDTraceVisible (BlocksGlobalShortcut).
func (m *Model) handleFDTraceKey(keyStr string) bool {
	switch keyStr {
	case "enter", " ", "space":
		return true
	case "j", "down":
		m.scrollFDTraceByLines(1)
		return true
	case "k", "up":
		m.scrollFDTraceByLines(-1)
		return true
	case "left", "h":
		return true
	case "right", "l":
		return true
	case "pgdown", "pgdn", "pagedown":
		m.scrollFDTraceByLines(m.pageStep())
		return true
	case "pgup", "pageup":
		m.scrollFDTraceByLines(-m.pageStep())
		return true
	case "g":
		m.fdTraceView.offset = 0
		return true
	case "G":
		m.fdTraceView.offset = m.maxFDTraceOffset()
		return true
	case "esc", "q":
		m.fdTraceView.visible = false
		m.fdTraceView.events = nil
		m.fdTraceView.offset = 0
		return true
	default:
		return true
	}
}

// handleStreamExportKey handles the x/X/E export shortcuts. They act only
// while the stream is paused, and are inactive when export is disabled
// (-tuiExport=false): the key is then not consumed, so no export file is
// written, no modal opens and no editor is requested. E returns a command
// emitting messages.OpenEditorRequestedMsg for the last export.
func (m *Model) handleStreamExportKey(keyStr string) (bool, tea.Cmd) {
	if !m.exportEnabled || !m.paused {
		return false, nil
	}
	m.statusMessage = ""
	switch keyStr {
	case "x":
		path, err := m.exportFilteredToCSV(defaultStreamExportFilename())
		if err != nil {
			m.statusMessage = fmt.Sprintf("Export failed: %v", err)
			return true, nil
		}
		m.lastExportPath = path
		m.statusMessage = "Exported: " + path
		return true, nil
	case "X":
		m.exportModal = m.exportModal.Open(defaultStreamExportFilename())
		return true, nil
	case "E":
		if m.lastExportPath == "" {
			m.statusMessage = "No stream export yet"
			return true, nil
		}
		m.statusMessage = "Opening in editor: " + m.lastExportPath
		return true, emit(messages.OpenEditorRequestedMsg{Path: m.lastExportPath})
	}
	return false, nil
}

// emit wraps msg in a command that delivers it to the parent model.
func emit(msg tea.Msg) tea.Cmd {
	return func() tea.Msg { return msg }
}

// handleStreamKey handles keys for the main live/paused stream table. The
// returned command carries any request for the parent (see HandleKey).
func (m *Model) handleStreamKey(keyStr string) (bool, tea.Cmd) {
	if keyStr != "T" {
		// The FD-trace footer note belongs to the row it was raised on; any
		// other key (navigation, resume, filter, ...) moves on from it.
		m.clearFDTraceStatus()
	}
	switch keyStr {
	case "x", "X", "E":
		return m.handleStreamExportKey(keyStr)
	case "enter":
		return m.handleEnterKey()
	case "F":
		return m.requestGlobalFilterUndo(true)
	case "esc":
		return m.requestGlobalFilterUndo(m.paused)
	case "T":
		if !m.paused {
			return false, nil
		}
		return m.openFDTraceView(), nil
	case "/":
		m.openSearch(SearchForward)
		return true, nil
	case "?":
		m.openSearch(SearchBackward)
		return true, nil
	case "n":
		return m.jumpSearch(m.searchDirection), nil
	case "N":
		return m.jumpSearch(-m.searchDirection), nil
	case " ", "space":
		return m.handleSpaceKey(), nil
	case "G", "g", "j", "down", "k", "up", "left", "h", "right", "l",
		"pgdown", "pgdn", "pagedown", "pgup", "pageup":
		return m.handleNavigationKey(keyStr), nil
	default:
		return false, nil
	}
}

// handleEnterKey handles Enter on the stream table, which acts on the paused
// selection only (live, the key is left to the caller): on a syscall row it
// requests a filter from the selected cell, on a warning row, which has no
// cells, it opens the modal with the row's whole message (task b23; Enter
// did nothing there before, and the row's one line cut the message's tail).
func (m *Model) handleEnterKey() (bool, tea.Cmd) {
	if !m.paused {
		return false, nil
	}
	if ev := m.selectedEvent(); ev != nil && ev.IsWarning {
		m.warningModal = m.warningModal.Open(*ev)
		return true, nil
	}
	return m.requestGlobalFilterFromSelectedCell()
}

// selectedEvent returns the selected row, nil when no row is selected.
func (m *Model) selectedEvent() *StreamEvent {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return nil
	}
	return &m.filtered[m.selectedIdx]
}

// requestGlobalFilterUndo returns a command asking the parent to pop the
// latest shared filter layer. The key is consumed only when allowed and
// there is a layer to pop; otherwise it falls through to the caller.
func (m *Model) requestGlobalFilterUndo(allowed bool) (bool, tea.Cmd) {
	if !allowed || len(m.filterStack) == 0 {
		return false, nil
	}
	return true, emit(messages.GlobalFilterUndoRequestedMsg{})
}

// fdTraceStatusPrefix starts every footer note raised by openFDTraceView, so
// clearFDTraceStatus can drop exactly those and leave other transient
// messages (Exported:, search results) alone.
const fdTraceStatusPrefix = "FD trace: "

// clearFDTraceStatus drops a stale FD-trace footer note. The note explains why
// T did nothing on one specific row; left in place it kept describing that row
// after the selection moved to a traceable one or after resume (task 2r2).
func (m *Model) clearFDTraceStatus() {
	if strings.HasPrefix(m.statusMessage, fdTraceStatusPrefix) {
		m.statusMessage = ""
	}
}

// handleSpaceKey toggles the paused/live state of the stream.
func (m *Model) handleSpaceKey() bool {
	m.paused = !m.paused
	if !m.paused {
		// Resuming returns to live-tail behavior immediately.
		m.autoScroll = true
		m.selectedIdx = -1
		m.Refresh()
	} else {
		m.ensureSelection()
		m.ensureSelectedCol()
		m.centerSelection()
	}
	return true
}

// handleNavigationKey dispatches scroll/cursor navigation in live and paused
// modes. It delegates g/G (goto edges) to handleGotoKey and directional keys
// (arrows, hjkl, page up/down) to handleDirectionalKey.
func (m *Model) handleNavigationKey(keyStr string) bool {
	switch keyStr {
	case "G", "g":
		return m.handleGotoKey(keyStr)
	case "j", "down", "k", "up", "left", "h", "right", "l",
		"pgdown", "pgdn", "pagedown", "pgup", "pageup":
		return m.handleDirectionalKey(keyStr)
	default:
		return false
	}
}

// handleGotoKey handles g (top) and G (bottom) in both live and paused modes.
func (m *Model) handleGotoKey(keyStr string) bool {
	if m.paused {
		return m.handlePausedTableNavigation(keyStr)
	}
	if keyStr == "G" {
		m.autoScroll = true
		m.viewport.GotoBottom()
		m.scrollOffset = clamp(m.viewport.YOffset(), 0, m.maxScrollOffset())
	} else {
		m.autoScroll = false
		m.viewport.GotoTop()
		m.scrollOffset = 0
	}
	return true
}

// handleDirectionalKey handles arrow/hjkl/page keys in both live and paused modes.
func (m *Model) handleDirectionalKey(keyStr string) bool {
	if m.paused {
		return m.handlePausedTableNavigation(keyStr)
	}
	// keyMsgFromString maps the page-key aliases (pgdn, pagedown, pageup)
	// to the page keys themselves, which handleViewportUpdate matches.
	msg, ok := keyMsgFromString(keyStr)
	return ok && m.handleViewportUpdate(msg)
}

// HandleTeaKey handles stream keys based on Bubble Tea key message types first,
// then falls back to string matching for rune-driven shortcuts. Its results
// have the same meaning as HandleKey's.
//
// An open search or export modal gets msg itself, not its name, and its
// bubbles textinput types only the press's text, so a key it does not bind,
// such as Ctrl+X, types nothing (task 9z2). The old route went through
// HandleKey's name: the switch below dropped the modifier of Ctrl/Alt+Left
// and Ctrl/Alt+Right (a plain cursor step, not a word), and keyMsgFromString
// then turned a name the textinput does not bind into typed text ("ctrl+x").
// Bound names (ctrl+a, home, alt+b, ...) already acted as their keys there.
func (m *Model) HandleTeaKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
	if m.inputModalVisible() {
		return m.handleModalKey(msg), nil
	}
	if m.handleViewportUpdate(msg) {
		return true, nil
	}

	switch msg.Code {
	case tea.KeyLeft:
		return m.HandleKey("left")
	case tea.KeyRight:
		return m.HandleKey("right")
	case tea.KeyUp:
		return m.HandleKey("up")
	case tea.KeyDown:
		return m.HandleKey("down")
	case tea.KeyPgUp:
		return m.HandleKey("pgup")
	case tea.KeyPgDown:
		return m.HandleKey("pgdown")
	case tea.KeySpace:
		return m.HandleKey("space")
	case tea.KeyEsc:
		return m.HandleKey("esc")
	case tea.KeyEnter:
		return m.HandleKey("enter")
	default:
		if msg.Text != "" {
			runes := []rune(msg.Text)
			if len(runes) == 1 {
				return m.HandleKey(msg.Text)
			}
		}
	}
	return m.HandleKey(msg.String())
}

func (m *Model) handleViewportUpdate(msg tea.KeyPressMsg) bool {
	if m.paused || m.fdTraceView.visible || m.exportModal.Visible() || m.searchModal.Visible() {
		return false
	}

	switch msg.String() {
	case "down", "j", "up", "k", "left", "h", "right", "l", "pgup", "pageup", "pgdown", "pgdn", "pagedown":
	default:
		return false
	}

	switch msg.String() {
	case "pgup", "pageup":
		m.viewport.ScrollUp(m.pageStep())
	case "pgdown", "pgdn", "pagedown":
		m.viewport.ScrollDown(m.pageStep())
	default:
		vp, cmd := m.viewport.Update(msg)
		_ = cmd
		m.viewport = vp
	}
	m.scrollOffset = clamp(m.viewport.YOffset(), 0, m.maxScrollOffset())
	if m.scrollOffset < m.maxScrollOffset() {
		m.autoScroll = false
	}
	return true
}

// View renders the stream table (or FD-trace overlay) for the given dimensions.
// It also renders any open modal on top of the base view.
func (m *Model) View(width, height int) string {
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 24
	}
	m.width = width
	m.height = height
	m.viewport.SetWidth(width)
	m.viewport.SetHeight(m.visibleRows())
	m.resizeModals(width)

	if m.fdTraceView.visible {
		return m.viewFDTrace(width)
	}

	base, start := m.renderStreamBase(width)

	// Modals overlay the full view regardless of footer visibility.
	if m.exportModal.Visible() {
		return m.exportModal.View(width, height)
	}
	if m.searchModal.Visible() {
		return m.searchModal.View(width, height)
	}
	if m.warningModal.Visible() {
		return m.warningModal.View(width, height)
	}
	// The footer gets only the rows the table leaves of height: on a short
	// terminal the table (never under one event row) takes them all, and the
	// footer lines are dropped, Row/Sel first and the status message last
	// (a single spare row goes to the message, appendStreamFooter, and the
	// filter-stack line yields its row to it too, fittingFilterStack),
	// instead of making the view taller than its budget. The dashboard can
	// then size its "too small" threshold by the table alone, so pausing or a
	// status message never swaps the table for that notice. Which footer
	// lines exist at all is appendStreamFooter's call (footerShown for
	// Row/Sel; the status message always).
	return m.appendStreamFooter(base, start, height-lipgloss.Height(base))
}

// renderStreamBase computes the visible row slice and renders the stream table.
// It returns the rendered string and the start index used for the status line.
func (m *Model) renderStreamBase(width int) (string, int) {
	rows := m.visibleRows()
	start := clamp(m.viewport.YOffset(), 0, m.maxScrollOffset())
	m.scrollOffset = start
	end := start + rows
	if end > len(m.filtered) {
		end = len(m.filtered)
	}
	visible := m.filtered[start:end]
	selectedVisibleIdx := -1
	if m.paused && m.selectedIdx >= start && m.selectedIdx < end {
		selectedVisibleIdx = m.selectedIdx - start
	}
	bufferLen := 0
	if m.source != nil {
		bufferLen = m.source.Len()
	}
	selectedCol := -1
	if m.paused && selectedVisibleIdx >= 0 {
		selectedCol = m.selectedCol
	}
	base := RenderStreamTable(width, m.paused, len(m.allEvents), len(m.filtered), bufferLen, ringBufferCapacity, m.filter, m.fittingFilterStack(len(visible)), visible, selectedVisibleIdx, selectedCol)
	return base, start
}

// fittingFilterStack is the filter stack the table shows above its column
// header: the whole stack while the table with that extra line still fits
// m.height (visibleRows reserves a row for it), none on a terminal so short
// that the table already takes every row. A status message the footer will
// show outranks the stack line: the row it needs is kept free first, so a
// single spare row goes to "Export failed", "Invalid regex" or "No match"
// (appendStreamFooter) rather than to the stack, which loses nothing when
// dropped because the dashboard status line summarises the same stack. The
// message is drawn with the help bar off and the stream live too, so it
// reserves its row in every footer state.
func (m *Model) fittingFilterStack(eventRows int) []string {
	messageRows := 0
	if m.statusMessage != "" {
		messageRows = 1
	}
	if streamTableChromeRows+eventRows+1+messageRows > m.height {
		return nil
	}
	return m.filterStack
}

// Refresh pulls a fresh snapshot from the source and re-applies the filter,
// unless the stream is paused. Driven by the high-frequency stream tick.
func (m *Model) Refresh() {
	if m.paused {
		return
	}
	if m.source == nil {
		m.allEvents = []StreamEvent{}
		m.ownsAllEvents = false
		m.filtered = []StreamEvent{}
		m.scrollOffset = 0
		m.viewport.SetContentLines(nil)
		m.viewport.SetYOffset(0)
		return
	}

	m.takeSnapshot()
	m.applyFilter()
}

// takeSnapshot replaces allEvents with the source's current rows. When the
// source supports AppendSnapshot it appends into allEvents' backing array,
// but only if that array was allocated by an earlier AppendSnapshot here
// (ownsAllEvents); nothing outside the model holds such an array, so
// overwriting it in place is safe. A plain Snapshot result is kept as is
// and marked not owned: the Source contract does not promise a private
// copy (a test sink may return its internal slice), and reusing it after a
// SetSource switch would clobber the previous source's storage.
func (m *Model) takeSnapshot() {
	if appender, ok := m.source.(snapshotAppender); ok {
		var dst []StreamEvent
		if m.ownsAllEvents {
			dst = m.allEvents[:0]
		}
		m.allEvents = appender.AppendSnapshot(dst)
		m.ownsAllEvents = true
		return
	}
	m.allEvents = m.source.Snapshot()
	m.ownsAllEvents = false
}

// filterRows appends the rows of src that match filter to dst and returns it.
// An inactive filter matches every row, so it bulk-copies src instead of
// evaluating Matches per row: that is the common case (no filter set) and it
// runs over the whole ring buffer on every stream tick. Both Model.applyFilter
// and the CSV export use it, so the export starts from the same filtered
// selection the Stream tab shows (the export then drops the warning rows, see
// below).
//
// Synthetic warning rows (Row.IsWarning) always pass, whatever the filter says.
// They describe the trace itself (a -tid that is not a thread of -pid, zero
// probes attached, dropped events), not a traced syscall, so a user filter has
// nothing to say about them - and the active -pid/-tid predicates of exactly
// the scopes that raise such warnings used to hide the explanation of why the
// trace stays empty (tasks ur2/wr2). The CSV export skips them separately: it
// contains the filtered real rows only, never the warning rows.
//
// Trade-off: because the bypassed warnings land in the returned slice, they
// are counted by the Stream tab's "filtered" counter (len(Model.filtered)
// feeds RenderStreamTable), so "filtered:N" can include warning rows that no
// filter predicate matched. That is intended: showing the explanation matters
// more than keeping the counter a pure count of matching syscalls, and the
// alternative (a second counter or a post-hoc subtraction) would put the
// warning's visibility and the number the user reads out of step.
func filterRows(dst, src []StreamEvent, filter Filter) []StreamEvent {
	if !filter.IsActive() {
		return append(dst, src...)
	}
	for i := range src {
		// Match through a pointer into src: the Row accessors have pointer
		// receivers, so this neither copies the row per accessor call nor
		// boxes a copy into the Candidate interface (a heap allocation per
		// row per tick).
		ev := &src[i]
		if ev.IsWarning {
			dst = append(dst, *ev)
			continue
		}
		// Plain Matches: the either-name rule for rename rows lives inside it
		// (Candidate.OldFileValue), so this stage cannot re-narrow what the
		// event loop and the dashboard ingest already applied.
		if filter.Matches(ev) {
			dst = append(dst, *ev)
		}
	}
	return dst
}

// applyFilter rebuilds filtered from allEvents and re-syncs the viewport.
// It reuses filtered's backing array: rows past the new length stay pinned
// until overwritten, which is bounded by the ring capacity and cheaper than
// reallocating the slice on every stream tick.
func (m *Model) applyFilter() {
	if len(m.allEvents) == 0 {
		m.filtered = m.filtered[:0]
		m.scrollOffset = 0
		m.selectedIdx = -1
		m.viewport.SetContentLines(nil)
		m.viewport.SetYOffset(0)
		return
	}

	m.filtered = filterRows(m.filtered[:0], m.allEvents, m.filter)
	m.viewport.SetWidth(m.width)
	m.viewport.SetHeight(m.visibleRows())
	m.viewport.SetContentLines(m.blankContentLines(len(m.filtered)))

	max := m.maxScrollOffset()
	if m.autoScroll {
		m.viewport.GotoBottom()
		m.scrollOffset = clamp(m.viewport.YOffset(), 0, max)
	} else {
		m.scrollOffset = clamp(m.scrollOffset, 0, max)
		m.viewport.SetYOffset(m.scrollOffset)
	}
	m.clampSelection()
	if m.paused {
		m.ensureSelection()
		m.ensureSelectedCol()
		m.centerSelection()
	}
}

// blankContentLines returns n empty lines for the viewport, which only
// tracks the row count for scrolling (rows are rendered by
// RenderStreamTable). The slice is reused across calls; sharing it with the
// viewport is safe because the viewport only rewrites lines that contain
// newlines, and these are always empty.
func (m *Model) blankContentLines(n int) []string {
	if cap(m.blankLines) < n {
		m.blankLines = make([]string, n)
	}
	return m.blankLines[:n]
}

func (m *Model) maxScrollOffset() int {
	rows := m.visibleRows()
	if len(m.filtered) <= rows {
		return 0
	}
	return len(m.filtered) - rows
}

// streamTableChromeRows is the stream panel without event rows: its two
// borders, the status line, the filter line and the column header.
const streamTableChromeRows = 5

// streamReservedRows is what visibleRows keeps of the view height besides the
// event rows: the panel chrome, the optional filter-stack line and the two
// footer lines (Row/Sel and the status message). Below that height the table
// keeps one event row and the extra lines are dropped (fittingFilterStack,
// appendStreamFooter, viewFDTrace's footer; a status message keeps its row
// longest, then the filter-stack line, then Row/Sel), so neither the stream
// table nor the FD-trace overlay outgrows its height from 6 rows up; the
// modals fit any height down to their compact layout (renderModal).
//
// The reservation is constant on purpose (task dz2): the dashboard no longer
// double-reserves it (the Stream tab gets the standard content viewport since
// ls2), but while the stream is live with the help bar off the footer and the
// filter stack are not drawn, so up to three of these rows stay blank. Sizing
// the table by what is drawn instead would grow and shrink it on every pause,
// help toggle, status message or filter change - the table's height, its
// paging step and its scroll offset would move under the user - and the
// dashboard's "too small" threshold would depend on that transient state.
// Three spare rows are the price of a table that stays put.
const streamReservedRows = streamTableChromeRows + 1 + 2

// visibleRows is how many event rows the table shows at the current height.
func (m *Model) visibleRows() int {
	if m.height <= 0 {
		return 8
	}
	rows := m.height - streamReservedRows
	if rows < 1 {
		return 1
	}
	return rows
}

func (m *Model) pageStep() int {
	rows := m.visibleRows()
	if rows <= 1 {
		return 1
	}
	return rows - 1
}

func (m *Model) handlePausedTableNavigation(keyStr string) bool {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return true
	}
	m.ensureSelection()
	m.ensureSelectedCol()
	row := m.selectedIdx
	col := m.selectedCol
	if !common.HandleTableNavigationKey(keyStr, &row, &col, len(m.filtered), streamColumnCount, m.pageStep()) {
		return false
	}
	m.selectedIdx = row
	m.selectedCol = col
	m.centerSelection()
	return true
}

// openFDTraceView opens the per-descriptor trace overlay for the selected row
// and reports whether the key was consumed. It is reachable only while the
// stream is paused (see handleStreamKey), so it reads m.allEvents - the
// frozen snapshot the table is showing - and never the live source: the ring
// keeps filling and evicting while paused, so a row still visible in the
// table could already have lost its fd's events from the live ring and the
// trace would come up empty (task 2r2). Every filtered row is a member of
// allEvents, so the selected row always matches itself and the trace is never
// empty; a row without a descriptor is the one case that cannot be traced, and
// it says so in the footer (cleared again by the next key, see
// clearFDTraceStatus) instead of silently ignoring the key.
func (m *Model) openFDTraceView() bool {
	if m.fdTraceView.visible || m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false
	}
	m.statusMessage = ""
	selected := m.filtered[m.selectedIdx]
	if selected.FD < 0 {
		m.statusMessage = fdTraceStatusPrefix + "selected row has no file descriptor"
		return true
	}

	matches := fdLifetimeEvents(m.allEvents, selected)

	m.fdTraceView.visible = true
	m.fdTraceView.pid = selected.PID
	m.fdTraceView.fd = selected.FD
	m.fdTraceView.events = matches
	m.fdTraceView.offset = 0
	return true
}

// fdLifetimeEvents returns the rows of selected's descriptor in events
// (oldest first) that belong to the same life of the number as selected: a
// descriptor number is reused as soon as it is closed, so matching (pid, fd)
// alone merged the rows of every file that ever held the number into one
// trace (task cr2). A life ends at a successful close of the number (included
// in the trace) and the next life starts after it. Only closes ior sees end a
// life: a number reused without a close row in the snapshot (a dup2 over it, an
// io_uring close, a close that fell out of the ring) still shares a trace.
func fdLifetimeEvents(events []StreamEvent, selected StreamEvent) []StreamEvent {
	var life []StreamEvent
	holdsSelected := false
	for i := range events {
		ev := &events[i]
		if ev.PID != selected.PID || ev.FD != selected.FD {
			continue
		}
		life = append(life, *ev)
		holdsSelected = holdsSelected || ev.Seq == selected.Seq
		if !endsFDLife(ev) {
			continue
		}
		if holdsSelected {
			return life
		}
		life = life[:0]
	}
	return life
}

// endsFDLife reports whether ev is a close that succeeded, after which its
// descriptor number is free for the next open.
func endsFDLife(ev *StreamEvent) bool {
	return ev.Syscall == "close" && !ev.IsError
}

// viewFDTrace renders the FD-trace overlay: its panel (five chrome rows plus
// visibleRows event rows) and, when a row is left for it, the footer line.
// visibleRows keeps one event row however short the view, so at six rows the
// panel alone fills it and the footer (with its "esc:back" hint; Esc still
// works) is dropped rather than making the view taller than its budget.
func (m *Model) viewFDTrace(width int) string {
	rows := m.visibleRows()
	start := clamp(m.fdTraceView.offset, 0, m.maxFDTraceOffset())
	end := start + rows
	if end > len(m.fdTraceView.events) {
		end = len(m.fdTraceView.events)
	}
	visible := m.fdTraceView.events[start:end]
	base := RenderFDTraceTable(width, m.fdTraceView.pid, m.fdTraceView.fd, len(m.fdTraceView.events), visible)
	if lipgloss.Height(base) >= m.height {
		return base
	}
	return base + "\n" + fdTraceFooterLine(width, rowNumber(start, len(m.fdTraceView.events)), len(m.fdTraceView.events))
}

func (m *Model) maxFDTraceOffset() int {
	rows := m.visibleRows()
	if len(m.fdTraceView.events) <= rows {
		return 0
	}
	return len(m.fdTraceView.events) - rows
}

func (m *Model) scrollFDTraceByLines(delta int) {
	if delta == 0 {
		return
	}
	max := m.maxFDTraceOffset()
	next := m.fdTraceView.offset + delta
	if next < 0 {
		next = 0
	}
	if next > max {
		next = max
	}
	m.fdTraceView.offset = next
}

func (m *Model) moveSelectionTo(idx int) {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	m.selectedIdx = clamp(idx, 0, len(m.filtered)-1)
	m.ensureSelectedCol()
	m.centerSelection()
}

func (m *Model) centerSelection() {
	if len(m.filtered) == 0 || m.selectedIdx < 0 {
		return
	}
	m.autoScroll = false
	mid := m.visibleRows() / 2
	target := m.selectedIdx - mid
	m.scrollOffset = clamp(target, 0, m.maxScrollOffset())
	m.viewport.SetYOffset(m.scrollOffset)
}

func (m *Model) ensureSelection() {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	if m.selectedIdx >= 0 && m.selectedIdx < len(m.filtered) {
		return
	}
	mid := m.visibleRows() / 2
	m.selectedIdx = clamp(m.scrollOffset+mid, 0, len(m.filtered)-1)
}

func (m *Model) ensureSelectedCol() {
	if m.selectedCol < 0 {
		m.selectedCol = 0
	}
	if m.selectedCol >= streamColumnCount {
		m.selectedCol = streamColumnCount - 1
	}
}

// requestGlobalFilterFromSelectedCell folds the selected cell's value into a
// copy of the current filter and returns a command emitting
// messages.GlobalFilterRequestedMsg. The local filter is left unchanged: the
// parent applies the shared filter and pushes it back via SetFilter.
//
// The action label is the presenter's canonical token for the dimension just
// set, so it reads exactly like the filter summary. A cell that yields no
// filter (a blank string cell, a placeholder cell - the File of a fileless
// row, the Latency or Ret of a noreturn row - or an unknown column) is not
// handled, so no empty undo layer is pushed. Nor does a warning row yield
// one: it is drawn as one spanning line without cells (renderWarningRow),
// every value behind it is a placeholder (pid 0, ret -1, the "warning"
// label), and a filter built from one would select by a value the user
// cannot see. Enter never gets here with one (handleEnterKey shows its
// message instead); the check keeps that true for any other caller.
func (m *Model) requestGlobalFilterFromSelectedCell() (bool, tea.Cmd) {
	if m.fdTraceView.visible || m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false, nil
	}
	ev := &m.filtered[m.selectedIdx]
	if ev.IsWarning {
		return false, nil
	}
	next := m.filter.Clone()
	dim, ok := setStringCellFilter(&next, ev, m.selectedCol)
	if !ok {
		dim, ok = setNumericCellFilter(&next, ev, m.selectedCol)
	}
	if !ok {
		return false, nil
	}
	action := presenter.DimensionSummary(next, dim)
	if action == "" {
		return false, nil
	}
	return true, emit(messages.GlobalFilterRequestedMsg{Filter: next, Action: action})
}

// setStringCellFilter sets next's Comm, Syscall or File filter to exactly the
// selected string cell's value and reports the dimension it set; ok is false
// for a non-string column or a blank cell (a blank value constrains nothing).
// A File cell of a fileless row (ev.NoFile, rendered as event.NoFileName)
// counts as blank: the placeholder is display text for "no file", while the
// global filter sees such a row's or live pair's file as "" (streamrow
// Row.FileValue, globalfilter pairCandidate.FileValue), so ^N:file$ would match
// nothing at all and blank the stream instead of selecting the fileless rows.
// The flag, not the text, decides: a real file literally named "N:file" shows
// the same cell text but its filter ^N:file$ matches it, so Enter works there.
//
// The pattern is globalfilter.ExactPattern (^value$), matching the dashboard
// row filters: Enter on "read" must not also admit readv/pread64, on
// "/tmp/a" not also "/tmp/ab", and a value's edge blanks or literal edge ^/$
// stay literal instead of being trimmed or read as anchors. Unlike the
// dashboard Processes tab's Comm cell (a substring, because that row counts
// every thread of a PID), a Stream row is one event and its Comm cell is
// that event's own thread comm, so exact is right here too.
func setStringCellFilter(next *Filter, ev *StreamEvent, col int) (presenter.Dimension, bool) {
	var value string
	var target **StringFilter
	var dim presenter.Dimension
	switch col {
	case streamColComm:
		value, target, dim = ev.Comm, &next.Comm, presenter.DimComm
	case streamColSyscall:
		value, target, dim = ev.Syscall, &next.Syscall, presenter.DimSyscall
	case streamColFile:
		value, target, dim = ev.FileName, &next.File, presenter.DimFile
		if ev.NoFile {
			return dim, false
		}
	default:
		return dim, false
	}
	if strings.TrimSpace(value) == "" {
		return dim, false
	}
	*target = &StringFilter{Pattern: globalfilter.ExactPattern(value)}
	return dim, true
}

// setNumericCellFilter sets next's numeric filter for the selected numeric
// cell and reports the dimension it set; ok is false for a non-numeric
// column. Durations become lower bounds (>=) so the filter keeps the selected
// event and everything slower; identifiers and counts use equality.
//
// The Latency and Ret cells of a noreturn row (ev.NoReturn: exit, exit_group,
// rt_sigreturn) are refused like the File cell of a fileless row: they render
// "-" because the row has neither value, and the 0s behind them are
// placeholders. Building a filter from them would select by a value the row
// does not have (latency >= 0 matches every row, ret == 0 every successful
// one), and the global filter rejects a noreturn row on either dimension
// anyway (globalfilter.Candidate.NoReturnValue), so not even the selected row
// would survive it.
func setNumericCellFilter(next *Filter, ev *StreamEvent, col int) (presenter.Dimension, bool) {
	switch col {
	case streamColGap:
		next.GapNs = &NumericFilter{Op: OpGte, Value: int64(ev.GapNs)}
		return presenter.DimGap, true
	case streamColLatency:
		if ev.NoReturn {
			return presenter.DimLatency, false
		}
		next.LatencyNs = &NumericFilter{Op: OpGte, Value: int64(ev.DurationNs)}
		return presenter.DimLatency, true
	case streamColPID:
		next.PID = &NumericFilter{Op: OpEq, Value: int64(ev.PID)}
		return presenter.DimPID, true
	case streamColTID:
		next.TID = &NumericFilter{Op: OpEq, Value: int64(ev.TID)}
		return presenter.DimTID, true
	case streamColFD:
		next.FD = &NumericFilter{Op: OpEq, Value: int64(ev.FD)}
		return presenter.DimFD, true
	case streamColRet:
		if ev.NoReturn {
			return presenter.DimRet, false
		}
		next.RetVal = &NumericFilter{Op: OpEq, Value: ev.RetVal}
		return presenter.DimRet, true
	case streamColBytes:
		next.Bytes = &NumericFilter{Op: OpEq, Value: int64(ev.Bytes)}
		return presenter.DimBytes, true
	}
	return 0, false
}

func (m *Model) currentSelectedSeq() uint64 {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return 0
	}
	return m.filtered[m.selectedIdx].Seq
}

func (m *Model) restoreSelectionBySeq(seq uint64) {
	if !m.paused || seq == 0 || len(m.filtered) == 0 {
		return
	}
	for i := range m.filtered {
		if m.filtered[i].Seq == seq {
			m.selectedIdx = i
			m.centerSelection()
			return
		}
	}
}

func (m *Model) clampSelection() {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	if m.selectedIdx < 0 {
		return
	}
	m.selectedIdx = clamp(m.selectedIdx, 0, len(m.filtered)-1)
}

func rowNumber(start, total int) int {
	if total == 0 {
		return 0
	}
	return start + 1
}

func clamp(v, min, max int) int {
	if max < min {
		return min
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// SetStatusMessage updates the stream footer status line.
func (m *Model) SetStatusMessage(message string) {
	m.statusMessage = message
}

func (m *Model) openSearch(direction SearchDirection) {
	m.paused = true
	m.ensureSelection()
	m.ensureSelectedCol()
	m.centerSelection()
	m.searchModal = m.searchModal.Open(direction, m.searchPattern)
}

func (m *Model) submitSearch(term string, direction SearchDirection) bool {
	re, err := regexp.Compile(term)
	if err != nil {
		m.statusMessage = fmt.Sprintf("Invalid regex: %v", err)
		return true
	}
	m.searchPattern = term
	m.searchRegex = re
	m.searchDirection = direction
	return m.jumpSearch(direction)
}

func (m *Model) jumpSearch(direction SearchDirection) bool {
	if m.searchRegex == nil {
		return false
	}
	if len(m.filtered) == 0 {
		m.statusMessage = "Search: no rows"
		return true
	}
	start := m.selectedIdx
	if start < 0 || start >= len(m.filtered) {
		if direction == SearchForward {
			start = -1
		} else {
			start = len(m.filtered)
		}
	}
	next := m.findMatch(start, direction)
	if next < 0 {
		m.statusMessage = fmt.Sprintf("No match: %q", m.searchPattern)
		return true
	}
	m.moveSelectionTo(next)
	prefix := "/"
	if direction == SearchBackward {
		prefix = "?"
	}
	m.statusMessage = fmt.Sprintf("%s%s @ row %d/%d", prefix, m.searchPattern, next+1, len(m.filtered))
	return true
}

func (m *Model) findMatch(start int, direction SearchDirection) int {
	n := len(m.filtered)
	if n == 0 {
		return -1
	}
	step := int(direction)
	for offset := 1; offset <= n; offset++ {
		idx := (start + step*offset + n) % n
		if streamEventMatchesRegex(m.filtered[idx], m.searchRegex) {
			return idx
		}
	}
	return -1
}

// streamEventMatchesRegex reports whether the paused search's pattern matches
// a row: any of its text cells, any of its numbers in decimal, or the word
// "error" on a failed call. A warning row is matched by the one line it shows
// (warningLine) and by nothing else: its other values are placeholders that
// are not drawn (comm "ior", pid 0, ret -1, 0 bytes, the error flag), and
// /^0$ or /^ior$ used to stop on a row showing neither.
func streamEventMatchesRegex(ev StreamEvent, re *regexp.Regexp) bool {
	if re == nil {
		return false
	}
	if ev.IsWarning {
		return re.MatchString(warningLine(ev))
	}
	if re.MatchString(ev.Syscall) || re.MatchString(ev.Comm) || re.MatchString(ev.FileName) {
		return true
	}
	if re.MatchString(strconv.FormatUint(ev.Seq, 10)) ||
		re.MatchString(strconv.FormatUint(ev.TimeNs, 10)) ||
		re.MatchString(strconv.FormatUint(uint64(ev.PID), 10)) ||
		re.MatchString(strconv.FormatUint(uint64(ev.TID), 10)) ||
		re.MatchString(strconv.FormatInt(int64(ev.FD), 10)) ||
		re.MatchString(strconv.FormatInt(ev.RetVal, 10)) ||
		re.MatchString(strconv.FormatUint(ev.Bytes, 10)) ||
		re.MatchString(strconv.FormatUint(ev.GapNs, 10)) ||
		re.MatchString(strconv.FormatUint(ev.DurationNs, 10)) {
		return true
	}
	if ev.IsError && re.MatchString("error") {
		return true
	}
	return false
}
