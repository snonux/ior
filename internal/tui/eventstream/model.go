package eventstream

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/common"
	"ior/internal/tui/messages"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
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
	}
	if height > 0 {
		m.height = height
		m.viewport.SetHeight(m.visibleRows())
	}
}

// SetFooterVisible controls whether stream footer/status lines are shown.
func (m *Model) SetFooterVisible(visible bool) {
	m.showFooter = visible
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

// Paused reports whether stream refresh is currently paused.
func (m *Model) Paused() bool {
	return m.paused
}

// HandleKey dispatches keyStr to the active modal or live/paused stream handlers.
// It reports whether the key was consumed (false means the caller should
// handle it) and returns a command for any request the stream cannot fulfil
// itself: it emits messages.GlobalFilterRequestedMsg,
// messages.GlobalFilterUndoRequestedMsg or messages.OpenEditorRequestedMsg
// for the parent to act on. The command is nil when the key only changed
// local stream state.
func (m *Model) HandleKey(keyStr string) (bool, tea.Cmd) {
	if m.searchModal.Visible() {
		return m.handleSearchModalKey(keyStr), nil
	}
	if m.exportModal.Visible() {
		return m.handleExportModalKey(keyStr), nil
	}
	if m.fdTraceView.visible {
		return m.handleFDTraceKey(keyStr), nil
	}
	return m.handleStreamKey(keyStr)
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
func (m *Model) handleSearchModalKey(keyStr string) bool {
	m.statusMessage = ""
	var (
		term   string
		submit bool
	)
	m.searchModal, term, submit = m.searchModal.Update(keyMsgFromString(keyStr))
	if !submit {
		return true
	}
	return m.submitSearch(term, m.searchModal.Direction())
}

// handleExportModalKey routes a key press while the export modal is open.
func (m *Model) handleExportModalKey(keyStr string) bool {
	m.statusMessage = ""
	var (
		filename string
		submit   bool
	)
	m.exportModal, filename, submit = m.exportModal.Update(keyMsgFromString(keyStr))
	if !submit {
		return true
	}
	path, err := m.exportFilteredToCSV(filename)
	if err != nil {
		m.statusMessage = fmt.Sprintf("Export failed: %v", err)
		return true
	}
	m.lastExportPath = path
	m.statusMessage = "Exported: " + path
	return true
}

// handleFDTraceKey routes a key press while the FD-trace overlay is visible.
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
		return false
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
	switch keyStr {
	case "x", "X", "E":
		return m.handleStreamExportKey(keyStr)
	case "enter":
		if m.paused {
			return m.requestGlobalFilterFromSelectedCell()
		}
		return false, nil
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

// requestGlobalFilterUndo returns a command asking the parent to pop the
// latest shared filter layer. The key is consumed only when allowed and
// there is a layer to pop; otherwise it falls through to the caller.
func (m *Model) requestGlobalFilterUndo(allowed bool) (bool, tea.Cmd) {
	if !allowed || len(m.filterStack) == 0 {
		return false, nil
	}
	return true, emit(messages.GlobalFilterUndoRequestedMsg{})
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
	// Map multi-word key names to canonical viewport key strings.
	vpKey := keyStr
	switch keyStr {
	case "pgdown", "pgdn", "pagedown":
		vpKey = "pgdown"
	case "pgup", "pageup":
		vpKey = "pgup"
	}
	return m.handleViewportUpdate(keyMsgFromString(vpKey))
}

// HandleTeaKey handles stream keys based on Bubble Tea key message types first,
// then falls back to string matching for rune-driven shortcuts. Its results
// have the same meaning as HandleKey's.
func (m *Model) HandleTeaKey(msg tea.KeyPressMsg) (bool, tea.Cmd) {
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
	// The paused selection/column/search footer is essential interaction
	// feedback while the user navigates rows and columns, so render it whenever
	// the stream is paused, independent of the dashboard help-bar toggle
	// (m.showFooter). The live Row x/N footer remains tied to the help bar.
	if !m.showFooter && !m.paused {
		return base
	}
	return m.appendStreamFooter(base, start)
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
	base := RenderStreamTable(width, m.paused, len(m.allEvents), len(m.filtered), bufferLen, ringBufferCapacity, m.filter, m.filterStack, visible, selectedVisibleIdx, selectedCol)
	return base, start
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
// and the CSV export use it, so the export contains exactly the rows the
// Stream tab shows.
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

func (m *Model) visibleRows() int {
	if m.height <= 0 {
		return 8
	}
	rows := m.height - 8
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

func (m *Model) openFDTraceView() bool {
	if m.fdTraceView.visible || m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false
	}
	selected := m.filtered[m.selectedIdx]
	if selected.FD < 0 {
		return false
	}

	snapshot := m.allEvents
	if m.source != nil {
		snapshot = m.source.Snapshot()
	}

	matches := make([]StreamEvent, 0, len(snapshot))
	for i := range snapshot {
		ev := snapshot[i]
		if ev.PID == selected.PID && ev.FD == selected.FD {
			matches = append(matches, ev)
		}
	}
	if len(matches) == 0 {
		return false
	}

	m.fdTraceView.visible = true
	m.fdTraceView.pid = selected.PID
	m.fdTraceView.fd = selected.FD
	m.fdTraceView.events = matches
	m.fdTraceView.offset = 0
	return true
}

func (m *Model) viewFDTrace(width int) string {
	rows := m.visibleRows()
	start := clamp(m.fdTraceView.offset, 0, m.maxFDTraceOffset())
	end := start + rows
	if end > len(m.fdTraceView.events) {
		end = len(m.fdTraceView.events)
	}
	visible := m.fdTraceView.events[start:end]
	base := RenderFDTraceTable(width, m.fdTraceView.pid, m.fdTraceView.fd, len(m.fdTraceView.events), visible)
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
// filter (a blank string cell, an unknown column) is not handled, so no empty
// undo layer is pushed.
func (m *Model) requestGlobalFilterFromSelectedCell() (bool, tea.Cmd) {
	if m.fdTraceView.visible || m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false, nil
	}
	ev := &m.filtered[m.selectedIdx]
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
// A File cell showing event.NoFileName counts as blank: the placeholder is
// display text for "no file", while the global filter sees such a row's or
// live pair's file as "" (streamrow Row.FileValue, globalfilter
// pairCandidate.FileValue), so ^N:file$ would match nothing at all and blank
// the stream instead of selecting the fileless rows.
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
		if value == event.NoFileName {
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
func setNumericCellFilter(next *Filter, ev *StreamEvent, col int) (presenter.Dimension, bool) {
	switch col {
	case streamColGap:
		next.GapNs = &NumericFilter{Op: OpGte, Value: int64(ev.GapNs)}
		return presenter.DimGap, true
	case streamColLatency:
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

func keyMsgFromString(keyStr string) tea.KeyPressMsg {
	switch keyStr {
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEsc}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case " ", "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	}
	if keyStr == "" {
		return tea.KeyPressMsg{}
	}
	runes := []rune(keyStr)
	return tea.KeyPressMsg{Code: runes[0], Text: keyStr}
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

func streamEventMatchesRegex(ev StreamEvent, re *regexp.Regexp) bool {
	if re == nil {
		return false
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
