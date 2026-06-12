package eventstream

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ior/internal/tui/common"

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

type Model struct {
	source Source

	allEvents []StreamEvent
	filtered  []StreamEvent

	filter      Filter
	filterStack []string

	paused bool

	scrollOffset        int
	autoScroll          bool
	selectedIdx         int
	selectedCol         int
	fdTraceView         fdTraceViewState
	exportModal         ExportModal
	searchModal         SearchModal
	searchPattern       string
	searchRegex         *regexp.Regexp
	searchDirection     SearchDirection
	lastExportPath      string
	pendingOpenPath     string
	pendingFilter       Filter
	pendingFilterAction string
	hasPendingFilter    bool
	pendingUndo         bool
	statusMessage       string
	exportDir           string
	isDark              bool

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

func NewModel(source Source) Model {
	m := Model{
		source:      source,
		exportModal: NewExportModal(),
		searchModal: NewSearchModal(),
		autoScroll:  true,
		selectedIdx: -1,
		selectedCol: 0,
		exportDir:   ".",
		showFooter:  true,
		isDark:      true,
		viewport:    newStreamViewport(),
	}
	m.SetDarkMode(true)
	return m
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
func (m Model) FilterModalVisible() bool {
	return false
}

// ExportModalVisible reports whether the stream export modal is currently open.
func (m Model) ExportModalVisible() bool {
	return m.exportModal.Visible()
}

// SearchModalVisible reports whether the stream search modal is currently open.
func (m Model) SearchModalVisible() bool {
	return m.searchModal.Visible()
}

// Paused reports whether stream refresh is currently paused.
func (m Model) Paused() bool {
	return m.paused
}

// HandleKey dispatches keyStr to the active modal or live/paused stream handlers.
// It returns true if the key was consumed, false if the caller should handle it.
func (m *Model) HandleKey(keyStr string) bool {
	if m.searchModal.Visible() {
		return m.handleSearchModalKey(keyStr)
	}
	if m.exportModal.Visible() {
		return m.handleExportModalKey(keyStr)
	}
	if m.fdTraceView.visible {
		return m.handleFDTraceKey(keyStr)
	}
	return m.handleStreamKey(keyStr)
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

// handleStreamExportKey handles x/X/E export shortcuts while the stream is paused.
func (m *Model) handleStreamExportKey(keyStr string) (bool, bool) {
	switch keyStr {
	case "x":
		if !m.paused {
			return false, true
		}
		m.statusMessage = ""
		path, err := m.exportFilteredToCSV(defaultStreamExportFilename())
		if err != nil {
			m.statusMessage = fmt.Sprintf("Export failed: %v", err)
			return true, true
		}
		m.lastExportPath = path
		m.statusMessage = "Exported: " + path
		return true, true
	case "X":
		if !m.paused {
			return false, true
		}
		m.statusMessage = ""
		m.exportModal = m.exportModal.Open(defaultStreamExportFilename())
		return true, true
	case "E":
		if !m.paused {
			return false, true
		}
		m.statusMessage = ""
		if m.lastExportPath == "" {
			m.statusMessage = "No stream export yet"
			return true, true
		}
		m.pendingOpenPath = m.lastExportPath
		m.statusMessage = "Opening in editor: " + m.lastExportPath
		return true, true
	}
	return false, false
}

// handleStreamKey handles keys for the main live/paused stream table.
func (m *Model) handleStreamKey(keyStr string) bool {
	if consumed, handled := m.handleStreamExportKey(keyStr); handled {
		return consumed
	}

	switch keyStr {
	case "enter":
		if m.paused {
			return m.requestGlobalFilterFromSelectedCell()
		}
		return false
	case "F":
		if len(m.filterStack) == 0 {
			return false
		}
		m.pendingUndo = true
		return true
	case "T":
		if !m.paused {
			return false
		}
		return m.openFDTraceView()
	case "esc":
		if m.paused && len(m.filterStack) > 0 {
			m.pendingUndo = true
			return true
		}
		return false
	case "/":
		m.openSearch(SearchForward)
		return true
	case "?":
		m.openSearch(SearchBackward)
		return true
	case "n":
		if m.searchRegex == nil {
			return false
		}
		return m.jumpSearch(m.searchDirection)
	case "N":
		if m.searchRegex == nil {
			return false
		}
		return m.jumpSearch(-m.searchDirection)
	case " ", "space":
		return m.handleSpaceKey()
	case "G", "g", "j", "down", "k", "up", "left", "h", "right", "l",
		"pgdown", "pgdn", "pagedown", "pgup", "pageup":
		return m.handleNavigationKey(keyStr)
	default:
		return false
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
// then falls back to string matching for rune-driven shortcuts.
func (m *Model) HandleTeaKey(msg tea.KeyPressMsg) bool {
	if m.handleViewportUpdate(msg) {
		return true
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
	if !m.showFooter {
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

// appendStreamFooter appends the status line (and optional status message) to
// the rendered table string using a Builder to minimise allocations.
func (m *Model) appendStreamFooter(base string, start int) string {
	status := fmt.Sprintf("Row %d/%d", rowNumber(start, len(m.filtered)), len(m.filtered))
	if m.paused && m.selectedIdx >= 0 {
		status = fmt.Sprintf("Row %d/%d | Sel %d/%d Col %d/%d | Enter push-filter | T fd-trace | Esc/F undo",
			rowNumber(start, len(m.filtered)), len(m.filtered),
			rowNumber(m.selectedIdx, len(m.filtered)), len(m.filtered),
			m.selectedCol+1, streamColumnCount)
	}
	// Use a Builder to avoid a redundant allocation for the optional status-message
	// line appended conditionally on every render call.
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n")
	b.WriteString(status)
	if m.statusMessage != "" {
		b.WriteString("\n")
		b.WriteString(m.statusMessage)
	}
	return b.String()
}

func (m *Model) Refresh() {
	if m.paused {
		return
	}
	if m.source == nil {
		m.allEvents = []StreamEvent{}
		m.filtered = []StreamEvent{}
		m.scrollOffset = 0
		m.viewport.SetContentLines(nil)
		m.viewport.SetYOffset(0)
		return
	}

	m.allEvents = m.source.Snapshot()
	m.applyFilter()
}

func (m *Model) applyFilter() {
	if len(m.allEvents) == 0 {
		m.filtered = []StreamEvent{}
		m.scrollOffset = 0
		m.selectedIdx = -1
		m.viewport.SetContentLines(nil)
		m.viewport.SetYOffset(0)
		return
	}

	filtered := make([]StreamEvent, 0, len(m.allEvents))
	for i := range m.allEvents {
		ev := m.allEvents[i]
		if m.filter.Matches(&ev) {
			filtered = append(filtered, ev)
		}
	}
	m.filtered = filtered
	m.viewport.SetWidth(m.width)
	m.viewport.SetHeight(m.visibleRows())
	lines := make([]string, len(m.filtered))
	m.viewport.SetContentLines(lines)

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
	status := fmt.Sprintf("FD Trace Row %d/%d | esc:back j/k:scroll", rowNumber(start, len(m.fdTraceView.events)), len(m.fdTraceView.events))
	return base + "\n" + status
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

func (m *Model) requestGlobalFilterFromSelectedCell() bool {
	if m.fdTraceView.visible || m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false
	}
	ev := m.filtered[m.selectedIdx]
	next := m.filter.Clone()

	switch m.selectedCol {
	case streamColGap:
		next.GapNs = &NumericFilter{Op: OpGte, Value: int64(ev.GapNs)}
		m.pendingFilterAction = fmt.Sprintf("gap>=%s", formatDurationNs(ev.GapNs))
	case streamColLatency:
		next.LatencyNs = &NumericFilter{Op: OpGte, Value: int64(ev.DurationNs)}
		m.pendingFilterAction = fmt.Sprintf("latency>=%s", formatDurationNs(ev.DurationNs))
	case streamColComm:
		next.Comm = &StringFilter{Pattern: ev.Comm}
		m.pendingFilterAction = "comm~" + ev.Comm
	case streamColPID:
		next.PID = &NumericFilter{Op: OpEq, Value: int64(ev.PID)}
		m.pendingFilterAction = fmt.Sprintf("pid=%d", ev.PID)
	case streamColTID:
		next.TID = &NumericFilter{Op: OpEq, Value: int64(ev.TID)}
		m.pendingFilterAction = fmt.Sprintf("tid=%d", ev.TID)
	case streamColSyscall:
		next.Syscall = &StringFilter{Pattern: ev.Syscall}
		m.pendingFilterAction = "syscall~" + ev.Syscall
	case streamColFD:
		next.FD = &NumericFilter{Op: OpEq, Value: int64(ev.FD)}
		m.pendingFilterAction = fmt.Sprintf("fd=%d", ev.FD)
	case streamColRet:
		next.RetVal = &NumericFilter{Op: OpEq, Value: ev.RetVal}
		m.pendingFilterAction = fmt.Sprintf("ret=%d", ev.RetVal)
	case streamColBytes:
		next.Bytes = &NumericFilter{Op: OpEq, Value: int64(ev.Bytes)}
		m.pendingFilterAction = fmt.Sprintf("bytes=%d", ev.Bytes)
	case streamColFile:
		next.File = &StringFilter{Pattern: ev.FileName}
		m.pendingFilterAction = "file~" + ev.FileName
	default:
		return false
	}

	m.pendingFilter = next
	m.hasPendingFilter = true
	return true
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

func (m *Model) setFilterForTest(f Filter) {
	m.filter = f
}

func (m *Model) setExportDirForTest(dir string) {
	m.exportDir = dir
}

// ConsumeOpenEditorRequest returns the pending editor-open path once.
func (m *Model) ConsumeOpenEditorRequest() (string, bool) {
	if m.pendingOpenPath == "" {
		return "", false
	}
	path := m.pendingOpenPath
	m.pendingOpenPath = ""
	return path, true
}

// ConsumeGlobalFilterRequest returns the pending global-filter request once.
func (m *Model) ConsumeGlobalFilterRequest() (Filter, string, bool) {
	if !m.hasPendingFilter {
		return Filter{}, "", false
	}
	filter := m.pendingFilter.Clone()
	action := m.pendingFilterAction
	m.pendingFilter = Filter{}
	m.pendingFilterAction = ""
	m.hasPendingFilter = false
	return filter, action, true
}

// ConsumeGlobalFilterUndoRequest returns the pending undo request once.
func (m *Model) ConsumeGlobalFilterUndoRequest() bool {
	if !m.pendingUndo {
		return false
	}
	m.pendingUndo = false
	return true
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

func (m *Model) dumpVisibleForTest() string {
	rows := make([]string, 0, len(m.filtered))
	for _, ev := range m.filtered {
		rows = append(rows, ev.Syscall)
	}
	return strings.Join(rows, ",")
}
