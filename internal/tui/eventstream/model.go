package eventstream

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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

type Model struct {
	source *RingBuffer

	allEvents []StreamEvent
	filtered  []StreamEvent

	filter      Filter
	filterModal FilterModal

	paused bool
	// pauseBeforeFilter keeps the pre-modal pause state so opening the filter
	// can pause refresh temporarily without losing the user's prior state.
	pauseBeforeFilter bool

	scrollOffset      int
	autoScroll        bool
	selectedIdx       int
	selectedCol       int
	fdTraceView       fdTraceViewState
	filterStack       []Filter
	filterActionStack []string
	exportModal       ExportModal
	lastExportPath    string
	pendingOpenPath   string
	statusMessage     string
	exportDir         string

	width  int
	height int
}

type fdTraceViewState struct {
	visible bool
	pid     uint32
	fd      int32
	events  []StreamEvent
	offset  int
}

func NewModel(source *RingBuffer) Model {
	return Model{
		source:      source,
		filterModal: NewFilterModal(),
		exportModal: NewExportModal(),
		autoScroll:  true,
		selectedIdx: -1,
		selectedCol: 0,
		exportDir:   ".",
	}
}

// SetViewport updates the render/scroll viewport dimensions used for
// max-scroll and page-step calculations during key handling.
func (m *Model) SetViewport(width, height int) {
	if width > 0 {
		m.width = width
	}
	if height > 0 {
		m.height = height
	}
}

// SetSource updates the backing ring buffer and refreshes visible rows.
func (m *Model) SetSource(source *RingBuffer) {
	m.source = source
	m.Refresh()
}

// FilterModalVisible reports whether the filter modal is currently open.
func (m Model) FilterModalVisible() bool {
	return m.filterModal.Visible()
}

// ExportModalVisible reports whether the stream export modal is currently open.
func (m Model) ExportModalVisible() bool {
	return m.exportModal.Visible()
}

// Paused reports whether stream refresh is currently paused.
func (m Model) Paused() bool {
	return m.paused
}

func (m *Model) HandleKey(keyStr string) bool {
	if m.exportModal.Visible() {
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
	if m.filterModal.Visible() {
		wasVisible := m.filterModal.Visible()
		m.filterModal = m.filterModal.Update(keyMsgFromString(keyStr))
		if wasVisible && !m.filterModal.Visible() {
			m.filter = m.filterModal.Filter()
			m.filterStack = nil
			m.filterActionStack = nil
			m.paused = m.pauseBeforeFilter
			m.applyFilter()
			if !m.paused {
				m.Refresh()
			}
		}
		return true
	}
	if m.fdTraceView.visible {
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

	switch keyStr {
	case "enter":
		if m.paused {
			return m.applyFilterFromSelectedCell()
		}
		return false
	case "x":
		if !m.paused {
			return false
		}
		m.statusMessage = ""
		path, err := m.exportFilteredToCSV(defaultStreamExportFilename())
		if err != nil {
			m.statusMessage = fmt.Sprintf("Export failed: %v", err)
			return true
		}
		m.lastExportPath = path
		m.statusMessage = "Exported: " + path
		return true
	case "X":
		if !m.paused {
			return false
		}
		m.statusMessage = ""
		m.exportModal = m.exportModal.Open(defaultStreamExportFilename())
		return true
	case "E":
		if !m.paused {
			return false
		}
		m.statusMessage = ""
		if m.lastExportPath == "" {
			m.statusMessage = "No stream export yet"
			return true
		}
		m.pendingOpenPath = m.lastExportPath
		m.statusMessage = "Opening in editor: " + m.lastExportPath
		return true
	case " ", "space":
		m.paused = !m.paused
		if !m.paused {
			// Resuming should return to live-tail behavior immediately.
			m.autoScroll = true
			m.selectedIdx = -1
			m.Refresh()
		} else {
			m.ensureSelection()
			m.ensureSelectedCol()
			m.centerSelection()
		}
		return true
	case "f", "F":
		m.pauseBeforeFilter = m.paused
		m.paused = true
		m.filterModal = m.filterModal.Open(m.filter)
		return true
	case "G":
		if m.paused {
			m.moveSelectionTo(len(m.filtered) - 1)
		} else {
			m.autoScroll = true
			m.scrollOffset = m.maxScrollOffset()
		}
		return true
	case "g":
		if m.paused {
			m.moveSelectionTo(0)
		} else {
			m.autoScroll = false
			m.scrollOffset = 0
		}
		return true
	case "c":
		m.filter = Filter{}
		m.filterStack = nil
		m.filterActionStack = nil
		m.applyFilter()
		return true
	case "j", "down":
		if m.paused {
			m.moveSelectionBy(1)
		} else {
			m.scrollByLines(1)
		}
		return true
	case "k", "up":
		if m.paused {
			m.moveSelectionBy(-1)
		} else {
			m.scrollByLines(-1)
		}
		return true
	case "left", "h":
		if m.paused {
			m.moveSelectedColBy(-1)
			return true
		}
		return false
	case "right", "l":
		if m.paused {
			m.moveSelectedColBy(1)
			return true
		}
		return false
	case "pgdown", "pgdn", "pagedown":
		if m.paused {
			m.moveSelectionBy(m.pageStep())
		} else {
			m.scrollByLines(m.pageStep())
		}
		return true
	case "pgup", "pageup":
		if m.paused {
			m.moveSelectionBy(-m.pageStep())
		} else {
			m.scrollByLines(-m.pageStep())
		}
		return true
	case "esc":
		if m.paused {
			return m.popFilter()
		}
		return false
	default:
		return false
	}
}

// HandleTeaKey handles stream keys based on Bubble Tea key message types first,
// then falls back to string matching for rune-driven shortcuts.
func (m *Model) HandleTeaKey(msg tea.KeyMsg) bool {
	switch msg.Type {
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
	case tea.KeyRunes:
		if len(msg.Runes) == 1 {
			return m.HandleKey(string(msg.Runes[0]))
		}
	}
	return m.HandleKey(msg.String())
}

func (m *Model) View(width, height int) string {
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 24
	}
	m.width = width
	m.height = height

	if m.fdTraceView.visible {
		return m.viewFDTrace(width)
	}

	rows := m.visibleRows()
	start := clamp(m.scrollOffset, 0, m.maxScrollOffset())
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
	base := RenderStreamTable(width, m.paused, len(m.allEvents), len(m.filtered), bufferLen, ringBufferCapacity, m.filter, visible, selectedVisibleIdx, selectedCol)
	status := fmt.Sprintf("Row %d/%d | space:pause f:filter G:tail g:top c:clear j/k:scroll", rowNumber(start, len(m.filtered)), len(m.filtered))
	if m.paused && m.selectedIdx >= 0 {
		status = fmt.Sprintf("Row %d/%d | Sel %d/%d Col %d/%d | enter:add-filter esc:undo(%d) x:export X:export-as E:open-last space:pause f:filter G:tail g:top c:clear j/k:row h/l:col", rowNumber(start, len(m.filtered)), len(m.filtered), rowNumber(m.selectedIdx, len(m.filtered)), len(m.filtered), m.selectedCol+1, streamColumnCount, len(m.filterStack))
	}
	out := base + "\n" + status
	if len(m.filterActionStack) > 0 {
		out += "\n" + "Stack: " + strings.Join(m.filterActionStack, " | ")
	}
	if m.statusMessage != "" {
		out += "\n" + m.statusMessage
	}

	if m.filterModal.Visible() {
		// While editing filters, show a dedicated modal screen to avoid
		// visual mixing with the live stream table underneath.
		return m.filterModal.View(width, height)
	}
	if m.exportModal.Visible() {
		return m.exportModal.View(width, height)
	}
	return out
}

func (m *Model) Refresh() {
	if m.paused {
		return
	}
	if m.source == nil {
		m.allEvents = []StreamEvent{}
		m.filtered = []StreamEvent{}
		m.scrollOffset = 0
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

	max := m.maxScrollOffset()
	if m.autoScroll {
		m.scrollOffset = max
	} else {
		m.scrollOffset = clamp(m.scrollOffset, 0, max)
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

func (m *Model) scrollByLines(delta int) {
	if delta == 0 {
		return
	}
	max := m.maxScrollOffset()
	next := m.scrollOffset + delta
	if next < 0 {
		next = 0
	}
	if next > max {
		next = max
	}
	if next != m.scrollOffset {
		m.scrollOffset = next
	}
	if m.scrollOffset < max {
		m.autoScroll = false
	}
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

func (m *Model) moveSelectionBy(delta int) {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	m.ensureSelection()
	m.ensureSelectedCol()
	m.moveSelectionTo(m.selectedIdx + delta)
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

func (m *Model) moveSelectedColBy(delta int) {
	if delta == 0 {
		return
	}
	m.ensureSelectedCol()
	m.selectedCol = clamp(m.selectedCol+delta, 0, streamColumnCount-1)
}

func (m *Model) applyFilterFromSelectedCell() bool {
	if m.selectedIdx < 0 || m.selectedIdx >= len(m.filtered) {
		return false
	}
	ev := m.filtered[m.selectedIdx]
	targetSeq := ev.Seq
	next := cloneFilter(m.filter)
	action := ""

	switch m.selectedCol {
	case streamColGap:
		next.GapNs = &NumericFilter{Op: OpGte, Value: int64(ev.GapNs)}
		action = fmt.Sprintf("gap>=%dns", ev.GapNs)
	case streamColLatency:
		next.LatencyNs = &NumericFilter{Op: OpGte, Value: int64(ev.DurationNs)}
		action = fmt.Sprintf("latency>=%dns", ev.DurationNs)
	case streamColComm:
		next.Comm = &StringFilter{Pattern: ev.Comm}
		action = fmt.Sprintf("comm~%s", ev.Comm)
	case streamColPID:
		next.PID = &NumericFilter{Op: OpEq, Value: int64(ev.PID)}
		action = fmt.Sprintf("pid=%d", ev.PID)
	case streamColTID:
		next.TID = &NumericFilter{Op: OpEq, Value: int64(ev.TID)}
		action = fmt.Sprintf("tid=%d", ev.TID)
	case streamColSyscall:
		next.Syscall = &StringFilter{Pattern: ev.Syscall}
		action = fmt.Sprintf("syscall~%s", ev.Syscall)
	case streamColFD:
		next.FD = &NumericFilter{Op: OpEq, Value: int64(ev.FD)}
		action = fmt.Sprintf("fd=%d", ev.FD)
	case streamColRet:
		next.RetVal = &NumericFilter{Op: OpEq, Value: ev.RetVal}
		action = fmt.Sprintf("ret=%d", ev.RetVal)
	case streamColBytes:
		next.Bytes = &NumericFilter{Op: OpEq, Value: int64(ev.Bytes)}
		action = fmt.Sprintf("bytes=%d", ev.Bytes)
	case streamColFile:
		next.File = &StringFilter{Pattern: ev.FileName}
		action = fmt.Sprintf("file~%s", ev.FileName)
	default:
		return false
	}

	m.filterStack = append(m.filterStack, cloneFilter(m.filter))
	m.filterActionStack = append(m.filterActionStack, action)
	m.filter = next
	m.applyFilter()
	m.restoreSelectionBySeq(targetSeq)
	return true
}

func (m *Model) popFilter() bool {
	if len(m.filterStack) == 0 {
		return false
	}
	targetSeq := m.currentSelectedSeq()
	last := m.filterStack[len(m.filterStack)-1]
	m.filterStack = m.filterStack[:len(m.filterStack)-1]
	if len(m.filterActionStack) > 0 {
		m.filterActionStack = m.filterActionStack[:len(m.filterActionStack)-1]
	}
	m.filter = cloneFilter(last)
	m.applyFilter()
	m.restoreSelectionBySeq(targetSeq)
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

func cloneFilter(in Filter) Filter {
	out := in
	out.Syscall = cloneStringFilter(in.Syscall)
	out.Comm = cloneStringFilter(in.Comm)
	out.File = cloneStringFilter(in.File)
	out.PID = cloneNumericFilter(in.PID)
	out.TID = cloneNumericFilter(in.TID)
	out.FD = cloneNumericFilter(in.FD)
	out.LatencyNs = cloneNumericFilter(in.LatencyNs)
	out.GapNs = cloneNumericFilter(in.GapNs)
	out.Bytes = cloneNumericFilter(in.Bytes)
	out.RetVal = cloneNumericFilter(in.RetVal)
	return out
}

func cloneStringFilter(in *StringFilter) *StringFilter {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneNumericFilter(in *NumericFilter) *NumericFilter {
	if in == nil {
		return nil
	}
	out := *in
	return &out
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

func keyMsgFromString(keyStr string) tea.KeyMsg {
	switch keyStr {
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case " ", "space":
		return tea.KeyMsg{Type: tea.KeySpace}
	}
	if keyStr == "" {
		return tea.KeyMsg{}
	}
	runes := []rune(keyStr)
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: runes}
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

// SetStatusMessage updates the stream footer status line.
func (m *Model) SetStatusMessage(message string) {
	m.statusMessage = message
}

func (m *Model) dumpVisibleForTest() string {
	rows := make([]string, 0, len(m.filtered))
	for _, ev := range m.filtered {
		rows = append(rows, ev.Syscall)
	}
	return strings.Join(rows, ",")
}
