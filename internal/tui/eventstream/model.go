package eventstream

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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

	scrollOffset int
	autoScroll   bool
	selectedIdx  int

	width  int
	height int
}

func NewModel(source *RingBuffer) Model {
	return Model{
		source:      source,
		filterModal: NewFilterModal(),
		autoScroll:  true,
		selectedIdx: -1,
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

// Paused reports whether stream refresh is currently paused.
func (m Model) Paused() bool {
	return m.paused
}

func (m *Model) HandleKey(keyStr string) bool {
	if m.filterModal.Visible() {
		wasVisible := m.filterModal.Visible()
		m.filterModal = m.filterModal.Update(keyMsgFromString(keyStr))
		if wasVisible && !m.filterModal.Visible() {
			m.filter = m.filterModal.Filter()
			m.paused = m.pauseBeforeFilter
			m.applyFilter()
			if !m.paused {
				m.Refresh()
			}
		}
		return true
	}

	switch keyStr {
	case " ", "space":
		m.paused = !m.paused
		if !m.paused {
			// Resuming should return to live-tail behavior immediately.
			m.autoScroll = true
			m.selectedIdx = -1
			m.Refresh()
		} else {
			m.ensureSelection()
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
	default:
		return false
	}
}

// HandleTeaKey handles stream keys based on Bubble Tea key message types first,
// then falls back to string matching for rune-driven shortcuts.
func (m *Model) HandleTeaKey(msg tea.KeyMsg) bool {
	switch msg.Type {
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

	base := RenderStreamTable(width, m.paused, len(m.allEvents), len(m.filtered), bufferLen, ringBufferCapacity, m.filter, visible, selectedVisibleIdx)
	status := fmt.Sprintf("Row %d/%d | space:pause f:filter G:tail g:top c:clear j/k:scroll", rowNumber(start, len(m.filtered)), len(m.filtered))
	if m.paused && m.selectedIdx >= 0 {
		status = fmt.Sprintf("Row %d/%d | Sel %d/%d | space:pause f:filter G:tail g:top c:clear j/k:select", rowNumber(start, len(m.filtered)), len(m.filtered), rowNumber(m.selectedIdx, len(m.filtered)), len(m.filtered))
	}
	out := base + "\n" + status

	if m.filterModal.Visible() {
		// While editing filters, show a dedicated modal screen to avoid
		// visual mixing with the live stream table underneath.
		return m.filterModal.View(width, height)
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

func (m *Model) moveSelectionBy(delta int) {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	m.ensureSelection()
	m.moveSelectionTo(m.selectedIdx + delta)
}

func (m *Model) moveSelectionTo(idx int) {
	if len(m.filtered) == 0 {
		m.selectedIdx = -1
		return
	}
	m.selectedIdx = clamp(idx, 0, len(m.filtered)-1)
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

func (m *Model) dumpVisibleForTest() string {
	rows := make([]string, 0, len(m.filtered))
	for _, ev := range m.filtered {
		rows = append(rows, ev.Syscall)
	}
	return strings.Join(rows, ",")
}
