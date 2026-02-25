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

	scrollOffset int
	autoScroll   bool

	width  int
	height int
}

func NewModel(source *RingBuffer) Model {
	return Model{
		source:      source,
		filterModal: NewFilterModal(),
		autoScroll:  true,
	}
}

func (m *Model) HandleKey(keyStr string) bool {
	if m.filterModal.Visible() {
		wasVisible := m.filterModal.Visible()
		m.filterModal = m.filterModal.Update(keyMsgFromString(keyStr))
		if wasVisible && !m.filterModal.Visible() {
			m.filter = m.filterModal.Filter()
			m.applyFilter()
		}
		return true
	}

	switch keyStr {
	case " ", "space":
		m.paused = !m.paused
		if !m.paused {
			m.Refresh()
		}
		return true
	case "f":
		m.filterModal = m.filterModal.Open(m.filter)
		return true
	case "G":
		m.autoScroll = true
		m.scrollOffset = m.maxScrollOffset()
		return true
	case "g":
		m.autoScroll = false
		m.scrollOffset = 0
		return true
	case "c":
		m.filter = Filter{}
		m.applyFilter()
		return true
	case "j", "down":
		if m.scrollOffset < m.maxScrollOffset() {
			m.scrollOffset++
		}
		if m.scrollOffset < m.maxScrollOffset() {
			m.autoScroll = false
		}
		return true
	case "k", "up":
		if m.scrollOffset > 0 {
			m.scrollOffset--
		}
		m.autoScroll = false
		return true
	default:
		return false
	}
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

	bufferLen := 0
	if m.source != nil {
		bufferLen = m.source.Len()
	}

	base := RenderStreamTable(width, m.paused, len(m.allEvents), len(m.filtered), bufferLen, ringBufferCapacity, m.filter, visible)
	status := fmt.Sprintf("Row %d/%d | space:pause f:filter G:tail g:top c:clear j/k:scroll", rowNumber(start, len(m.filtered)), len(m.filtered))
	out := base + "\n" + status

	if m.filterModal.Visible() {
		return m.filterModal.View(width, height) + "\n" + out
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
