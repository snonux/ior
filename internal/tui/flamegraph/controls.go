package flamegraph

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

func (m *Model) togglePause() {
	m.paused = !m.paused
}

func (m *Model) clearSnapshotState(clearSearch bool) {
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomStack = nil
	m.zoomLineWidth = 0
	m.selectedIdx = 0
	m.snapshot = nil
	m.globalTotal = 0
	m.frames = nil
	m.targetFrames = nil
	m.matchIndices = make(map[int]bool)
	m.filterVisible = make(map[int]bool)
	m.subtreeSet = make(map[int]bool)
	m.hasNavigableSnapshot = false
	if clearSearch {
		m.searchQuery = ""
	}
}

func (m *Model) resetBaseline() {
	if m.liveTrie != nil {
		m.liveTrie.Reset()
	}
	m.clearSnapshotState(true)
	m.statusMessage = "Baseline reset"
}

func (m *Model) cycleFieldOrder() {
	if len(m.fieldPresets) == 0 {
		return
	}
	m.fieldIndex = (m.fieldIndex + 1) % len(m.fieldPresets)
	nextPreset := m.fieldPresets[m.fieldIndex]
	if m.liveTrie != nil {
		if err := m.liveTrie.Reconfigure(nextPreset); err != nil {
			m.statusMessage = "Field order error: " + err.Error()
			return
		}
	}
	m.clearSnapshotState(false)
	m.statusMessage = "Order: " + strings.Join(nextPreset, "/")
}

func (m *Model) toggleCountField() {
	// 3-way cycle: count → bytes → duration → count.
	// durationToPrev (inter-syscall gap) is reachable via the CLI flag but
	// kept out of the toolbar cycle for now.
	var next string
	switch m.countField {
	case "count":
		next = "bytes"
	case "bytes":
		next = "duration"
	default:
		next = "count"
	}
	if m.liveTrie != nil {
		if err := m.liveTrie.SetCountField(next); err != nil {
			m.statusMessage = "Metric toggle error: " + err.Error()
			return
		}
	}
	m.countField = next
	m.clearSnapshotState(false)
	m.statusMessage = "Metric: " + m.countFieldLabel() + " (new baseline)"
}

func (m *Model) toggleHeightField() {
	// 4-way cycle: off → duration → bytes → count → off.
	var next string
	switch m.heightField {
	case "":
		next = "duration"
	case "duration":
		next = "bytes"
	case "bytes":
		next = "count"
	default:
		next = ""
	}
	if m.liveTrie != nil {
		if err := m.liveTrie.SetHeightField(next); err != nil {
			m.statusMessage = "Height toggle error: " + err.Error()
			return
		}
	}
	m.heightField = next
	m.clearSnapshotState(false)
	m.statusMessage = "Height: " + m.heightFieldLabel() + " (new baseline)"
}

func (m *Model) toggleHelp() {
	m.showHelp = !m.showHelp
}

func (m Model) toolbarLine() string {
	state := lipgloss.NewStyle().Foreground(common.ColorPrimary).Render("[LIVE]")
	if m.paused {
		state = lipgloss.NewStyle().Foreground(common.ColorDanger).Bold(true).Render("[PAUSED]")
	}
	order := m.currentFieldPresetLabel()
	// Use a Builder to avoid repeated allocations for the optional suffix segments.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s | view:%s | o:order(%s) | b:metric(%s) | v:height(%s) | /:search | enter/click:zoom | click ancestor:undo | u/esc:undo | r:reset | space:pause",
		state, compactFramePath(m.currentRootPath()), order, m.countFieldLabel(), m.heightFieldLabel()))
	if m.searchQuery != "" {
		b.WriteString(" | filter:")
		b.WriteString(m.searchQuery)
	}
	if m.statusMessage != "" {
		b.WriteString(" | ")
		b.WriteString(m.statusMessage)
	}
	if flameKeyDebugEnabled && m.lastKeyDebug != "" {
		b.WriteString(" | ")
		b.WriteString(m.lastKeyDebug)
	}
	width := m.width
	if width <= 0 {
		width = 80
	}
	return padOrTrim(b.String(), width)
}

func (m Model) helpOverlay() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	help := "Flame help: j/k depth  h/l sibling  pgup top  pgdn root  enter/click zoom  click ancestor undo  u/backspace/esc undo  / search  n/N matches  space pause  r reset baseline  o order  b metric  v height  ? help"
	return common.HelpBarStyle.Width(width).Render(padOrTrim(help, width))
}

func (m Model) selectionStatusLine() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	mode := "LIVE"
	if m.paused {
		mode = "PAUSED"
	}
	heightLabel := ""
	if m.heightField != "" {
		heightLabel = " | height:" + m.heightFieldLabel()
	}
	if len(m.frames) == 0 {
		line := fmt.Sprintf("[%s] sel:none | arrows/hjkl navigate | enter zoom | / filter%s", mode, heightLabel)
		return common.HelpBarStyle.Width(width).Render(padOrTrim(line, width))
	}
	selIdx := m.selectedIdx
	if selIdx < 0 || selIdx >= len(m.frames) {
		selIdx = 0
	}
	frame := m.frames[selIdx]
	systemShare := frame.Percent
	if m.globalTotal > 0 {
		systemShare = percentOfTotal(frame.Total, m.globalTotal)
	}
	metric := m.countFieldLabel()
	shareLabel := fmt.Sprintf("%.2f%% of total %s", systemShare, metric)
	if strings.TrimSpace(m.searchQuery) != "" && len(m.matchIndices) > 0 {
		filterTotal, _ := filterCoverageTotals(m.frames, m.matchIndices, m.globalTotal)
		if filterTotal > 0 {
			selectedFilterTotal := filterCoverageTotalForPath(m.frames, m.matchIndices, frame.Path)
			filterShare := percentOfTotal(selectedFilterTotal, filterTotal)
			shareLabel = fmt.Sprintf("%.2f%% of filtered %s", filterShare, metric)
		}
	}
	// Use a Builder to avoid a separate allocation for the optional filter suffix.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] sel:%d/%d %s | path:%s | depth:%d | total(%s):%d | %s%s",
		mode, selIdx+1, len(m.frames), frame.Name, compactFramePath(frame.Path), frame.Depth, m.countFieldLabel(), frame.Total, shareLabel, heightLabel))
	if m.searchQuery != "" {
		b.WriteString(" | filter:")
		b.WriteString(m.searchQuery)
	}
	return common.HelpBarStyle.Width(width).Render(padOrTrim(b.String(), width))
}

func (m Model) currentFieldPresetLabel() string {
	if len(m.fieldPresets) == 0 {
		return "n/a"
	}
	idx := m.fieldIndex
	if idx < 0 {
		idx = 0
	}
	if idx >= len(m.fieldPresets) {
		idx = len(m.fieldPresets) - 1
	}
	return strings.Join(m.fieldPresets[idx], "/")
}

func (m Model) countFieldLabel() string {
	switch m.countField {
	case "count":
		return "events"
	case "bytes":
		return "bytes"
	case "duration":
		return "duration"
	default:
		return m.countField
	}
}

func (m Model) heightFieldLabel() string {
	switch m.heightField {
	case "":
		return "off"
	case "count":
		return "count"
	case "bytes":
		return "bytes"
	case "duration":
		return "duration"
	default:
		return m.heightField
	}
}
