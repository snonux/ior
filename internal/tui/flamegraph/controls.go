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
	next := "bytes"
	if m.countField == "bytes" {
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

func (m *Model) toggleHelp() {
	m.showHelp = !m.showHelp
}

func (m Model) toolbarLine() string {
	state := lipgloss.NewStyle().Foreground(common.ColorPrimary).Render("[LIVE]")
	if m.paused {
		state = lipgloss.NewStyle().Foreground(common.ColorDanger).Bold(true).Render("[PAUSED]")
	}
	order := m.currentFieldPresetLabel()
	line := fmt.Sprintf("%s | view:%s | o:order(%s) | b:metric(%s) | /:search | enter/click:zoom | click ancestor:undo | u/esc:undo | r:reset | space/p:pause", state, compactFramePath(m.currentRootPath()), order, m.countFieldLabel())
	if m.searchQuery != "" {
		line += " | filter:" + m.searchQuery
	}
	if m.statusMessage != "" {
		line += " | " + m.statusMessage
	}
	if m.lastKeyDebug != "" {
		line += " | " + m.lastKeyDebug
	}
	width := m.width
	if width <= 0 {
		width = 80
	}
	return padOrTrim(line, width)
}

func (m Model) helpOverlay() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	help := "Flame help: j/k depth  h/l sibling  pgup top  pgdn root  enter/click zoom  click ancestor undo  u/backspace/esc undo  / search  n/N matches  space/p pause  r reset baseline  o order  b metric  ? help"
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
	if len(m.frames) == 0 {
		line := fmt.Sprintf("[%s] sel:none | arrows/hjkl navigate | enter zoom | / filter", mode)
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
	line := fmt.Sprintf("[%s] sel:%d/%d %s | path:%s | depth:%d | total(%s):%d | %s",
		mode, selIdx+1, len(m.frames), frame.Name, compactFramePath(frame.Path), frame.Depth, m.countFieldLabel(), frame.Total, shareLabel)
	if m.searchQuery != "" {
		line += " | filter:" + m.searchQuery
	}
	return common.HelpBarStyle.Width(width).Render(padOrTrim(line, width))
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
	default:
		return m.countField
	}
}
