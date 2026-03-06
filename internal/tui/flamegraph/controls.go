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

func (m *Model) resetBaseline() {
	if m.liveTrie != nil {
		m.liveTrie.Reset()
	}
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomStack = nil
	m.selectedIdx = 0
	m.snapshot = nil
	m.frames = nil
	m.targetFrames = nil
	m.searchQuery = ""
	m.matchIndices = make(map[int]bool)
	m.subtreeSet = make(map[int]bool)
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
	m.zoomRoot = nil
	m.zoomPath = ""
	m.zoomStack = nil
	m.selectedIdx = 0
	m.snapshot = nil
	m.frames = nil
	m.targetFrames = nil
	m.subtreeSet = make(map[int]bool)
	m.statusMessage = "Order: " + strings.Join(nextPreset, "/")
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
	line := fmt.Sprintf("%s | view:%s | o:order(%s) | /:search | enter:zoom | u:undo | r:reset | p:pause", state, compactFramePath(m.currentRootPath()), order)
	if m.searchQuery != "" {
		line += " | filter:" + m.searchQuery
	}
	if m.statusMessage != "" {
		line += " | " + m.statusMessage
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
	help := "Flame help: j/k depth  h/l sibling  enter zoom  u/backspace undo  esc reset  / search  n/N matches  p pause  r reset baseline  o order  ? help"
	return common.HelpBarStyle.Width(width).Render(padOrTrim(help, width))
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
