package flamegraph

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

var countFieldCycle = []string{"count", "bytes", "duration"}

var heightFieldCycle = []string{"", "duration", "bytes", "count"}

func nextCycleValue(current string, cycle []string) string {
	if len(cycle) == 0 {
		return current
	}
	for idx := range cycle {
		if cycle[idx] == current {
			return cycle[(idx+1)%len(cycle)]
		}
	}
	return cycle[0]
}

func (m *Model) togglePause() {
	m.paused = !m.paused
}

// clearSnapshotState discards the current snapshot and view state after the
// baseline, field order or metrics changed. It also invalidates any refresh
// still in flight: that job was computed for the previous state, so its
// result must not be applied (and, while paused, frozen) under the new one.
// The job keeps the in-flight slot until it completes, so refreshes against
// the shared live trie never overlap. The frame animation is reset the same
// way: a tick still scheduled for the previous layout is dropped instead of
// restoring the discarded frames.
func (m *Model) clearSnapshotState(clearSearch bool) {
	m.invalidateRefresh()
	m.zoom.reset()
	m.sel.reset()
	m.snapshot = nil
	m.globalTotal = 0
	m.anim.reset()
	m.search.discardResults(clearSearch)
}

func resetBoolSet(values map[int]bool) map[int]bool {
	if values == nil {
		return make(map[int]bool)
	}
	clear(values)
	return values
}

// resetBaseline is the flame tab's `r` key. It deliberately drops the flame
// selection: clearSnapshotState resets the selection manager together with
// the zoom, as it does for a field-order or metric change, because the user
// asked for a fresh baseline. The automatic 30s reset and the `r` key on the
// dashboard tables are different on purpose: they keep the selected item (the
// tables via stickyKey, the flame via SelectionManager's wantedPath) so the
// cursor does not jump to row 0 / root every time the data refills.
func (m *Model) resetBaseline() {
	if m.liveTrie != nil {
		m.liveTrie.Reset()
	}
	m.clearSnapshotState(true)
	m.statusMessage = "Baseline reset"
}

// cycleFieldOrder switches the trie to the next field-order preset. The model's
// fieldIndex only advances once the trie accepted the preset: advancing first
// would make the toolbar's o:order(...) label advertise a preset the trie
// rejected and is not using.
func (m *Model) cycleFieldOrder() {
	if len(m.fieldPresets) == 0 {
		return
	}
	nextIndex := (m.fieldIndex + 1) % len(m.fieldPresets)
	nextPreset := m.fieldPresets[nextIndex]
	if m.liveTrie != nil {
		if err := m.liveTrie.Reconfigure(nextPreset); err != nil {
			m.statusMessage = "Field order error: " + err.Error()
			return
		}
	}
	m.fieldIndex = nextIndex
	m.clearSnapshotState(false)
	m.statusMessage = "Order: " + strings.Join(nextPreset, "/")
}

func (m *Model) toggleCountField() {
	// 3-way cycle: count -> bytes -> duration -> count.
	// durationToPrev (inter-syscall gap) is reachable via the CLI flag but
	// kept out of the toolbar cycle for now.
	next := nextCycleValue(m.countField, countFieldCycle)
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
	// 4-way cycle: off -> duration -> bytes -> count -> off.
	next := nextCycleValue(m.heightField, heightFieldCycle)
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

func (m *Model) toolbarLine() string {
	theme := common.Current()
	state := lipgloss.NewStyle().Foreground(theme.Primary).Render("[LIVE]")
	if m.paused {
		state = lipgloss.NewStyle().Foreground(theme.Danger).Bold(true).Render("[PAUSED]")
	}
	order := m.currentFieldPresetLabel()
	// Use a Builder to avoid repeated allocations for the optional suffix segments.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s | view:%s | o:order(%s) | b:metric(%s) | v:height(%s) | /:search | enter/click:zoom | click ancestor:undo | u/esc:undo | r:reset | space:pause",
		state, compactFramePath(m.currentRootPath()), order, m.countFieldLabel(), m.heightFieldLabel()))
	// The search query is typed by the user but can be pasted, and the status
	// message can echo errors or frame names: both are sanitised.
	if query := m.search.query(); query != "" {
		b.WriteString(" | filter:")
		b.WriteString(common.Sanitize(query))
	}
	if m.statusMessage != "" {
		b.WriteString(" | ")
		b.WriteString(common.Sanitize(m.statusMessage))
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

func (m *Model) helpOverlay() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	help := "Flame help: j/k depth  h/l sibling  pgup top  pgdn root  enter/click zoom  click ancestor undo  u/backspace/esc undo  / search  n/N matches  space pause  r reset baseline  o order  b metric  v height  ? help"
	return common.Current().HelpBarStyle.Width(width).Render(padOrTrim(help, width))
}

// selectionStatusLine renders the bottom status bar: live/paused mode, the
// selected frame's position, path, depth, total and share, the optional
// height metric, and the active search filter.
func (m *Model) selectionStatusLine() string {
	width := m.width
	if width <= 0 {
		width = 80
	}
	mode := "LIVE"
	if m.paused {
		mode = "PAUSED"
	}
	frames := m.anim.currentFrames()
	if len(frames) == 0 {
		heightLabel := ""
		if m.heightMetricActive() {
			heightLabel = " | height:" + m.heightFieldLabel()
		}
		line := fmt.Sprintf("[%s] sel:none | arrows/hjkl navigate | enter zoom | / filter%s", mode, heightLabel)
		return common.Current().HelpBarStyle.Width(width).Render(padOrTrim(line, width))
	}
	selIdx := m.sel.selected()
	if selIdx < 0 || selIdx >= len(frames) {
		selIdx = 0
	}
	frame := frames[selIdx]
	query := m.search.query()
	// Use a Builder to avoid a separate allocation for the optional filter suffix.
	var b strings.Builder
	b.WriteString(fmt.Sprintf("[%s] sel:%d/%d %s | path:%s | depth:%d | total(%s):%d | %s%s",
		mode, selIdx+1, len(frames), frame.Name, compactFramePath(frame.Path), frame.Depth, m.countFieldLabel(), frame.Total,
		m.selectionShareLabel(frames, frame, query), m.selectionHeightLabel(frames, frame)))
	if query != "" {
		// Sanitised like the toolbar copy of the query (task io2).
		b.WriteString(" | filter:")
		b.WriteString(common.Sanitize(query))
	}
	return common.Current().HelpBarStyle.Width(width).Render(padOrTrim(b.String(), width))
}

// selectionHeightLabel returns the " | height(...)" suffix for the selected
// frame, as a share of the tallest visible frame, or "" when no height
// metric is active.
func (m *Model) selectionHeightLabel(frames []tuiFrame, frame tuiFrame) string {
	if !m.heightMetricActive() {
		return ""
	}
	maxHeightTotal := uint64(0)
	for i := range frames {
		if frames[i].HeightTotal > maxHeightTotal {
			maxHeightTotal = frames[i].HeightTotal
		}
	}
	heightShare := percentOfTotal(frame.HeightTotal, maxHeightTotal)
	return fmt.Sprintf(" | height(%s)=%d (%.1f%% of max)", m.heightFieldLabel(), frame.HeightTotal, heightShare)
}

// selectionShareLabel returns the selected frame's share: of the filtered
// total while a search query has matches with a non-zero coverage, otherwise
// of the global total (falling back to the frame's layout percent when the
// global total is unknown).
func (m *Model) selectionShareLabel(frames []tuiFrame, frame tuiFrame, query string) string {
	metric := m.countFieldLabel()
	if matches := m.search.matches(); strings.TrimSpace(query) != "" && len(matches) > 0 {
		filterTotal, _ := filterCoverageTotals(frames, matches, m.globalTotal)
		if filterTotal > 0 {
			selectedFilterTotal := filterCoverageTotalForPath(frames, matches, frame.Path)
			filterShare := percentOfTotal(selectedFilterTotal, filterTotal)
			return fmt.Sprintf("%.2f%% of filtered %s", filterShare, metric)
		}
	}
	systemShare := frame.Percent
	if m.globalTotal > 0 {
		systemShare = percentOfTotal(frame.Total, m.globalTotal)
	}
	return fmt.Sprintf("%.2f%% of total %s", systemShare, metric)
}

func (m *Model) currentFieldPresetLabel() string {
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

func (m *Model) countFieldLabel() string {
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

func (m *Model) heightFieldLabel() string {
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

func (m *Model) heightMetricActive() bool {
	return strings.TrimSpace(m.heightField) != ""
}
