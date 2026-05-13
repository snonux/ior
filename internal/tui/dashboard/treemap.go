package dashboard

import (
	"cmp"
	"fmt"
	"image/color"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"ior/internal/statsengine"

	"charm.land/lipgloss/v2"
)

const maxSyscallTreemapItems = 20

type syscallTreemapItem struct {
	Name     string
	Count    uint64
	Bytes    uint64
	Duration uint64
	Errors   uint64
	P95Ns    uint64
	Detail   string
	Value    uint64
}

type syscallTreemapTile struct {
	item  syscallTreemapItem
	index int
	x     int
	y     int
	w     int
	h     int
}

type treemapCell struct {
	char      rune
	colorSlot int
	bold      bool
}

func renderSyscallsTreemap(snap *statsengine.Snapshot, width, height int, metric bubbleMetric, selected int, isDark bool) string {
	if snap == nil {
		return "Syscalls treemap: waiting for stats..."
	}
	items := buildSyscallTreemapItems(snap, metric)
	return renderTreemapPanel("Syscalls treemap", "Syscalls treemap: no data", items, width, height, metric, selected, isDark)
}

func renderFilesTreemap(snap *statsengine.Snapshot, width, height int, metric bubbleMetric, selected int, isDark bool) string {
	if snap == nil {
		return "Files treemap: waiting for stats..."
	}
	items := buildFilesTreemapItems(snap, metric)
	return renderTreemapPanel("Files treemap", "Files treemap: no directory data", items, width, height, metric, selected, isDark)
}

func renderProcessesTreemap(snap *statsengine.Snapshot, width, height int, metric bubbleMetric, selected int, isDark bool) string {
	if snap == nil {
		return "Processes treemap: waiting for stats..."
	}
	items := buildProcessesTreemapItems(snap, metric)
	return renderTreemapPanel("Processes treemap", "Processes treemap: no data", items, width, height, metric, selected, isDark)
}

func renderTreemapPanel(title, emptyText string, items []syscallTreemapItem, width, height int, metric bubbleMetric, selected int, isDark bool) string {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	header := fmt.Sprintf("%s | metric:%s | v mode | b metric | j/k select", title, treemapMetricLabel(metric))
	if len(items) == 0 {
		return header + "\n" + emptyText + "\nsel: none"
	}

	selected = clampOffset(selected, len(items))
	chartHeight := height - 2
	if chartHeight < 4 {
		chartHeight = 4
	}

	tiles := layoutSyscallTreemap(items, 0, 0, width, chartHeight)
	grid := make([][]treemapCell, chartHeight)
	for row := 0; row < chartHeight; row++ {
		grid[row] = make([]treemapCell, width)
		for col := 0; col < width; col++ {
			grid[row][col] = treemapCell{char: ' ', colorSlot: -1}
		}
	}
	fillTreemapGrid(grid, tiles, selected)
	palette := treemapPalette(isDark)

	lines := make([]string, 0, chartHeight+2)
	lines = append(lines, padOrTrim(header, width))
	for _, row := range grid {
		lines = append(lines, renderTreemapRow(row, palette))
	}
	lines = append(lines, padOrTrim(treemapStatusLine(items, selected, metric), width))
	return strings.Join(lines, "\n")
}

func buildSyscallTreemapItems(snap *statsengine.Snapshot, metric bubbleMetric) []syscallTreemapItem {
	if snap == nil {
		return nil
	}
	syscalls := snap.Syscalls()
	items := make([]syscallTreemapItem, 0, len(syscalls))
	for _, syscall := range syscalls {
		item := syscallTreemapItem{
			Name:     syscall.Name,
			Count:    syscall.Count,
			Bytes:    syscall.Bytes,
			Duration: syscall.TotalLatencyNs,
			Errors:   syscall.Errors,
			P95Ns:    syscall.LatencyP95Ns,
			Detail: fmt.Sprintf(
				"rate %.1f/s, errors %d, p95 %s",
				syscall.RatePerSec,
				syscall.Errors,
				formatDurationUintNs(syscall.LatencyP95Ns),
			),
		}
		item.Value = treemapValue(item, metric)
		if item.Value == 0 {
			continue
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	slices.SortFunc(items, func(a, b syscallTreemapItem) int {
		if a.Value != b.Value {
			return cmp.Compare(b.Value, a.Value)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(items) > maxSyscallTreemapItems {
		items = items[:maxSyscallTreemapItems]
	}
	return items
}

func buildFilesTreemapItems(snap *statsengine.Snapshot, metric bubbleMetric) []syscallTreemapItem {
	if snap == nil {
		return nil
	}
	dirs := aggregateFilesByDir(snap.Files())
	items := make([]syscallTreemapItem, 0, len(dirs))
	for _, dir := range dirs {
		pathLabel := rootPathLabelFromFSPath(dir.Dir)
		totalBytes := dir.BytesRead + dir.BytesWritten
		item := syscallTreemapItem{
			Name:     pathLabel,
			Count:    dir.Accesses,
			Bytes:    totalBytes,
			Duration: dir.TotalLatencyNs,
			Detail: fmt.Sprintf(
				"dir %s, files %d, read %s, write %s, max %s",
				dir.Dir,
				dir.FileCount,
				formatBytes(float64(dir.BytesRead)),
				formatBytes(float64(dir.BytesWritten)),
				formatDurationUintNs(dir.MaxLatencyNs),
			),
		}
		item.Value = treemapValue(item, metric)
		if item.Value == 0 {
			continue
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	slices.SortFunc(items, func(a, b syscallTreemapItem) int {
		if a.Value != b.Value {
			return cmp.Compare(b.Value, a.Value)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(items) > maxSyscallTreemapItems {
		items = items[:maxSyscallTreemapItems]
	}
	return items
}

func buildProcessesTreemapItems(snap *statsengine.Snapshot, metric bubbleMetric) []syscallTreemapItem {
	if snap == nil {
		return nil
	}
	processes := snap.Processes()
	items := make([]syscallTreemapItem, 0, len(processes))
	for _, proc := range processes {
		label := fmt.Sprintf("%d", proc.PID)
		if comm := strings.TrimSpace(proc.Comm); comm != "" {
			label = fmt.Sprintf("%d:%s", proc.PID, comm)
		}
		item := syscallTreemapItem{
			Name:     label,
			Count:    proc.Syscalls,
			Bytes:    proc.Bytes,
			Duration: proc.TotalLatencyNs,
			Detail: fmt.Sprintf(
				"pid %d, rate %.1f/s, avg %s",
				proc.PID,
				proc.RatePerSec,
				formatDurationNs(proc.AvgLatencyNs),
			),
		}
		item.Value = treemapValue(item, metric)
		if item.Value == 0 {
			continue
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	slices.SortFunc(items, func(a, b syscallTreemapItem) int {
		if a.Value != b.Value {
			return cmp.Compare(b.Value, a.Value)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	if len(items) > maxSyscallTreemapItems {
		items = items[:maxSyscallTreemapItems]
	}
	return items
}

func treemapValue(item syscallTreemapItem, metric bubbleMetric) uint64 {
	switch metric {
	case bubbleMetricBytes:
		return item.Bytes
	case bubbleMetricDuration:
		return item.Duration
	default:
		return item.Count
	}
}

func layoutSyscallTreemap(items []syscallTreemapItem, x, y, w, h int) []syscallTreemapTile {
	tiles := make([]syscallTreemapTile, 0, len(items))
	layoutSyscallTreemapInto(items, x, y, w, h, 0, &tiles)
	return tiles
}

// layoutSyscallTreemapInto recursively partitions items into tiles using a
// binary split strategy. Items are bisected near the median value and placed
// into the left/right (vertical split) or top/bottom (horizontal split) halves.
func layoutSyscallTreemapInto(items []syscallTreemapItem, x, y, w, h, baseIndex int, out *[]syscallTreemapTile) {
	if len(items) == 0 || w <= 0 || h <= 0 {
		return
	}

	total := sumTreemapValues(items)
	if len(items) == 1 || total == 0 {
		// Degenerate case: single item or all-zero values — fill the whole rect.
		*out = append(*out, syscallTreemapTile{
			item: items[0], index: baseIndex,
			x: x, y: y, w: w, h: h,
		})
		return
	}

	splitAt := findTreemapSplitIndex(items, total)
	first, second := items[:splitAt], items[splitAt:]
	firstTotal := sumTreemapValues(first)

	if chooseSplitVertical(w, h) {
		layoutTreemapVertical(first, second, x, y, w, h, baseIndex, splitAt, firstTotal, total, out)
	} else {
		layoutTreemapHorizontal(first, second, x, y, w, h, baseIndex, splitAt, firstTotal, total, out)
	}
}

// sumTreemapValues returns the sum of Value fields across items.
func sumTreemapValues(items []syscallTreemapItem) uint64 {
	total := uint64(0)
	for _, item := range items {
		total += item.Value
	}
	return total
}

// chooseSplitVertical returns true when the rectangle should be split along
// the vertical axis (left/right), using aspect-ratio heuristics.
func chooseSplitVertical(w, h int) bool {
	splitVertical := w >= h
	if splitVertical && w <= 1 {
		return false
	}
	if !splitVertical && h <= 1 {
		return true
	}
	return splitVertical
}

// layoutTreemapVertical splits the items into left (first) and right (second)
// columns proportional to their value totals and recurses into each column.
func layoutTreemapVertical(first, second []syscallTreemapItem, x, y, w, h, baseIndex, splitAt int, firstTotal, total uint64, out *[]syscallTreemapTile) {
	w1 := int(math.Round(float64(w) * float64(firstTotal) / float64(total)))
	if w1 < 1 {
		w1 = 1
	}
	if w1 >= w {
		w1 = w - 1
	}
	layoutSyscallTreemapInto(first, x, y, w1, h, baseIndex, out)
	layoutSyscallTreemapInto(second, x+w1, y, w-w1, h, baseIndex+splitAt, out)
}

// layoutTreemapHorizontal splits items into top (first) and bottom (second)
// rows proportional to their value totals and recurses into each row.
func layoutTreemapHorizontal(first, second []syscallTreemapItem, x, y, w, h, baseIndex, splitAt int, firstTotal, total uint64, out *[]syscallTreemapTile) {
	h1 := int(math.Round(float64(h) * float64(firstTotal) / float64(total)))
	if h1 < 1 {
		h1 = 1
	}
	if h1 >= h {
		h1 = h - 1
	}
	layoutSyscallTreemapInto(first, x, y, w, h1, baseIndex, out)
	layoutSyscallTreemapInto(second, x, y+h1, w, h-h1, baseIndex+splitAt, out)
}

func findTreemapSplitIndex(items []syscallTreemapItem, total uint64) int {
	target := float64(total) / 2.0
	running := float64(0)
	for idx, item := range items {
		running += float64(item.Value)
		if running >= target {
			if idx == 0 {
				return 1
			}
			if idx >= len(items)-1 {
				return len(items) - 1
			}
			return idx + 1
		}
	}
	return len(items) / 2
}

func fillTreemapGrid(grid [][]treemapCell, tiles []syscallTreemapTile, selected int) {
	height := len(grid)
	if height == 0 {
		return
	}
	width := len(grid[0])
	if width == 0 {
		return
	}
	for idx, tile := range tiles {
		isSelected := tile.index == selected
		for row := tile.y; row < minInt(height, tile.y+tile.h); row++ {
			for col := tile.x; col < minInt(width, tile.x+tile.w); col++ {
				grid[row][col] = treemapCell{
					char:      '█',
					colorSlot: idx,
					bold:      isSelected,
				}
			}
		}
		drawTreemapLabel(grid, tile, isSelected, idx)
	}
}

func drawTreemapLabel(grid [][]treemapCell, tile syscallTreemapTile, selected bool, colorSlot int) {
	height := len(grid)
	if height == 0 {
		return
	}
	width := len(grid[0])
	if width == 0 || tile.h < 1 || tile.w < 2 {
		return
	}
	row := tile.y
	if row < 0 || row >= height {
		return
	}
	maxLabel := tile.w - 1
	if maxLabel < 1 {
		return
	}
	label := abbreviateTreemapLabel(tile.item.Name, maxLabel)
	col := tile.x
	for _, r := range []rune(label) {
		if col >= width {
			break
		}
		if col >= 0 {
			grid[row][col] = treemapCell{
				char:      r,
				colorSlot: colorSlot,
				bold:      selected,
			}
		}
		col++
	}
}

func abbreviateTreemapLabel(label string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	label = strings.TrimSpace(label)
	if label == "" {
		label = "?"
	}
	if utf8.RuneCountInString(label) <= maxRunes {
		return label
	}
	if maxRunes == 1 {
		return "…"
	}
	r := []rune(label)
	return string(r[:maxRunes-1]) + "…"
}

func treemapStatusLine(items []syscallTreemapItem, selected int, metric bubbleMetric) string {
	if len(items) == 0 {
		return "sel:none"
	}
	selected = clampOffset(selected, len(items))
	item := items[selected]
	var metricText string
	switch metric {
	case bubbleMetricBytes:
		metricText = formatBytes(float64(item.Bytes))
	case bubbleMetricDuration:
		metricText = formatDurationUintNs(item.Duration)
	default:
		metricText = fmt.Sprintf("%d", item.Count)
	}
	// Use a Builder to avoid a redundant allocation for the optional detail suffix
	// appended conditionally on every render call.
	var b strings.Builder
	b.WriteString(fmt.Sprintf(
		"sel:%d/%d %s | %s=%s | bytes=%s",
		selected+1,
		len(items),
		item.Name,
		treemapMetricLabel(metric),
		metricText,
		formatBytes(float64(item.Bytes)),
	))
	if detail := strings.TrimSpace(item.Detail); detail != "" {
		b.WriteString(" | ")
		b.WriteString(detail)
	}
	return b.String()
}

func treemapMetricLabel(metric bubbleMetric) string {
	switch metric {
	case bubbleMetricBytes:
		return "bytes"
	case bubbleMetricDuration:
		return "duration"
	default:
		return "events"
	}
}

func treemapPalette(isDark bool) []color.Color {
	if isDark {
		return []color.Color{
			lipgloss.Color("81"),
			lipgloss.Color("75"),
			lipgloss.Color("117"),
			lipgloss.Color("186"),
			lipgloss.Color("214"),
			lipgloss.Color("177"),
			lipgloss.Color("39"),
			lipgloss.Color("203"),
		}
	}
	return []color.Color{
		lipgloss.Color("24"),
		lipgloss.Color("31"),
		lipgloss.Color("30"),
		lipgloss.Color("64"),
		lipgloss.Color("94"),
		lipgloss.Color("130"),
		lipgloss.Color("161"),
		lipgloss.Color("25"),
	}
}

func renderTreemapRow(cells []treemapCell, palette []color.Color) string {
	if len(cells) == 0 {
		return ""
	}
	var b strings.Builder
	styleCache := make(map[string]lipgloss.Style, 8)
	selectedColor := lipgloss.Color("129")
	for _, cell := range cells {
		if cell.colorSlot < 0 {
			if cell.bold {
				b.WriteString(lipgloss.NewStyle().Bold(true).Render(string(cell.char)))
			} else {
				b.WriteRune(cell.char)
			}
			continue
		}
		slot := cell.colorSlot
		if len(palette) > 0 {
			slot = slot % len(palette)
		}
		key := fmt.Sprintf("%d/%t", slot, cell.bold)
		style, ok := styleCache[key]
		if !ok {
			style = lipgloss.NewStyle().Foreground(palette[slot])
			if cell.bold {
				style = style.Foreground(selectedColor)
			}
			if cell.bold {
				style = style.Bold(true)
			}
			styleCache[key] = style
		}
		b.WriteString(style.Render(string(cell.char)))
	}
	return b.String()
}
