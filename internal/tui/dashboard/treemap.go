package dashboard

import (
	"fmt"
	"image/color"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"ior/internal/statsengine"

	"charm.land/lipgloss/v2"
)

const maxSyscallTreemapItems = 20

type syscallTreemapItem struct {
	Name   string
	Count  uint64
	Bytes  uint64
	Errors uint64
	P95Ns  uint64
	Value  uint64
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
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 18
	}
	items := buildSyscallTreemapItems(snap, metric)
	header := fmt.Sprintf("Syscalls treemap | metric:%s | v mode | b metric | j/k select", treemapMetricLabel(metric))
	if len(items) == 0 {
		return header + "\nSyscalls treemap: no data\nsel: none"
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
			Name:   syscall.Name,
			Count:  syscall.Count,
			Bytes:  syscall.Bytes,
			Errors: syscall.Errors,
			P95Ns:  syscall.LatencyP95Ns,
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
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value != items[j].Value {
			return items[i].Value > items[j].Value
		}
		return items[i].Name < items[j].Name
	})
	if len(items) > maxSyscallTreemapItems {
		items = items[:maxSyscallTreemapItems]
	}
	return items
}

func treemapValue(item syscallTreemapItem, metric bubbleMetric) uint64 {
	if metric == bubbleMetricBytes {
		return item.Bytes
	}
	return item.Count
}

func layoutSyscallTreemap(items []syscallTreemapItem, x, y, w, h int) []syscallTreemapTile {
	tiles := make([]syscallTreemapTile, 0, len(items))
	layoutSyscallTreemapInto(items, x, y, w, h, 0, &tiles)
	return tiles
}

func layoutSyscallTreemapInto(items []syscallTreemapItem, x, y, w, h, baseIndex int, out *[]syscallTreemapTile) {
	if len(items) == 0 || w <= 0 || h <= 0 {
		return
	}
	if len(items) == 1 {
		*out = append(*out, syscallTreemapTile{
			item:  items[0],
			index: baseIndex,
			x:     x,
			y:     y,
			w:     w,
			h:     h,
		})
		return
	}

	total := uint64(0)
	for _, item := range items {
		total += item.Value
	}
	if total == 0 {
		*out = append(*out, syscallTreemapTile{
			item:  items[0],
			index: baseIndex,
			x:     x,
			y:     y,
			w:     w,
			h:     h,
		})
		return
	}

	splitAt := findTreemapSplitIndex(items, total)
	first := items[:splitAt]
	second := items[splitAt:]
	firstTotal := uint64(0)
	for _, item := range first {
		firstTotal += item.Value
	}

	splitVertical := w >= h
	if splitVertical && w <= 1 {
		splitVertical = false
	}
	if !splitVertical && h <= 1 {
		splitVertical = true
	}

	if splitVertical {
		w1 := int(math.Round(float64(w) * float64(firstTotal) / float64(total)))
		if w1 < 1 {
			w1 = 1
		}
		if w1 >= w {
			w1 = w - 1
		}
		if w1 <= 0 {
			w1 = 1
		}
		layoutSyscallTreemapInto(first, x, y, w1, h, baseIndex, out)
		layoutSyscallTreemapInto(second, x+w1, y, w-w1, h, baseIndex+splitAt, out)
		return
	}

	h1 := int(math.Round(float64(h) * float64(firstTotal) / float64(total)))
	if h1 < 1 {
		h1 = 1
	}
	if h1 >= h {
		h1 = h - 1
	}
	if h1 <= 0 {
		h1 = 1
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
	metricValue := item.Count
	if metric == bubbleMetricBytes {
		metricValue = item.Bytes
	}
	metricText := fmt.Sprintf("%d", metricValue)
	if metric == bubbleMetricBytes {
		metricText = formatBytes(float64(metricValue))
	}
	return fmt.Sprintf(
		"sel:%d/%d %s | %s=%s | bytes=%s | errors=%d | p95=%s",
		selected+1,
		len(items),
		item.Name,
		treemapMetricLabel(metric),
		metricText,
		formatBytes(float64(item.Bytes)),
		item.Errors,
		formatDurationUintNs(item.P95Ns),
	)
}

func treemapMetricLabel(metric bubbleMetric) string {
	if metric == bubbleMetricBytes {
		return "bytes"
	}
	return "events"
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
				style = style.Bold(true)
			}
			styleCache[key] = style
		}
		b.WriteString(style.Render(string(cell.char)))
	}
	return b.String()
}
