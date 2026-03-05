package flamegraph

import (
	"fmt"
	"hash/fnv"
	"image/color"
	common "ior/internal/tui/common"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

const pathSeparator = "\x1f"
const minFlameWidth = 60

// BuildTerminalLayout converts a live trie snapshot into terminal frame cells.
func BuildTerminalLayout(snapshot *snapshotNode, width, height int) []tuiFrame {
	if snapshot == nil || width <= 0 || height <= 0 {
		return nil
	}
	rootTotal := snapshotTotal(snapshot)
	if rootTotal == 0 {
		return nil
	}

	rootName := frameName(snapshot.Name, 0)
	frames := make([]tuiFrame, 0, len(snapshot.Children)+1)
	collectTerminalLayout(&frames, snapshot, rootTotal, width, height, 0, 0, rootName)
	return frames
}

func collectTerminalLayout(out *[]tuiFrame, node *snapshotNode, rootTotal uint64, width, height, depth, col int, path string) {
	if node == nil || depth >= height {
		return
	}
	total := snapshotTotal(node)
	frameWidth := int(math.Floor(float64(width) * (float64(total) / float64(rootTotal))))
	if frameWidth < 1 {
		return
	}

	name := frameName(node.Name, depth)
	*out = append(*out, tuiFrame{
		Name:    name,
		Col:     col,
		Row:     depth,
		Width:   frameWidth,
		Total:   total,
		Percent: 100 * float64(total) / float64(rootTotal),
		Fill:    terminalFrameColor(name),
		Depth:   depth,
		Path:    path,
	})

	cursor := col
	for _, child := range node.Children {
		childTotal := snapshotTotal(child)
		childWidth := int(math.Floor(float64(width) * (float64(childTotal) / float64(rootTotal))))
		if childWidth < 1 {
			continue
		}
		childName := frameName(child.Name, depth+1)
		childPath := strings.Join([]string{path, childName}, pathSeparator)
		collectTerminalLayout(out, child, rootTotal, width, height, depth+1, cursor, childPath)
		cursor += childWidth
	}
}

func snapshotTotal(node *snapshotNode) uint64 {
	if node == nil {
		return 0
	}
	total := node.Value
	for _, child := range node.Children {
		total += snapshotTotal(child)
	}
	if node.Total > total {
		return node.Total
	}
	return total
}

func frameName(name string, depth int) string {
	if name != "" {
		return name
	}
	if depth == 0 {
		return "root"
	}
	return "(unknown)"
}

func terminalFrameColor(name string) color.Color {
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(name))
	h := hasher.Sum32()
	return color.RGBA{
		R: uint8(200 + int(h%35)),
		G: uint8(80 + int((h>>8)%120)),
		B: uint8(40 + int((h>>16)%90)),
		A: 255,
	}
}

// RenderTerminalView renders a terminal flamegraph viewport from laid out frames.
func RenderTerminalView(frames []tuiFrame, width, height, selectedIdx int) string {
	if width < minFlameWidth {
		return common.PanelStyle.Render("Flame: terminal too narrow (need >= 60 columns)")
	}
	if height < 3 {
		return common.PanelStyle.Render("Flame: viewport too short")
	}
	if len(frames) == 0 {
		return common.PanelStyle.Render("Flame: waiting for data...")
	}

	availableRows := height - 2 // toolbar + status
	maxRow := maxFrameRow(frames)
	rowOffset := 0
	truncated := false
	if maxRow+1 > availableRows {
		rowOffset = maxRow + 1 - availableRows
		truncated = true
	}

	if selectedIdx < 0 || selectedIdx >= len(frames) {
		selectedIdx = 0
	}
	selected := frames[selectedIdx]

	toolbar := fmt.Sprintf("Flame | frames:%d | rows:%d", len(frames), availableRows)
	if truncated {
		toolbar += " | showing deepest levels"
	}
	toolbar = padOrTrim(toolbar, width)
	status := fmt.Sprintf("Selected: %s %.2f%% total=%d depth=%d", selected.Name, selected.Percent, selected.Total, selected.Depth)
	status = padOrTrim(status, width)

	rows := buildRenderRows(frames, width, rowOffset, maxRow, selected.Path)

	var b strings.Builder
	b.Grow((width + 1) * (len(rows) + 2))
	b.WriteString(toolbar)
	for _, row := range rows {
		b.WriteString("\n")
		b.WriteString(row)
	}
	b.WriteString("\n")
	b.WriteString(status)
	return b.String()
}

func buildRenderRows(frames []tuiFrame, width, rowOffset, maxRow int, selectedPath string) []string {
	rowsByDepth := make(map[int][]tuiFrame)
	for _, frame := range frames {
		if frame.Row < rowOffset || frame.Row > maxRow {
			continue
		}
		rowsByDepth[frame.Row] = append(rowsByDepth[frame.Row], frame)
	}

	rows := make([]string, 0, maxRow-rowOffset+1)
	for row := maxRow; row >= rowOffset; row-- {
		framesAtRow := rowsByDepth[row]
		sort.Slice(framesAtRow, func(i, j int) bool {
			return framesAtRow[i].Col < framesAtRow[j].Col
		})
		rows = append(rows, renderRow(framesAtRow, width, selectedPath))
	}
	return rows
}

func renderRow(frames []tuiFrame, width int, selectedPath string) string {
	if len(frames) == 0 {
		return strings.Repeat(" ", width)
	}
	var b strings.Builder
	b.Grow(width + 8)
	cursor := 0
	for _, frame := range frames {
		if frame.Col >= width {
			continue
		}
		if frame.Col > cursor {
			gap := frame.Col - cursor
			b.WriteString(strings.Repeat(" ", gap))
			cursor += gap
		}

		cellWidth := frame.Width
		if frame.Col+cellWidth > width {
			cellWidth = width - frame.Col
		}
		if cellWidth <= 0 {
			continue
		}
		label := padOrTrim(frame.Name, cellWidth)
		style := lipgloss.NewStyle().Width(cellWidth).Foreground(common.ColorBackground).Background(frame.Fill)
		if frame.Path == selectedPath {
			style = style.Bold(true).Underline(true)
		}
		cell := style.Render(label)
		b.WriteString(cell)
		cursor = frame.Col + cellWidth
	}
	if cursor < width {
		b.WriteString(strings.Repeat(" ", width-cursor))
	}
	return b.String()
}

func maxFrameRow(frames []tuiFrame) int {
	maxRow := 0
	for _, frame := range frames {
		if frame.Row > maxRow {
			maxRow = frame.Row
		}
	}
	return maxRow
}

func padOrTrim(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= width {
		return s + strings.Repeat(" ", width-utf8.RuneCountInString(s))
	}
	if width == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:width-1]) + "…"
}
