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
	return buildTerminalLayoutWithPath(snapshot, width, height, "")
}

func buildTerminalLayoutWithPath(snapshot *snapshotNode, width, height int, rootPath string) []tuiFrame {
	if snapshot == nil || width <= 0 || height <= 0 {
		return nil
	}
	rootTotal := snapshotTotal(snapshot)
	if rootTotal == 0 {
		return nil
	}

	rootName := frameName(snapshot.Name, 0)
	if rootPath != "" {
		rootName = rootPath
	}
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
func RenderTerminalView(frames []tuiFrame, width, height, selectedIdx int, subtreeSet, matchSet map[int]bool, isDark, searchActive bool, searchQuery string) string {
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
	if subtreeSet == nil {
		subtreeSet = computeSubtreeSet(frames, selectedIdx)
	}

	toolbar := fmt.Sprintf("Flame | frames:%d | rows:%d", len(frames), availableRows)
	if truncated {
		toolbar += " | showing deepest levels"
	}
	toolbar = padOrTrim(toolbar, width)
	status := fmt.Sprintf("Selected: %s %.2f%% total=%d depth=%d", selected.Name, selected.Percent, selected.Total, selected.Depth)
	if searchQuery != "" {
		matches := orderedMatchIndices(matchSet)
		pos := 0
		if len(matches) > 0 {
			if idx := indexOf(matches, selectedIdx); idx >= 0 {
				pos = idx + 1
			}
		}
		status = fmt.Sprintf("Search %q  %d/%d matches", searchQuery, pos, len(matches))
	}
	status = padOrTrim(status, width)

	rows := buildRenderRows(frames, width, rowOffset, maxRow, selected.Path, subtreeSet, matchSet, selectedIdx, isDark, searchActive)

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

type indexedFrame struct {
	idx   int
	frame tuiFrame
}

func buildRenderRows(frames []tuiFrame, width, rowOffset, maxRow int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, searchActive bool) []string {
	rowsByDepth := make(map[int][]indexedFrame)
	for idx, frame := range frames {
		if frame.Row < rowOffset || frame.Row > maxRow {
			continue
		}
		rowsByDepth[frame.Row] = append(rowsByDepth[frame.Row], indexedFrame{idx: idx, frame: frame})
	}

	rows := make([]string, 0, maxRow-rowOffset+1)
	for row := maxRow; row >= rowOffset; row-- {
		framesAtRow := rowsByDepth[row]
		sort.Slice(framesAtRow, func(i, j int) bool {
			return framesAtRow[i].frame.Col < framesAtRow[j].frame.Col
		})
		rows = append(rows, renderRow(framesAtRow, width, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, searchActive))
	}
	return rows
}

func renderRow(frames []indexedFrame, width int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, searchActive bool) string {
	if len(frames) == 0 {
		return strings.Repeat(" ", width)
	}
	var b strings.Builder
	b.Grow(width + 8)
	cursor := 0
	for _, item := range frames {
		frame := item.frame
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
		style := styleForFrame(item.idx, frame, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, searchActive).Width(cellWidth)
		cell := style.Render(label)
		b.WriteString(cell)
		cursor = frame.Col + cellWidth
	}
	if cursor < width {
		b.WriteString(strings.Repeat(" ", width-cursor))
	}
	return b.String()
}

func computeSubtreeSet(frames []tuiFrame, selectedIdx int) map[int]bool {
	subtree := make(map[int]bool)
	if selectedIdx < 0 || selectedIdx >= len(frames) {
		return subtree
	}
	selectedPath := frames[selectedIdx].Path
	for idx, frame := range frames {
		path := frame.Path
		if path == selectedPath ||
			strings.HasPrefix(path, selectedPath+pathSeparator) ||
			strings.HasPrefix(selectedPath, path+pathSeparator) {
			subtree[idx] = true
		}
	}
	return subtree
}

func styleForFrame(idx int, frame tuiFrame, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, searchActive bool) lipgloss.Style {
	base := lipgloss.NewStyle().
		Foreground(common.ColorBackground).
		Background(frame.Fill)

	isSelected := idx == selectedIdx
	inSubtree := subtreeSet[idx]
	isMatch := matchSet != nil && matchSet[idx]

	matchColor := lipgloss.Color("160")
	if !isDark {
		matchColor = lipgloss.Color("124")
	}

	if isSelected {
		return base.Bold(true).Reverse(true).Underline(true)
	}

	if isMatch {
		style := base.Background(matchColor)
		if inSubtree {
			return style.Bold(true)
		}
		return style.Faint(true)
	}

	if searchActive {
		return base.Background(common.ColorPanel).Foreground(common.ColorMuted).Faint(true)
	}

	if inSubtree {
		if frameRelation(frame.Path, selectedPath) == relationAncestor {
			return base.BorderLeft(true).BorderForeground(common.ColorAccent)
		}
		return base
	}

	return base.Background(common.ColorPanel).Foreground(common.ColorMuted).Faint(true)
}

type relation int

const (
	relationNone relation = iota
	relationAncestor
	relationDescendant
)

func frameRelation(path, selectedPath string) relation {
	if path == selectedPath {
		return relationDescendant
	}
	if strings.HasPrefix(selectedPath, path+pathSeparator) {
		return relationAncestor
	}
	if strings.HasPrefix(path, selectedPath+pathSeparator) {
		return relationDescendant
	}
	return relationNone
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
