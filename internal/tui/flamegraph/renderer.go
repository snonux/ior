package flamegraph

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"image/color"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

const pathSeparator = "\x1f"
const pathSeparatorByte = '\x1f'
const minFlameWidth = 60
const maxBarVisualHeight = 3

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
	collectTerminalLayout(&frames, snapshot, rootTotal, height, 0, 0, rootName, width, rootPath != "")
	return frames
}

func collectTerminalLayout(out *[]tuiFrame, node *snapshotNode, rootTotal uint64, height, depth, col int, path string, span int, normalizeRootChildren bool) {
	if node == nil || depth >= height {
		return
	}
	total := snapshotTotal(node)
	if total == 0 || span < 1 {
		return
	}

	name := frameName(node.Name, depth)
	*out = append(*out, tuiFrame{
		Name:        name,
		Col:         col,
		Row:         depth,
		Width:       span,
		Total:       total,
		HeightTotal: snapshotHeightTotal(node),
		Percent:     100 * float64(total) / float64(rootTotal),
		Fill:        terminalFrameColor(name),
		Depth:       depth,
		Path:        path,
	})

	if len(node.Children) == 0 {
		return
	}

	layoutTotal := total
	if normalizeRootChildren && depth == 0 {
		if childrenTotal := childSnapshotTotal(node.Children); childrenTotal > 0 {
			layoutTotal = childrenTotal
		}
	}
	childWidths := allocateChildWidths(node.Children, layoutTotal, span)
	cursor := col
	for idx, child := range node.Children {
		childWidth := childWidths[idx]
		if childWidth < 1 {
			continue
		}
		childName := frameName(child.Name, depth+1)
		childPath := strings.Join([]string{path, childName}, pathSeparator)
		collectTerminalLayout(out, child, rootTotal, height, depth+1, cursor, childPath, childWidth, false)
		cursor += childWidth
	}
}

func childSnapshotTotal(children []*snapshotNode) uint64 {
	total := uint64(0)
	for _, child := range children {
		total += snapshotTotal(child)
	}
	return total
}

func allocateChildWidths(children []*snapshotNode, parentTotal uint64, span int) []int {
	widths := make([]int, len(children))
	if span <= 0 || parentTotal == 0 || len(children) == 0 {
		return widths
	}

	type childWidth struct {
		idx   int
		total uint64
		raw   float64
	}
	items := make([]childWidth, 0, len(children))
	used := 0
	for idx, child := range children {
		total := snapshotTotal(child)
		if total == 0 {
			continue
		}
		raw := float64(span) * (float64(total) / float64(parentTotal))
		width := int(math.Floor(raw))
		if width > 0 {
			widths[idx] = width
			used += width
		}
		items = append(items, childWidth{idx: idx, total: total, raw: raw})
	}
	if len(items) == 0 {
		return widths
	}

	// If proportional rounding culled every child, surface top contributors so
	// the user can still navigate beyond the root frame.
	if used == 0 {
		slices.SortFunc(items, func(a, b childWidth) int {
			if a.total != b.total {
				return cmp.Compare(b.total, a.total)
			}
			return cmp.Compare(a.idx, b.idx)
		})
		visible := min(span, len(items))
		for i := 0; i < visible; i++ {
			widths[items[i].idx] = 1
		}
	}
	return widths
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

func snapshotHeightTotal(node *snapshotNode) uint64 {
	if node == nil {
		return 0
	}
	total := uint64(0)
	for _, child := range node.Children {
		total += snapshotHeightTotal(child)
	}
	if node.HeightTotal > total {
		return node.HeightTotal
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
	if semantic, ok := semanticFrameColor(name); ok {
		return semantic
	}

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

type semanticMatchKind int

const (
	semanticMatchContains semanticMatchKind = iota
	semanticMatchPrefix
)

type semanticRule struct {
	kind    semanticMatchKind
	pattern string
	color   color.RGBA
}

var semanticColorRules = []semanticRule{
	{kind: semanticMatchContains, pattern: "read", color: color.RGBA{R: 78, G: 132, B: 201, A: 255}},
	{kind: semanticMatchContains, pattern: "pread", color: color.RGBA{R: 78, G: 132, B: 201, A: 255}},
	{kind: semanticMatchContains, pattern: "write", color: color.RGBA{R: 222, G: 122, B: 58, A: 255}},
	{kind: semanticMatchContains, pattern: "pwrite", color: color.RGBA{R: 222, G: 122, B: 58, A: 255}},
	{kind: semanticMatchContains, pattern: "open", color: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
	{kind: semanticMatchContains, pattern: "close", color: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
	{kind: semanticMatchContains, pattern: "stat", color: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
	{kind: semanticMatchContains, pattern: "rename", color: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
	{kind: semanticMatchContains, pattern: "link", color: color.RGBA{R: 196, G: 168, B: 72, A: 255}},
	{kind: semanticMatchPrefix, pattern: "/", color: color.RGBA{R: 88, G: 156, B: 84, A: 255}},
	{kind: semanticMatchContains, pattern: "path:", color: color.RGBA{R: 88, G: 156, B: 84, A: 255}},
	{kind: semanticMatchContains, pattern: "/", color: color.RGBA{R: 88, G: 156, B: 84, A: 255}},
	{kind: semanticMatchContains, pattern: "pid", color: color.RGBA{R: 67, G: 151, B: 149, A: 255}},
	{kind: semanticMatchContains, pattern: "tid", color: color.RGBA{R: 67, G: 151, B: 149, A: 255}},
	{kind: semanticMatchPrefix, pattern: "sys_", color: color.RGBA{R: 191, G: 99, B: 74, A: 255}},
}

func semanticRuleMatches(label string, rule semanticRule) bool {
	switch rule.kind {
	case semanticMatchPrefix:
		return strings.HasPrefix(label, rule.pattern)
	default:
		return strings.Contains(label, rule.pattern)
	}
}

func semanticFrameColor(name string) (color.Color, bool) {
	label := strings.ToLower(strings.TrimSpace(name))
	if label == "" {
		return nil, false
	}
	for _, rule := range semanticColorRules {
		if semanticRuleMatches(label, rule) {
			return rule.color, true
		}
	}
	return nil, false
}

// renderViewParams bundles the pre-computed layout parameters used by
// RenderTerminalView helpers to avoid threading many individual arguments.
type renderViewParams struct {
	rowOffset     int
	maxRow        int
	barHeight     int
	leafBarHeight int
	availableRows int
	visibleFrames int
	truncated     bool
	heightMetric  bool
}

// RenderContext bundles flamegraph render inputs to avoid long positional
// parameter lists at call sites.
type RenderContext struct {
	Frames             []tuiFrame
	Width              int
	Height             int
	SelectedIdx        int
	SubtreeSet         map[int]bool
	MatchSet           map[int]bool
	FilterSet          map[int]bool
	GlobalTotal        uint64
	MetricLabel        string
	HeightMetricActive bool
	IsDark             bool
	SearchQuery        string
}

type renderRowsContext struct {
	frames             []tuiFrame
	width              int
	rowOffset          int
	maxRow             int
	barHeight          int
	leafBarHeight      int
	availableRows      int
	selectedPath       string
	subtreeSet         map[int]bool
	matchSet           map[int]bool
	selectedIdx        int
	heightMetricActive bool
	isDark             bool
}

// computeRenderParams derives the row-layout parameters for a given frame set
// and viewport height.
func computeRenderParams(frames []tuiFrame, height int, heightMetricActive bool) renderViewParams {
	return computeRenderParamsForAvailableRows(frames, height-2, heightMetricActive)
}

// computeRenderParamsForAvailableRows derives row-layout parameters for a
// frame set and pre-computed data-area row budget.
func computeRenderParamsForAvailableRows(frames []tuiFrame, availableRows int, heightMetricActive bool) renderViewParams {
	if availableRows < 1 {
		availableRows = 1
	}
	maxRow := maxFrameRowForSet(frames, nil)
	totalDepthRows := maxRow + 1
	barHeight := computeBarHeight(availableRows, totalDepthRows, maxBarVisualHeight)
	leafBarHeight := barHeight
	visibleDepthRows := availableRows / barHeight
	if heightMetricActive {
		barHeight = 1
		visibleDepthRows = availableRows
	}
	if visibleDepthRows < 1 {
		visibleDepthRows = 1
	}
	rowOffset := 0
	truncated := false
	if maxRow+1 > visibleDepthRows {
		rowOffset = maxRow + 1 - visibleDepthRows
		truncated = true
	}
	if heightMetricActive {
		visibleNonLeafRows := max(0, maxRow-rowOffset)
		leafBarHeight = availableRows - visibleNonLeafRows
		if leafBarHeight < 1 {
			leafBarHeight = 1
		}
	}
	return renderViewParams{
		rowOffset:     rowOffset,
		maxRow:        maxRow,
		barHeight:     barHeight,
		leafBarHeight: leafBarHeight,
		availableRows: availableRows,
		visibleFrames: countVisibleFrames(frames, nil),
		truncated:     truncated,
		heightMetric:  heightMetricActive,
	}
}

// frameIndexAt returns the index of the frame rendered at terminal coordinates
// (x, y), or -1 if no frame occupies that cell. showHelp adds one extra line
// to the UI chrome so the frame area row calculations account for it.
func frameIndexAt(frames []tuiFrame, x, y, width, height int, showHelp, heightMetricActive bool) int {
	if len(frames) == 0 || width <= 0 || height <= 0 {
		return -1
	}
	if x < 0 || x >= width || y < 0 {
		return -1
	}
	extraLines := 1 // selection status line
	if showHelp {
		extraLines++
	}
	renderHeight := height - extraLines
	if renderHeight < 3 {
		renderHeight = 3
	}
	params := computeRenderParamsForAvailableRows(frames, renderHeight-2, heightMetricActive)
	if y < 1 || y > params.availableRows {
		return -1
	}
	targetRow := frameCoordToTargetRow(y-1, params)
	if targetRow < 0 {
		return -1
	}
	return findFrameAtRow(frames, targetRow, x, width)
}

// frameCoordToTargetRow converts a data-area row offset (0-based, after
// stripping the toolbar row) into the logical frame row index. Returns -1 when
// the coordinate falls in the top padding above the first visible row.
func frameCoordToTargetRow(dataRow int, params renderViewParams) int {
	if params.visibleFrames == 0 || params.availableRows < 1 || dataRow < 0 || dataRow >= params.availableRows {
		return -1
	}
	renderedRows := (params.maxRow - params.rowOffset + 1) * params.barHeight
	if params.heightMetric {
		renderedRows = params.leafBarHeight + max(0, params.maxRow-params.rowOffset)*params.barHeight
	}
	padTop := 0
	if renderedRows < params.availableRows {
		padTop = params.availableRows - renderedRows
	}
	if dataRow < padTop {
		return -1
	}
	rowInRender := dataRow - padTop
	for row := params.maxRow; row >= params.rowOffset; row-- {
		rowHeight := params.barHeight
		if params.heightMetric && row == params.maxRow {
			rowHeight = params.leafBarHeight
		}
		if rowInRender < rowHeight {
			return row
		}
		rowInRender -= rowHeight
	}
	return -1
}

// findFrameAtRow scans frames for the narrowest one that occupies logical row
// targetRow and contains pixel column x within [0, width). Returning the
// narrowest frame resolves overlap between wide parent and narrow child bars.
func findFrameAtRow(frames []tuiFrame, targetRow, x, width int) int {
	best := -1
	bestWidth := int(^uint(0) >> 1)
	for idx, frame := range frames {
		if frame.Row != targetRow || frame.Col >= width {
			continue
		}
		right := min(width, frame.Col+frame.Width)
		if x < frame.Col || x >= right {
			continue
		}
		if frame.Width < bestWidth {
			best = idx
			bestWidth = frame.Width
		}
	}
	return best
}

// buildToolbar assembles the top-of-view toolbar string and pads/trims it to
// width. The toolbar is replaced by the caller via replaceHeaderLine.
// A Builder is used to avoid an extra allocation for the optional truncation suffix.
func buildToolbar(frames []tuiFrame, width int, params renderViewParams) string {
	viewPath := compactFramePath(frames[0].Path)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Flame | view:%s | frames:%d | rows:%d",
		viewPath, params.visibleFrames, params.availableRows))
	if params.truncated {
		b.WriteString(" | showing deepest levels")
	}
	return padOrTrim(b.String(), width)
}

// buildFilteredStatus builds the per-selection status line when a search filter
// is active. The searchQuery is embedded in the status so the user can see
// which pattern is applied.
func buildFilteredStatus(frames []tuiFrame, selected tuiFrame, selectedIdx int, matchSet map[int]bool, metricLabel, searchQuery string, globalTotal uint64, visibleFrames int) string {
	filterCoveredTotal, filterBaseTotal := filterCoverageTotals(frames, matchSet, globalTotal)
	filterSystemShare := percentOfTotal(filterCoveredTotal, filterBaseTotal)
	selectedFilterShare := 0.0
	if filterCoveredTotal > 0 {
		selectedMatchTotal := filterCoverageTotalForPath(frames, matchSet, selected.Path)
		selectedFilterShare = percentOfTotal(selectedMatchTotal, filterCoveredTotal)
	}
	matches := orderedMatchIndices(matchSet)
	pos := 0
	if len(matches) > 0 {
		if idx := indexOf(matches, selectedIdx); idx >= 0 {
			pos = idx + 1
		}
	}
	frameCoverage := 0.0
	if len(frames) > 0 {
		frameCoverage = 100 * float64(visibleFrames) / float64(len(frames))
	}
	return fmt.Sprintf("Filter %q: %.1f%% %s (%d/%d matches, %.1f%% frames shown) | Selected: %s total(%s)=%d depth=%d %.2f%% filtered %s",
		searchQuery, filterSystemShare, metricLabel, pos, len(matches), frameCoverage,
		selected.Name, metricLabel, selected.Total, selected.Depth, selectedFilterShare, metricLabel)
}

// buildNormalStatus builds the per-selection status line when no filter is active.
func buildNormalStatus(selected tuiFrame, metricLabel string, globalTotal uint64) string {
	selectedSystemShare := selected.Percent
	if globalTotal > 0 {
		selectedSystemShare = percentOfTotal(selected.Total, globalTotal)
	}
	return fmt.Sprintf("Selected: %s [%s] total(%s)=%d depth=%d col=%d width=%d share=%.2f%% %s",
		selected.Name, compactFramePath(selected.Path), metricLabel, selected.Total, selected.Depth, selected.Col, selected.Width, selectedSystemShare, metricLabel)
}

// RenderTerminalView renders a terminal flamegraph viewport from laid out frames.
// The function is split into helpers (computeRenderParams, buildToolbar,
// buildFilteredStatus, buildNormalStatus) to keep each piece under 50 lines.
func RenderTerminalView(ctx RenderContext) string {
	frames := ctx.Frames
	width := ctx.Width
	height := ctx.Height
	selectedIdx := ctx.SelectedIdx
	subtreeSet := ctx.SubtreeSet
	matchSet := ctx.MatchSet
	filterSet := ctx.FilterSet
	globalTotal := ctx.GlobalTotal
	metricLabel := ctx.MetricLabel
	heightMetricActive := ctx.HeightMetricActive
	isDark := ctx.IsDark
	searchQuery := ctx.SearchQuery

	if width < minFlameWidth {
		return common.PanelStyle.Render("Flame: terminal too narrow (need >= 60 columns)")
	}
	if height < 3 {
		return common.PanelStyle.Render("Flame: viewport too short")
	}
	if len(frames) == 0 {
		return common.PanelStyle.Render("Flame: waiting for data...")
	}
	if strings.TrimSpace(metricLabel) == "" {
		metricLabel = "events"
	}
	filterIsActive := strings.TrimSpace(searchQuery) != ""
	if filterIsActive {
		if filterSet == nil {
			filterSet = computeFilterVisibleSetInto(frames, matchSet, nil)
		}
		if len(filterSet) == 0 {
			return common.PanelStyle.Render(fmt.Sprintf("Flame: no frames match filter %q", searchQuery))
		}
	} else {
		filterSet = nil
	}
	selectedIdx = normalizeSelectedIndex(frames, selectedIdx, filterSet)
	selected := frames[selectedIdx]
	if subtreeSet == nil {
		subtreeSet = computeSubtreeSet(frames, selectedIdx)
	}
	params := computeRenderParams(frames, height, heightMetricActive)
	toolbar := buildToolbar(frames, width, params)
	var status string
	if filterIsActive {
		status = buildFilteredStatus(frames, selected, selectedIdx, matchSet, metricLabel, searchQuery, globalTotal, params.visibleFrames)
	} else {
		status = buildNormalStatus(selected, metricLabel, globalTotal)
	}
	rows := buildRenderRows(renderRowsContext{
		frames:             frames,
		width:              width,
		rowOffset:          params.rowOffset,
		maxRow:             params.maxRow,
		barHeight:          params.barHeight,
		leafBarHeight:      params.leafBarHeight,
		availableRows:      params.availableRows,
		selectedPath:       selected.Path,
		subtreeSet:         subtreeSet,
		matchSet:           matchSet,
		selectedIdx:        selectedIdx,
		heightMetricActive: heightMetricActive,
		isDark:             isDark,
	})
	return renderViewRows(toolbar, status, rows, width)
}

func renderViewRows(toolbar, status string, rows []string, width int) string {
	status = padOrTrim(status, width)
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

func buildRenderRows(ctx renderRowsContext) []string {
	frames := ctx.frames
	width := ctx.width
	rowOffset := ctx.rowOffset
	maxRow := ctx.maxRow
	barHeight := ctx.barHeight
	leafBarHeight := ctx.leafBarHeight
	availableRows := ctx.availableRows
	selectedPath := ctx.selectedPath
	subtreeSet := ctx.subtreeSet
	matchSet := ctx.matchSet
	selectedIdx := ctx.selectedIdx
	heightMetricActive := ctx.heightMetricActive
	isDark := ctx.isDark

	rowsByDepth := make(map[int][]indexedFrame)
	for idx, frame := range frames {
		if frame.Row < rowOffset || frame.Row > maxRow {
			continue
		}
		rowsByDepth[frame.Row] = append(rowsByDepth[frame.Row], indexedFrame{idx: idx, frame: frame})
	}

	if barHeight < 1 {
		barHeight = 1
	}

	rows := make([]string, 0, (maxRow-rowOffset+1)*barHeight)
	for row := maxRow; row >= rowOffset; row-- {
		framesAtRow := rowsByDepth[row]
		slices.SortFunc(framesAtRow, func(a, b indexedFrame) int {
			return cmp.Compare(a.frame.Col, b.frame.Col)
		})
		if heightMetricActive && row == maxRow {
			frameHeights := leafFrameHeights(framesAtRow, leafBarHeight)
			for h := leafBarHeight - 1; h >= 0; h-- {
				showLabels := h == 0
				rows = append(rows, renderLeafRowBand(framesAtRow, frameHeights, h, width, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, showLabels))
			}
			continue
		}
		for repeat := 0; repeat < barHeight; repeat++ {
			showLabels := repeat == barHeight/2
			rows = append(rows, renderRow(framesAtRow, width, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, showLabels))
		}
	}

	if availableRows > 0 {
		if len(rows) > availableRows {
			rows = rows[:availableRows]
		}
		if len(rows) < availableRows {
			blank := strings.Repeat(" ", width)
			pad := make([]string, 0, availableRows)
			for i := 0; i < availableRows-len(rows); i++ {
				pad = append(pad, blank)
			}
			pad = append(pad, rows...)
			rows = pad
		}
	}
	return rows
}

func leafFrameHeights(frames []indexedFrame, leafBarHeight int) map[int]int {
	heights := make(map[int]int, len(frames))
	if leafBarHeight < 1 {
		leafBarHeight = 1
	}
	maxHeightTotal := uint64(0)
	for _, item := range frames {
		if item.frame.HeightTotal > maxHeightTotal {
			maxHeightTotal = item.frame.HeightTotal
		}
	}
	for _, item := range frames {
		frameHeight := 1
		if maxHeightTotal > 0 {
			scaled := math.Round(float64(leafBarHeight) * (float64(item.frame.HeightTotal) / float64(maxHeightTotal)))
			frameHeight = int(scaled)
		}
		frameHeight = max(1, frameHeight)
		frameHeight = min(leafBarHeight, frameHeight)
		heights[item.idx] = frameHeight
	}
	return heights
}

func renderLeafRowBand(frames []indexedFrame, frameHeights map[int]int, band, width int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, showLabels bool) string {
	visible := make([]indexedFrame, 0, len(frames))
	for _, item := range frames {
		if frameHeights[item.idx] > band {
			visible = append(visible, item)
		}
	}
	return renderRow(visible, width, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, showLabels)
}

func renderRow(frames []indexedFrame, width int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, showLabels bool) string {
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
		label := strings.Repeat(" ", cellWidth)
		if showLabels {
			label = frameLabel(frame.Name, cellWidth, item.idx == selectedIdx, matchSet != nil && matchSet[item.idx])
		}
		style := styleForFrame(item.idx, frame, selectedPath, subtreeSet, matchSet, selectedIdx, isDark)
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
	return computeSubtreeSetInto(frames, selectedIdx, nil)
}

func computeSubtreeSetInto(frames []tuiFrame, selectedIdx int, subtree map[int]bool) map[int]bool {
	if subtree == nil {
		subtree = make(map[int]bool)
	} else {
		for idx := range subtree {
			delete(subtree, idx)
		}
	}
	if selectedIdx < 0 || selectedIdx >= len(frames) {
		return subtree
	}

	selectedPath := frames[selectedIdx].Path
	for idx, frame := range frames {
		path := frame.Path
		if path == selectedPath ||
			hasPathBoundaryPrefix(path, selectedPath) ||
			hasPathBoundaryPrefix(selectedPath, path) {
			subtree[idx] = true
		}
	}
	return subtree
}

func hasPathBoundaryPrefix(value, prefix string) bool {
	if len(value) <= len(prefix) {
		return false
	}
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return value[len(prefix)] == pathSeparatorByte
}

func computeFilterVisibleSetInto(frames []tuiFrame, matchSet, visible map[int]bool) map[int]bool {
	if visible == nil {
		visible = make(map[int]bool)
	} else {
		for idx := range visible {
			delete(visible, idx)
		}
	}
	if len(matchSet) == 0 {
		return visible
	}

	matchPaths := make([]string, 0, len(matchSet))
	for idx := range matchSet {
		if idx >= 0 && idx < len(frames) {
			matchPaths = append(matchPaths, frames[idx].Path)
		}
	}
	for idx, frame := range frames {
		for _, matchPath := range matchPaths {
			// Show matching frames and their full ancestry to root.
			if frame.Path == matchPath || hasPathBoundaryPrefix(matchPath, frame.Path) {
				visible[idx] = true
				break
			}
		}
	}
	return visible
}

func styleForFrame(idx int, frame tuiFrame, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark bool) lipgloss.Style {
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
		selectedBg := lipgloss.Color("129")
		selectedFg := lipgloss.Color("15")
		return base.Background(selectedBg).Foreground(selectedFg).Bold(true)
	}

	if isMatch {
		style := base.Background(matchColor).Foreground(lipgloss.Color("15"))
		if inSubtree {
			return style.Bold(true)
		}
		return style.Faint(true)
	}

	if inSubtree {
		if frameRelation(frame.Path, selectedPath) == relationAncestor {
			return base.BorderLeft(true).BorderForeground(common.ColorAccent)
		}
		return base
	}

	return base.Background(common.ColorPanel).Foreground(common.ColorMuted).Faint(true)
}

func frameLabel(name string, width int, isSelected, isMatch bool) string {
	if width <= 0 {
		return ""
	}
	if isSelected {
		if width == 1 {
			return ">"
		}
		return ">" + padOrTrim(name, width-2) + "<"
	}
	if isMatch {
		if width == 1 {
			return "*"
		}
		return "*" + padOrTrim(name, width-1)
	}
	return padOrTrim(name, width)
}

func compactFramePath(path string) string {
	if path == "" {
		return "root"
	}
	parts := strings.Split(path, pathSeparator)
	if len(parts) <= 3 {
		return strings.Join(parts, "/")
	}
	return strings.Join([]string{parts[0], "...", parts[len(parts)-1]}, "/")
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

func maxFrameRowForSet(frames []tuiFrame, include map[int]bool) int {
	maxRow := 0
	for idx, frame := range frames {
		if include != nil && !include[idx] {
			continue
		}
		if frame.Row > maxRow {
			maxRow = frame.Row
		}
	}
	return maxRow
}

func countVisibleFrames(frames []tuiFrame, include map[int]bool) int {
	if include == nil {
		return len(frames)
	}
	count := 0
	for idx := range frames {
		if include[idx] {
			count++
		}
	}
	return count
}

func normalizeSelectedIndex(frames []tuiFrame, selectedIdx int, include map[int]bool) int {
	if len(frames) == 0 {
		return 0
	}
	if selectedIdx >= 0 && selectedIdx < len(frames) && (include == nil || include[selectedIdx]) {
		return selectedIdx
	}
	if include != nil {
		for idx := range frames {
			if include[idx] {
				return idx
			}
		}
	}
	return 0
}

func computeBarHeight(availableRows, depthRows, maxHeight int) int {
	if availableRows <= 0 || depthRows <= 0 {
		return 1
	}
	height := availableRows / depthRows
	if height < 1 {
		height = 1
	}
	if maxHeight > 0 && height > maxHeight {
		height = maxHeight
	}
	return height
}

func filterCoverageTotals(frames []tuiFrame, matchSet map[int]bool, totalBase uint64) (coveredTotal uint64, rootTotal uint64) {
	if len(frames) == 0 || len(matchSet) == 0 {
		return 0, 0
	}
	rootTotal = totalBase
	if rootTotal == 0 {
		rootTotal = frames[0].Total
	}
	if rootTotal == 0 {
		return 0, 0
	}
	roots := compactMatchRoots(frames, matchSet)
	for _, root := range roots {
		coveredTotal += root.total
	}
	return coveredTotal, rootTotal
}

func filterCoverageTotalForPath(frames []tuiFrame, matchSet map[int]bool, path string) uint64 {
	if path == "" || len(frames) == 0 || len(matchSet) == 0 {
		return 0
	}
	roots := compactMatchRoots(frames, matchSet)
	var coveredTotal uint64
	for _, root := range roots {
		if root.path == path || hasPathBoundaryPrefix(root.path, path) {
			coveredTotal += root.total
		}
	}
	return coveredTotal
}

type matchRoot struct {
	path  string
	total uint64
}

func compactMatchRoots(frames []tuiFrame, matchSet map[int]bool) []matchRoot {
	roots := make([]matchRoot, 0, len(matchSet))
	for idx := range matchSet {
		if idx < 0 || idx >= len(frames) {
			continue
		}
		roots = append(roots, matchRoot{
			path:  frames[idx].Path,
			total: frames[idx].Total,
		})
	}
	slices.SortFunc(roots, func(a, b matchRoot) int {
		return cmp.Compare(len(a.path), len(b.path))
	})
	merged := make([]matchRoot, 0, len(roots))
	for _, candidate := range roots {
		covered := false
		for _, root := range merged {
			if candidate.path == root.path || hasPathBoundaryPrefix(candidate.path, root.path) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		merged = append(merged, candidate)
	}
	return merged
}

func percentOfTotal(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(value) / float64(total)
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
