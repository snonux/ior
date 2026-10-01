package flamegraph

import (
	"cmp"
	"fmt"
	"hash/fnv"
	"image/color"
	"iter"
	"math"
	"slices"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

const pathSeparator = "\x1f"
const pathSeparatorByte = '\x1f'
const minFlameWidth = 60
const maxBarVisualHeight = 3

type childWidth struct {
	idx   int
	total uint64
	raw   float64
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

// collectTerminalLayout appends the frame for node and, recursively, for its
// descendants, laid out in the column band [col, col+span) at row depth.
func collectTerminalLayout(out *[]tuiFrame, node *snapshotNode, rootTotal uint64, height, depth, col int, path string, span int, normalizeRootChildren bool) {
	if node == nil || depth >= height {
		return
	}
	total := snapshotTotal(node)
	if total == 0 || span < 1 {
		return
	}

	*out = append(*out, newTerminalFrame(node, total, rootTotal, depth, col, span, path))
	if len(node.Children) == 0 {
		return
	}

	layoutTotal, layoutSpan := childLayoutBounds(node, total, span, normalizeRootChildren && depth == 0)
	childWidths := allocateChildWidths(node.Children, layoutTotal, layoutSpan)
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

// newTerminalFrame builds the display frame of one snapshot node.
func newTerminalFrame(node *snapshotNode, total, rootTotal uint64, depth, col, span int, path string) tuiFrame {
	name := frameName(node.Name, depth)
	return tuiFrame{
		// Sanitised display label (traced names are attacker-controlled, and
		// an unterminated ESC[ would swallow padOrTrim's padding); Path keeps
		// the raw names because it is the lookup key.
		Name:        common.Sanitize(name),
		Col:         col,
		Row:         depth,
		Width:       span,
		Total:       total,
		HeightTotal: snapshotHeightTotal(node),
		Percent:     100 * float64(total) / float64(rootTotal),
		Fill:        terminalFrameColor(name),
		Depth:       depth,
		Path:        path,
	}
}

// childLayoutBounds returns the total and column span that node's children
// are sized against. normalizeRoot is set for the root of a zoomed view,
// whose children fill the whole width.
func childLayoutBounds(node *snapshotNode, total uint64, span int, normalizeRoot bool) (layoutTotal uint64, layoutSpan int) {
	childrenTotal := childSnapshotTotal(node.Children)
	if normalizeRoot {
		if childrenTotal > 0 {
			return childrenTotal, span
		}
		return total, span
	}
	if representedTotal := node.Value + childrenTotal; representedTotal > 0 && representedTotal < total {
		// Snapshot totals retain the contribution of pruned descendants. Size
		// the remaining children against their represented total so pruning
		// does not leave a hole in the original child band. A node's own value
		// determines that band's span and therefore keeps its proportional gap.
		return childrenTotal, proportionalChildSpan(span, total-node.Value, total)
	}
	return total, span
}

func proportionalChildSpan(span int, childTotal, parentTotal uint64) int {
	if span <= 0 || childTotal == 0 || parentTotal == 0 {
		return 0
	}
	if childTotal >= parentTotal {
		return span
	}
	childSpan := int(math.Floor(float64(span) * (float64(childTotal) / float64(parentTotal))))
	return max(1, childSpan)
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

	items := make([]childWidth, 0, len(children))
	childrenTotal := uint64(0)
	used := 0
	for idx, child := range children {
		total := snapshotTotal(child)
		if total == 0 {
			continue
		}
		childrenTotal += total
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
		fallbackSpan := proportionalChildSpan(span, childrenTotal, parentTotal)
		keepLargestChildrenVisible(widths, items, fallbackSpan)
		return widths
	}

	partitionVisibleChildWidths(widths, items, childrenTotal, parentTotal, span)
	return widths
}

func keepLargestChildrenVisible(widths []int, items []childWidth, span int) {
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

func partitionVisibleChildWidths(widths []int, items []childWidth, childrenTotal, parentTotal uint64, span int) {
	// Floors deliberately cull sub-cell children, but the cells lost to
	// rounding (and to those culled children) still belong to this child band.
	// Reallocate the band's target span among the already-visible children so
	// their widths form a stable, gap-free partition without reviving noise.
	targetSpan := span
	if childrenTotal < parentTotal {
		targetSpan = int(math.Floor(float64(span) * (float64(childrenTotal) / float64(parentTotal))))
	}
	visibleItems := items[:0]
	visibleTotal := uint64(0)
	for _, item := range items {
		if widths[item.idx] == 0 {
			continue
		}
		visibleItems = append(visibleItems, item)
		visibleTotal += item.total
	}
	if len(visibleItems) == 0 {
		return
	}
	used := 0
	for idx := range visibleItems {
		raw := float64(targetSpan) * (float64(visibleItems[idx].total) / float64(visibleTotal))
		visibleItems[idx].raw = raw
		width := int(math.Floor(raw))
		widths[visibleItems[idx].idx] = width
		used += width
	}
	slices.SortFunc(visibleItems, func(a, b childWidth) int {
		aRemainder := a.raw - math.Floor(a.raw)
		bRemainder := b.raw - math.Floor(b.raw)
		if aRemainder != bRemainder {
			return cmp.Compare(bRemainder, aRemainder)
		}
		return cmp.Compare(a.idx, b.idx)
	})
	for idx := 0; used < targetSpan; idx++ {
		widths[visibleItems[idx%len(visibleItems)].idx]++
		used++
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
//
// When RenderTerminalView draws a placeholder message instead of frames
// ("terminal too narrow", "viewport too short", "waiting for data"), nothing
// is hittable, so the same width/height/frame-count test it uses
// (layoutPlaceholder) makes this return -1 too; without it the frames laid
// out for a width the screen no longer shows would still resolve and a click
// on blank space would zoom into an undrawn frame. The "no frames match
// filter" placeholder depends on the search state, not on geometry, so the
// caller checks it with filterHidesAllFrames before calling this.
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
	if _, placeholder := layoutPlaceholder(width, renderHeight, len(frames)); placeholder {
		return -1
	}
	params := computeRenderParamsForAvailableRows(frames, renderHeight-2, heightMetricActive)
	if y < 1 || y > params.availableRows {
		return -1
	}
	line, ok := frameCoordToLine(y-1, params)
	if !ok {
		return -1
	}
	return findFrameAtLine(frames, line, x, width)
}

// frameLine identifies one rendered terminal line of the frame area: the
// logical frame row it belongs to and, for the height-metric leaf row, which
// of its bands it is. band is -1 for every other row, whose repeated lines
// all draw the same frames; for the leaf row it counts up from 0 (the bottom
// band) exactly like the band argument of renderLeafRowBand, and
// leafBarHeight is the band count needed to rescale leafFrameHeights.
type frameLine struct {
	row           int
	band          int
	leafBarHeight int
}

// frameCoordToLine converts a data-area row offset (0-based, after stripping
// the toolbar row) into the frameLine drawn there, mirroring buildRenderRows'
// top-to-bottom emission order (deepest row first, leaf bands from the top
// band down). ok is false when the coordinate falls in the top padding above
// the first visible row or outside the data area.
func frameCoordToLine(dataRow int, params renderViewParams) (line frameLine, ok bool) {
	if params.visibleFrames == 0 || params.availableRows < 1 || dataRow < 0 || dataRow >= params.availableRows {
		return frameLine{}, false
	}
	renderedRows := (params.maxRow - params.rowOffset + 1) * params.barHeight
	if params.heightMetric {
		renderedRows = params.leafBarHeight + max(0, params.maxRow-params.rowOffset)*params.barHeight
	}
	padTop := max(0, params.availableRows-renderedRows)
	if dataRow < padTop {
		return frameLine{}, false
	}
	rowInRender := dataRow - padTop
	for row := params.maxRow; row >= params.rowOffset; row-- {
		if params.heightMetric && row == params.maxRow {
			if rowInRender < params.leafBarHeight {
				// buildRenderRows emits band leafBarHeight-1 first.
				band := params.leafBarHeight - 1 - rowInRender
				return frameLine{row: row, band: band, leafBarHeight: params.leafBarHeight}, true
			}
			rowInRender -= params.leafBarHeight
			continue
		}
		if rowInRender < params.barHeight {
			return frameLine{row: row, band: -1}, true
		}
		rowInRender -= params.barHeight
	}
	return frameLine{}, false
}

// findFrameAtLine returns the index of the frame drawn at column x of line,
// or -1 when that cell is blank. It selects the same frames the renderer
// draws on that line (framesOnLine, which applies the leaf-band filter of
// renderLeafRowBand) and resolves the cell with frameAtCell, which replays
// renderRow's clipped column walk. Hit testing therefore agrees with the
// screen cell by cell, including upper leaf bands above shorter frames and
// mid-animation overlaps where a later frame is drawn only from the end of
// an earlier one.
func findFrameAtLine(frames []tuiFrame, line frameLine, x, width int) int {
	if x < 0 || x >= width {
		return -1
	}
	return frameAtCell(framesOnLine(frames, line), x, width)
}

// framesOnLine collects the frames of line.row in renderRow order and, for a
// leaf band, keeps only those tall enough to reach it. It recomputes
// leafFrameHeights over the same row set buildRenderRows uses, so both sides
// derive identical band heights.
func framesOnLine(frames []tuiFrame, line frameLine) []indexedFrame {
	var framesAtRow []indexedFrame
	for idx, frame := range frames {
		if frame.Row == line.row {
			framesAtRow = append(framesAtRow, indexedFrame{idx: idx, frame: frame})
		}
	}
	sortFramesByCol(framesAtRow)
	if line.band < 0 {
		return framesAtRow
	}
	return leafBandFrames(framesAtRow, leafFrameHeights(framesAtRow, line.leafBarHeight), line.band)
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
// which pattern is applied; it is typed or pasted text, so it is sanitised
// first (%q alone prints U+2800 and U+FFFC raw; task ms2).
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
		common.Sanitize(searchQuery), filterSystemShare, metricLabel, pos, len(matches), frameCoverage,
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
// The work is split into helpers so each piece stays short: renderPlaceholder
// handles the degenerate-viewport/no-data messages, resolveRenderFilterSet
// decides which frames the active search filter keeps visible, and
// renderSelectedView lays out toolbar, rows and status line for the chosen
// selection.
func RenderTerminalView(ctx RenderContext) string {
	if msg, ok := renderPlaceholder(ctx); ok {
		return renderMessagePanel(msg, ctx.Width)
	}
	if strings.TrimSpace(ctx.MetricLabel) == "" {
		ctx.MetricLabel = "events"
	}
	filterSet, filterIsActive := resolveRenderFilterSet(ctx)
	if filterIsActive && filterHidesAllFrames(filterSet) {
		return renderMessagePanel(fmt.Sprintf("Flame: no frames match filter %q", common.Sanitize(ctx.SearchQuery)), ctx.Width)
	}
	ctx.FilterSet = filterSet
	return renderSelectedView(ctx, filterIsActive)
}

// messagePanelChrome is the columns PanelStyle adds around its text: a border
// cell and a padding cell on each side.
const messagePanelChrome = 4

// renderMessagePanel boxes a placeholder message in PanelStyle, cut so the
// panel is at most width cells wide. The "terminal too narrow" message is
// shown precisely when the terminal is narrow, and a line wider than the
// terminal would soft-wrap into extra rows the dashboard has not budgeted.
// Below the panel's own chrome plus one cell the bare message is cut instead;
// width <= 0 means unbounded.
func renderMessagePanel(msg string, width int) string {
	if width <= 0 {
		return common.Current().PanelStyle.Render(msg)
	}
	if width <= messagePanelChrome {
		return common.TruncateRight(msg, width, "…")
	}
	return common.Current().PanelStyle.Render(common.TruncateRight(msg, width-messagePanelChrome, "…"))
}

// renderPlaceholder returns the message shown instead of a flamegraph when the
// viewport is too small or there are no frames yet. ok is false when a real
// flamegraph can be rendered.
func renderPlaceholder(ctx RenderContext) (msg string, ok bool) {
	return layoutPlaceholder(ctx.Width, ctx.Height, len(ctx.Frames))
}

// layoutPlaceholder is the geometry-and-data half of the placeholder decision,
// shared by the renderer (renderPlaceholder) and the mouse hit test
// (frameIndexAt) so the two cannot disagree about when frames are on screen.
// height is the render height (terminal height minus the status/help lines).
func layoutPlaceholder(width, height, frameCount int) (msg string, ok bool) {
	switch {
	case width < minFlameWidth:
		return "Flame: terminal too narrow (need >= 60 columns)", true
	case height < 3:
		return "Flame: viewport too short", true
	case frameCount == 0:
		return "Flame: waiting for data...", true
	}
	return "", false
}

// filterHidesAllFrames reports whether an applied search filter keeps no frame
// visible, in which case RenderTerminalView shows "no frames match filter"
// instead of the flamegraph. filterSet is the filter-visible set; callers
// only ask while a filter is active (filterActive(query)).
func filterHidesAllFrames(filterSet map[int]bool) bool {
	return len(filterSet) == 0
}

// resolveRenderFilterSet returns the set of frames kept visible by the search
// filter and whether a filter is active at all. Without a search query the set
// is nil so every frame is drawn. Callers without a SearchController-maintained
// set get the same visibility rule as the live search path (matches,
// descendants and ancestors).
func resolveRenderFilterSet(ctx RenderContext) (map[int]bool, bool) {
	if strings.TrimSpace(ctx.SearchQuery) == "" {
		return nil, false
	}
	if ctx.FilterSet != nil {
		return ctx.FilterSet, true
	}
	return filterVisibleSetUsingAncestry(ctx.Frames, ctx.MatchSet, buildFrameAncestry(ctx.Frames), nil), true
}

// renderSelectedView renders toolbar, flame rows and status line once the
// viewport is known to be drawable and ctx.FilterSet/ctx.MetricLabel have been
// resolved. The selection is normalised into the visible (filtered) frames.
func renderSelectedView(ctx RenderContext, filterIsActive bool) string {
	frames := ctx.Frames
	selectedIdx := normalizeSelectedIndex(frames, ctx.SelectedIdx, ctx.FilterSet)
	selected := frames[selectedIdx]
	subtreeSet := ctx.SubtreeSet
	if subtreeSet == nil {
		subtreeSet = computeSubtreeSet(frames, selectedIdx)
	}
	params := computeRenderParams(frames, ctx.Height, ctx.HeightMetricActive)
	toolbar := buildToolbar(frames, ctx.Width, params)
	var status string
	if filterIsActive {
		status = buildFilteredStatus(frames, selected, selectedIdx, ctx.MatchSet, ctx.MetricLabel, ctx.SearchQuery, ctx.GlobalTotal, params.visibleFrames)
	} else {
		status = buildNormalStatus(selected, ctx.MetricLabel, ctx.GlobalTotal)
	}
	rows := buildRenderRows(renderRowsContext{
		frames:             frames,
		width:              ctx.Width,
		rowOffset:          params.rowOffset,
		maxRow:             params.maxRow,
		barHeight:          params.barHeight,
		leafBarHeight:      params.leafBarHeight,
		availableRows:      params.availableRows,
		selectedPath:       selected.Path,
		subtreeSet:         subtreeSet,
		matchSet:           ctx.MatchSet,
		selectedIdx:        selectedIdx,
		heightMetricActive: ctx.HeightMetricActive,
		isDark:             ctx.IsDark,
	})
	return renderViewRows(toolbar, status, rows, ctx.Width)
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

// buildRenderRows draws the visible flame rows top (deepest row, maxRow) to
// bottom (rowOffset). Each row repeats barHeight lines; with the height metric
// active the deepest row is drawn as leafBarHeight bands instead. The result
// is fitted to availableRows by fitRowsToViewport.
func buildRenderRows(ctx renderRowsContext) []string {
	rowsByDepth := groupFramesByRow(ctx.frames, ctx.rowOffset, ctx.maxRow)
	if ctx.barHeight < 1 {
		ctx.barHeight = 1
	}
	rows := make([]string, 0, (ctx.maxRow-ctx.rowOffset+1)*ctx.barHeight)
	for row := ctx.maxRow; row >= ctx.rowOffset; row-- {
		framesAtRow := rowsByDepth[row]
		sortFramesByCol(framesAtRow)
		if ctx.heightMetricActive && row == ctx.maxRow {
			rows = appendLeafRowBands(rows, framesAtRow, ctx)
			continue
		}
		for repeat := 0; repeat < ctx.barHeight; repeat++ {
			showLabels := repeat == ctx.barHeight/2
			rows = append(rows, renderRow(framesAtRow, ctx.width, ctx.selectedPath, ctx.subtreeSet, ctx.matchSet, ctx.selectedIdx, ctx.isDark, showLabels))
		}
	}
	return fitRowsToViewport(rows, ctx.availableRows, ctx.width)
}

// groupFramesByRow buckets the frames whose Row lies in [rowOffset, maxRow],
// remembering each frame's original index for selection/match lookups.
func groupFramesByRow(frames []tuiFrame, rowOffset, maxRow int) map[int][]indexedFrame {
	rowsByDepth := make(map[int][]indexedFrame)
	for idx, frame := range frames {
		if frame.Row < rowOffset || frame.Row > maxRow {
			continue
		}
		rowsByDepth[frame.Row] = append(rowsByDepth[frame.Row], indexedFrame{idx: idx, frame: frame})
	}
	return rowsByDepth
}

// appendLeafRowBands appends the leafBarHeight bands of the height-metric leaf
// row, highest band first; labels are only drawn on the bottom band (h == 0).
func appendLeafRowBands(rows []string, framesAtRow []indexedFrame, ctx renderRowsContext) []string {
	frameHeights := leafFrameHeights(framesAtRow, ctx.leafBarHeight)
	for h := ctx.leafBarHeight - 1; h >= 0; h-- {
		showLabels := h == 0
		rows = append(rows, renderLeafRowBand(framesAtRow, frameHeights, h, ctx.width, ctx.selectedPath, ctx.subtreeSet, ctx.matchSet, ctx.selectedIdx, ctx.isDark, showLabels))
	}
	return rows
}

// fitRowsToViewport trims rows to availableRows, or top-pads them with blank
// lines so the flamegraph stays anchored to the bottom of the viewport. A
// non-positive availableRows leaves rows unchanged.
func fitRowsToViewport(rows []string, availableRows, width int) []string {
	if availableRows <= 0 {
		return rows
	}
	if len(rows) > availableRows {
		return rows[:availableRows]
	}
	if len(rows) < availableRows {
		blank := strings.Repeat(" ", width)
		pad := make([]string, 0, availableRows)
		for i := 0; i < availableRows-len(rows); i++ {
			pad = append(pad, blank)
		}
		return append(pad, rows...)
	}
	return rows
}

// leafFrameHeights scales each leaf-row frame's HeightTotal to a band count in
// [1, leafBarHeight], relative to the tallest frame of the row. It is keyed by
// frame index and consumed by leafBandFrames on both the drawing path
// (buildRenderRows) and the hit-testing path (framesOnLine).
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

// renderLeafRowBand draws one band of the height-metric leaf row: only the
// frames whose scaled height reaches band (see leafBandFrames).
func renderLeafRowBand(frames []indexedFrame, frameHeights map[int]int, band, width int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, showLabels bool) string {
	return renderRow(leafBandFrames(frames, frameHeights, band), width, selectedPath, subtreeSet, matchSet, selectedIdx, isDark, showLabels)
}

// leafBandFrames returns the frames drawn on leaf band band (0 = bottom):
// those whose leafFrameHeights entry is taller than band, so shorter frames
// leave the upper bands blank. Order is preserved. renderLeafRowBand and the
// mouse hit test (framesOnLine) share it so they agree on band contents.
func leafBandFrames(frames []indexedFrame, frameHeights map[int]int, band int) []indexedFrame {
	visible := make([]indexedFrame, 0, len(frames))
	for _, item := range frames {
		if frameHeights[item.idx] > band {
			visible = append(visible, item)
		}
	}
	return visible
}

// sortFramesByCol orders one row's frames left to right. The sort is stable
// so frames sharing a Col (possible mid-animation) keep their layout order;
// renderRow and the mouse hit test both walk this exact order (via
// drawnSpans) to agree on which frame owns an overlapping cell.
func sortFramesByCol(frames []indexedFrame) {
	slices.SortStableFunc(frames, func(a, b indexedFrame) int {
		return cmp.Compare(a.frame.Col, b.frame.Col)
	})
}

// drawnCellSpan returns the half-open column range [start, end) that frame
// occupies when drawn after earlier frames of the same row have filled the
// columns up to cursor. Settled layouts never overlap, but the spring
// animation moves every frame independently, so a frame can start left of
// cursor (inside its still-sliding neighbour). Drawing it at full width from
// cursor would push the row past width and shift everything after it, so the
// frame is clipped to the columns the earlier frame did not claim and to the
// viewport. ok is false when nothing of the frame remains visible.
func drawnCellSpan(frame tuiFrame, cursor, width int) (start, end int, ok bool) {
	start = max(frame.Col, cursor)
	end = min(frame.Col+frame.Width, width)
	if start >= end {
		return 0, 0, false
	}
	return start, end, true
}

// cellSpan is the half-open column range [start, end) a frame is drawn on.
type cellSpan struct {
	start, end int
}

// drawnSpans yields every visible frame of a line (sorted by sortFramesByCol)
// with the cells it is drawn on, advancing the cursor through drawnCellSpan
// and skipping fully hidden frames. It is the single column walk shared by
// renderRow (drawing) and frameAtCell (hit testing).
func drawnSpans(frames []indexedFrame, width int) iter.Seq2[indexedFrame, cellSpan] {
	return func(yield func(indexedFrame, cellSpan) bool) {
		cursor := 0
		for _, item := range frames {
			start, end, ok := drawnCellSpan(item.frame, cursor, width)
			if !ok {
				continue
			}
			if !yield(item, cellSpan{start: start, end: end}) {
				return
			}
			cursor = end
		}
	}
}

// frameAtCell returns the index of the frame renderRow draws at column x of
// the given line frames, or -1 when that cell is blank.
func frameAtCell(frames []indexedFrame, x, width int) int {
	for item, span := range drawnSpans(frames, width) {
		if x < span.start {
			return -1 // spans are ascending: x lies in a gap
		}
		if x < span.end {
			return item.idx
		}
	}
	return -1
}

// renderRow draws one terminal line of frames, which must already be sorted
// by sortFramesByCol. The cells come from drawnSpans, which keeps the line
// exactly width cells wide even mid-animation; frameAtCell walks the same
// spans so mouse hits match what is on screen.
func renderRow(frames []indexedFrame, width int, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark, showLabels bool) string {
	if len(frames) == 0 {
		return strings.Repeat(" ", width)
	}
	var b strings.Builder
	b.Grow(width + 8)
	cursor := 0
	for item, span := range drawnSpans(frames, width) {
		if span.start > cursor {
			b.WriteString(strings.Repeat(" ", span.start-cursor))
		}
		cellWidth := span.end - span.start
		label := strings.Repeat(" ", cellWidth)
		if showLabels {
			label = frameLabel(item.frame.Name, cellWidth, item.idx == selectedIdx, matchSet != nil && matchSet[item.idx])
		}
		style := styleForFrame(item.idx, item.frame, selectedPath, subtreeSet, matchSet, selectedIdx, isDark)
		b.WriteString(style.Render(label))
		cursor = span.end
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

func styleForFrame(idx int, frame tuiFrame, selectedPath string, subtreeSet, matchSet map[int]bool, selectedIdx int, isDark bool) lipgloss.Style {
	theme := common.Current()
	base := lipgloss.NewStyle().
		Foreground(theme.Background).
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
			return base.BorderLeft(true).BorderForeground(theme.Accent)
		}
		return base
	}

	return base.Background(theme.Panel).Foreground(theme.Muted).Faint(true)
}

// frameLabel renders name into exactly width cells via padOrTrim, adding the
// ">…<" selection or "*" match marker. Like padOrTrim it expects name to be
// free of control characters (sanitised upstream, task io2).
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

// compactFramePath renders a raw frame Path for the toolbar and status line:
// at most the first and last component joined by "/...". Path holds raw
// traced names (it is a lookup key), so the display text is sanitised here.
func compactFramePath(path string) string {
	if path == "" {
		return "root"
	}
	parts := strings.Split(path, pathSeparator)
	if len(parts) <= 3 {
		return common.Sanitize(strings.Join(parts, "/"))
	}
	return common.Sanitize(strings.Join([]string{parts[0], "...", parts[len(parts)-1]}, "/"))
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

// maxFrameRowForSet returns the deepest row among the frames admitted by
// include; a nil include admits every frame.
func maxFrameRowForSet(frames []tuiFrame, include frameFilter) int {
	maxRow := 0
	for idx, frame := range frames {
		if !include.admits(idx) {
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

// padOrTrim fits s into exactly width terminal cells via the shared
// common.FitRight. It measures and cuts by display width, not rune count: a
// CJK or emoji rune takes two cells, so counting runes let a wide-character
// frame name overflow its cell and push the whole row past the viewport. When
// s is too wide it is cut and ends in "…" (a 1-cell width hard-cuts to the
// first cell, or shows "…" when that cell would be half of a wide rune); a
// wide rune is never split, so the cut can be one cell short and is then
// space-padded to width.
//
// The exact-width guarantee holds only for control-character-free input:
// tabs, C1 bytes or an unterminated escape sequence are measured as zero
// width but move the cursor (tab) or swallow the following bytes, including
// padding (unterminated escape). padOrTrim does not sanitise; frame names and
// paths are sanitised upstream (task io2).
func padOrTrim(s string, width int) string {
	return common.FitRight(s, width, common.Ellipsis)
}
