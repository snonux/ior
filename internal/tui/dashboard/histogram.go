package dashboard

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

// Histogram panel geometry. A panel is drawn in one of two layouts, chosen
// per width by planHistogramLayout so that no line is ever wider than the
// panel (a wider line soft-wraps into rows the height budget has not counted,
// the panel gets cut mid-row and its counts no longer add up to total=):
//
//   - full:    "label | bar count" rows under the title, with the scale legend
//     as the last content line;
//   - compact: "label | count" rows, no bar column and so no legend, once the
//     bar column cannot get histogramMinBarWidth cells.
//
// Below the compact layout's width the panel is replaced by a one-line
// "terminal too narrow" notice panel (renderHistogramTooNarrow).
const (
	// histogramChromeRows is what a full panel spends besides bucket rows:
	// the top and bottom border, the title line and the scale legend. It is
	// the larger of the two layouts' chrome, so it is what the tab minimum
	// (latencyMinRows) is built on.
	histogramChromeRows = 4
	// histogramCompactChromeRows is the compact panel's chrome: borders and
	// title only, as it has no bars to explain with a legend.
	histogramCompactChromeRows = 3
	// histogramColumnSeparator sits between the label and the bar (or count).
	histogramColumnSeparator = " | "
	// histogramRowSeparators is the cells a full row spends besides label,
	// bar and count: the column separator and the space before the count.
	histogramRowSeparators = len(histogramColumnSeparator) + 1
	// histogramMinBarWidth is the narrowest bar column worth drawing; below it
	// the compact layout drops the column.
	histogramMinBarWidth = 4
	// histogramDefaultBarWidth and histogramBarSlack keep the long-standing
	// look on normal terminals: a row leaves histogramBarSlack cells free at
	// its end while the bar still gets histogramDefaultBarWidth cells; on
	// narrower panels the slack goes before the bar shrinks.
	histogramDefaultBarWidth = 8
	histogramBarSlack        = 2
	// histogramScaleLegend is the full layout's last content line.
	histogramScaleLegend = "Scale: █▓▒░"
)

// histogramSpec names one histogram section of the Latency+Gaps tab.
type histogramSpec struct {
	// title is the panel title, followed by " (total=N)".
	title string
	// shortTitle replaces title when the full title line does not fit, and
	// prefixes the "terminal too narrow" and "waiting for stats" notices.
	shortTitle string
	// sparkLabel labels the sparkline panel under the histogram.
	sparkLabel string
}

var (
	latencyHistogramSpec = histogramSpec{title: "Latency Histogram", shortTitle: "Latency", sparkLabel: "Latency sparkline:"}
	gapHistogramSpec     = histogramSpec{title: "Gap Histogram", shortTitle: "Gaps", sparkLabel: "Gap sparkline:"}
)

// renderLatencyTab renders the latency histogram panel over its sparkline
// panel within width columns and height rows (<= 0 means unbounded).
func renderLatencyTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.RenderMessagePanel(latencyHistogramSpec.shortTitle+": waiting for stats...", width)
	}
	return renderHistogramSection(snap.LatencyHistogram, latencyHistogramSpec, snap.LatencySeriesNs(), width, height)
}

// renderGapsTab is renderLatencyTab for the gap histogram.
func renderGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.RenderMessagePanel(gapHistogramSpec.shortTitle+": waiting for stats...", width)
	}
	return renderHistogramSection(snap.GapHistogram, gapHistogramSpec, snap.GapSeriesNs(), width, height)
}

// sparklineRows is the fixed height of the sparkline panel under a histogram
// (border, one sparkline line, border).
const sparklineRows = 3

// renderHistogramSection stacks a histogram panel over a one-line sparkline
// panel and fits both into width columns and height rows (<= 0 means
// unbounded; width <= 0 is 80 columns). The buckets are the subject, and the
// slowest ones are the point of a latency tool, so they are never silently
// cut: the sparkline is kept only while every bucket still fits beside it;
// otherwise it goes first and only then are buckets folded into one tail row
// (foldHistogramBuckets), whose count keeps the displayed counts adding up to
// the histogram total. The sparkline is also left out when its line would be
// wider than the panel. A panel too narrow for even the compact layout is the
// "terminal too narrow" notice alone.
func renderHistogramSection(hist statsengine.HistogramSnapshot, spec histogramSpec, series []float64, width, height int) string {
	if width <= 0 {
		width = 80
	}
	n := len(hist.Buckets())
	layout, fits := planHistogramLayout(hist, spec, width)
	if n > 0 && !fits {
		return fitBlocks([]string{renderHistogramTooNarrow(hist, spec, width)}, height)
	}
	spark, sparkFits := renderHistogramSparkline(spec.sparkLabel, series, width)
	if height <= 0 || n == 0 {
		// Unbounded, or the fixed-size "no data" panel: fitBlocks drops the
		// sparkline if it does not fit.
		blocks := []string{renderHistogram(hist, spec, width, 0)}
		if sparkFits {
			blocks = append(blocks, spark)
		}
		return fitBlocks(blocks, height)
	}
	if withSpark := height - sparklineRows; sparkFits && withSpark >= n+layout.chromeRows() {
		return fitBlocks([]string{renderHistogram(hist, spec, width, withSpark), spark}, height)
	}
	// The sparkline would cost buckets (or does not fit the width): it goes,
	// so the histogram keeps as many individual buckets as possible and
	// folds only the remainder.
	return fitBlocks([]string{renderHistogram(hist, spec, width, height)}, height)
}

// renderHistogramSparkline renders the sparkline panel under a histogram,
// exactly width columns wide (not panelWidth, which widens a sub-20-column
// panel to 20). ok is false when the labelled sparkline line would be wider
// than the panel's inner width (renderOverviewSparkline keeps at least 8
// sparkline cells beside the label, so below ~34 columns it does not fit):
// lipgloss would wrap it onto further rows, so the caller leaves the
// sparkline out instead.
func renderHistogramSparkline(label string, series []float64, width int) (panel string, ok bool) {
	inner := width - panelHorizontalChrome
	if inner <= 0 {
		return "", false
	}
	line := renderOverviewSparkline(label, series, inner)
	if common.DisplayWidth(line) > inner {
		return "", false
	}
	return common.Current().PanelStyle.Width(width).Render(line), true
}

// renderLatencyGapsTab renders the latency section over the gap section. The
// height is split between them (the latency section takes the odd row). When
// half of it cannot hold even a one-bucket histogram, two clipped slivers
// would show nothing useful, so the latency section gets the whole height and
// the gap section is left out.
func renderLatencyGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.RenderMessagePanel("Latency+Gaps: waiting for stats...", width)
	}
	if height <= 0 {
		return renderLatencyTab(snap, width, 0) + "\n" + renderGapsTab(snap, width, 0)
	}
	latHeight, gapHeight := (height+1)/2, height/2
	if gapHeight < histogramChromeRows+1 {
		return renderLatencyTab(snap, width, height)
	}
	return fitBlocks([]string{
		renderLatencyTab(snap, width, latHeight),
		renderGapsTab(snap, width, gapHeight),
	}, height)
}

// renderHistogram renders a histogram snapshot as a bar chart panel exactly
// width columns wide (<= 0 means 80). height is the panel's total rows
// including borders, title and scale legend (<= 0 means unbounded); buckets
// beyond what fits are folded into one tail row (foldHistogramBuckets), never
// cut. The "no data" panel is a fixed three rows, and a width too narrow for
// the compact layout yields the "terminal too narrow" notice panel instead.
func renderHistogram(hist statsengine.HistogramSnapshot, spec histogramSpec, width, height int) string {
	buckets := hist.Buckets()
	if len(buckets) == 0 {
		return common.RenderMessagePanel(spec.title+": no data", width)
	}
	if width <= 0 {
		width = 80
	}
	layout, fits := planHistogramLayout(hist, spec, width)
	if !fits {
		return renderHistogramTooNarrow(hist, spec, width)
	}
	buckets = foldHistogramBuckets(buckets, histogramBucketRows(height, layout.chromeRows()))
	lines := make([]string, 0, len(buckets)+2)
	lines = append(lines, layout.title)
	lines = append(lines, histogramBucketLines(hist, buckets, layout, width-panelHorizontalChrome)...)
	if !layout.compact {
		lines = append(lines, histogramScaleLegend)
	}
	return common.Current().PanelStyle.Width(width).Render(strings.Join(lines, "\n"))
}

// histogramBucketLines renders one row per (folded) bucket into inner cells:
// "label | bar count" in the full layout, "label | count" in the compact
// one. The columns are sized from the buckets actually shown, which are never
// wider than what planHistogramLayout measured, so the bar keeps at least
// histogramMinBarWidth cells.
func histogramBucketLines(hist statsengine.HistogramSnapshot, buckets []statsengine.HistogramBucketSnapshot, layout histogramLayout, inner int) []string {
	maxCount, labelWidth, countWidth := histogramMetrics(hist, buckets)
	room := inner - labelWidth - countWidth - histogramRowSeparators
	barWidth := max(room-histogramBarSlack, min(room, histogramDefaultBarWidth))
	lines := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		label := common.PadRight(bucket.Label, labelWidth) + histogramColumnSeparator
		if layout.compact {
			lines = append(lines, fmt.Sprintf("%s%*d", label, countWidth, bucket.Count))
			continue
		}
		bar := common.PadRight(renderHistogramBar(bucket.Count, maxCount, barWidth), barWidth)
		lines = append(lines, fmt.Sprintf("%s%s %*d", label, bar, countWidth, bucket.Count))
	}
	return lines
}

// histogramLayout is how a histogram panel is drawn at one width.
type histogramLayout struct {
	// title is the title line: the full or the short title with its total.
	title string
	// compact drops the bar column and the scale legend.
	compact bool
}

// chromeRows is the rows the layout spends besides bucket rows.
func (l histogramLayout) chromeRows() int {
	if l.compact {
		return histogramCompactChromeRows
	}
	return histogramChromeRows
}

// planHistogramLayout picks the layout of hist's panel at width columns: the
// full one while a bar column of histogramMinBarWidth cells fits, else the
// compact one. ok is false when even the compact rows or the short title line
// are wider than the panel's inner width. The columns are measured over every
// bucket and every label folding could produce (histogramColumnWidths), not
// over the rows a given height shows, so the choice does not change with the
// height and every row a fold can produce fits.
func planHistogramLayout(hist statsengine.HistogramSnapshot, spec histogramSpec, width int) (layout histogramLayout, ok bool) {
	inner := width - panelHorizontalChrome
	title, ok := fitHistogramTitle(spec, hist.Total, inner)
	if !ok {
		return histogramLayout{}, false
	}
	labelWidth, countWidth := histogramColumnWidths(hist)
	compactRow := labelWidth + len(histogramColumnSeparator) + countWidth
	switch {
	case inner-labelWidth-countWidth-histogramRowSeparators >= histogramMinBarWidth &&
		common.DisplayWidth(histogramScaleLegend) <= inner:
		return histogramLayout{title: title}, true
	case compactRow <= inner:
		return histogramLayout{title: title, compact: true}, true
	}
	return histogramLayout{}, false
}

// fitHistogramTitle returns the title line "<title> (total=N)" if it fits
// into inner cells, else the same line with the short title. ok is false
// when neither fits: the total must stay readable, since it is what the
// displayed bucket counts add up to.
func fitHistogramTitle(spec histogramSpec, total uint64, inner int) (line string, ok bool) {
	for _, title := range []string{spec.title, spec.shortTitle} {
		line = fmt.Sprintf("%s (total=%d)", title, total)
		if common.DisplayWidth(line) <= inner {
			return line, true
		}
	}
	return "", false
}

// histogramColumnWidths is the widest label and count any panel of hist can
// show: the labels as they are and as foldedBucketLabel would rewrite them
// ("[0,1us)" becomes the wider "[0,+inf)"), and the digits of the total or of
// the sum of all bucket counts (a folded row holds a sum, and a torn snapshot
// may count a little ahead of its total), whichever is larger.
func histogramColumnWidths(hist statsengine.HistogramSnapshot) (labelWidth, countWidth int) {
	sum := uint64(0)
	for _, bucket := range hist.Buckets() {
		labelWidth = max(labelWidth, common.DisplayWidth(bucket.Label),
			common.DisplayWidth(foldedBucketLabel(bucket.Label)))
		sum += bucket.Count
	}
	return labelWidth, len(strconv.FormatUint(max(sum, hist.Total), 10))
}

// histogramMinWidth is the narrowest terminal hist's panel fits: the panel
// chrome around the wider of the short title line and a compact row. It is
// the number the "terminal too narrow" notice asks for.
func histogramMinWidth(hist statsengine.HistogramSnapshot, spec histogramSpec) int {
	labelWidth, countWidth := histogramColumnWidths(hist)
	title := common.DisplayWidth(fmt.Sprintf("%s (total=%d)", spec.shortTitle, hist.Total))
	return panelHorizontalChrome + max(title, labelWidth+len(histogramColumnSeparator)+countWidth)
}

// renderHistogramTooNarrow is the notice panel shown instead of a histogram
// that cannot fit width columns, worded like the Flame tab's
// ("Flame: terminal too narrow (need >= 60 columns)") and cut to the width
// itself (common.RenderMessagePanel), so it never soft-wraps either.
func renderHistogramTooNarrow(hist statsengine.HistogramSnapshot, spec histogramSpec, width int) string {
	msg := fmt.Sprintf("%s: terminal too narrow (need >= %d columns)", spec.shortTitle, histogramMinWidth(hist, spec))
	return common.RenderMessagePanel(msg, width)
}

// foldHistogramBuckets fits the buckets into maxRows rows without losing any
// count. It first drops empty buckets from both ends (they carry no
// information, only when space is short), then, if still too many, keeps the
// fastest maxRows-1 buckets and folds the rest into a single "[lower,+inf)" row
// holding their summed count. The slow tail is therefore always represented
// and the displayed counts always add up to the total. maxRows <= 0 means
// unbounded; at least one row (possibly the folded one) is always produced.
func foldHistogramBuckets(buckets []statsengine.HistogramBucketSnapshot, maxRows int) []statsengine.HistogramBucketSnapshot {
	if maxRows <= 0 || len(buckets) <= maxRows {
		return buckets
	}
	for len(buckets) > maxRows && buckets[0].Count == 0 {
		buckets = buckets[1:]
	}
	for len(buckets) > maxRows && buckets[len(buckets)-1].Count == 0 {
		buckets = buckets[:len(buckets)-1]
	}
	if len(buckets) <= maxRows {
		return buckets
	}
	heads := max(maxRows-1, 0)
	folded := statsengine.HistogramBucketSnapshot{
		Label:   foldedBucketLabel(buckets[heads].Label),
		LowerNs: buckets[heads].LowerNs,
		UpperNs: buckets[len(buckets)-1].UpperNs,
	}
	for _, b := range buckets[heads:] {
		folded.Count += b.Count
	}
	return append(slices.Clone(buckets[:heads]), folded)
}

// foldedBucketLabel turns the label of the first folded bucket ("[1ms,10ms)")
// into the open-ended label of the whole tail ("[1ms,+inf)"). A label without
// the bracket/comma shape is kept as is rather than guessed at.
func foldedBucketLabel(first string) string {
	if !strings.HasPrefix(first, "[") {
		return first
	}
	lower, _, ok := strings.Cut(first, ",")
	if !ok {
		return first
	}
	return lower + ",+inf)"
}

// histogramBucketRows is the number of bucket rows left in a panel of height
// rows once its chrome rows are spent, at least one (a panel shorter than its
// chrome overflows and the caller clips it). height <= 0 means unbounded (0).
func histogramBucketRows(height, chrome int) int {
	if height <= 0 {
		return 0
	}
	return max(height-chrome, 1)
}

// histogramMetrics computes the maximum count, the widest label in display
// cells and the widest count in digits (at least the total's) of the buckets
// shown, to align the histogram columns.
func histogramMetrics(hist statsengine.HistogramSnapshot, buckets []statsengine.HistogramBucketSnapshot) (maxCount uint64, labelWidth, countWidth int) {
	countWidth = len(strconv.FormatUint(hist.Total, 10))
	for _, bucket := range buckets {
		maxCount = max(maxCount, bucket.Count)
		labelWidth = max(labelWidth, common.DisplayWidth(bucket.Label))
		countWidth = max(countWidth, len(strconv.FormatUint(bucket.Count, 10)))
	}
	return maxCount, labelWidth, countWidth
}

// renderHistogramBar draws count's bar, at most width cells, scaled to
// maxCount; its shade encodes the ratio (see histogramScaleLegend).
func renderHistogramBar(count, maxCount uint64, width int) string {
	if count == 0 || maxCount == 0 || width <= 0 {
		return ""
	}

	ratio := float64(count) / float64(maxCount)
	length := int(math.Round(ratio * float64(width)))
	if length < 1 {
		length = 1
	}
	if length > width {
		length = width
	}

	char := '░'
	switch {
	case ratio >= 0.75:
		char = '█'
	case ratio >= 0.5:
		char = '▓'
	case ratio >= 0.25:
		char = '▒'
	}

	return strings.Repeat(string(char), length)
}
