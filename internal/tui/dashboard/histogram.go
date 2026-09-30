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

// histogramChromeRows is what a histogram panel spends besides bucket rows:
// the top and bottom border, the title line and the scale legend.
const histogramChromeRows = 4

// renderLatencyTab renders the latency histogram panel over its sparkline
// panel within height rows (<= 0 means unbounded).
func renderLatencyTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.Current().PanelStyle.Render("Latency: waiting for stats...")
	}
	return renderHistogramSection(snap.LatencyHistogram, "Latency Histogram",
		"Latency sparkline:", snap.LatencySeriesNs(), width, height)
}

// renderGapsTab is renderLatencyTab for the gap histogram.
func renderGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.Current().PanelStyle.Render("Gaps: waiting for stats...")
	}
	return renderHistogramSection(snap.GapHistogram, "Gap Histogram",
		"Gap sparkline:", snap.GapSeriesNs(), width, height)
}

// sparklineRows is the fixed height of the sparkline panel under a histogram
// (border, one sparkline line, border).
const sparklineRows = 3

// renderHistogramSection stacks a histogram panel over a one-line sparkline
// panel and fits both into height rows (<= 0 means unbounded). The buckets are
// the subject, and the slowest ones are the point of a latency tool, so they
// are never silently cut: the sparkline is kept only while every bucket still
// fits beside it; otherwise it goes first and only then are buckets folded into one tail row (foldHistogramBuckets), whose
// count keeps the displayed counts adding up to the histogram total.
func renderHistogramSection(hist statsengine.HistogramSnapshot, title, sparkLabel string, series []float64, width, height int) string {
	spark := common.Current().PanelStyle.Width(panelWidth(width)).Render(
		renderOverviewSparkline(sparkLabel, series, panelInnerWidth(width)),
	)
	if height <= 0 {
		return renderHistogram(hist, title, width, 0) + "\n" + spark
	}
	n := len(hist.Buckets())
	if n == 0 {
		// The fixed-size "no data" panel; fitBlocks drops the sparkline if needed.
		return fitBlocks([]string{renderHistogram(hist, title, width, 0), spark}, height)
	}
	withSpark := height - sparklineRows
	if withSpark >= n+histogramChromeRows {
		return fitBlocks([]string{renderHistogram(hist, title, width, withSpark), spark}, height)
	}
	// The sparkline would cost buckets: it goes, so the histogram keeps as
	// many individual buckets as possible and folds only the remainder.
	return fitBlocks([]string{renderHistogram(hist, title, width, height)}, height)
}

// renderLatencyGapsTab renders the latency section over the gap section. The
// height is split between them (the latency section takes the odd row). When
// half of it cannot hold even a one-bucket histogram, two clipped slivers
// would show nothing useful, so the latency section gets the whole height and
// the gap section is left out.
func renderLatencyGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.Current().PanelStyle.Render("Latency+Gaps: waiting for stats...")
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

// renderHistogram renders a histogram snapshot as a bar chart panel. height
// is the panel's total rows including borders, title and scale legend
// (<= 0 means unbounded); buckets beyond what fits are folded into one tail
// row (foldHistogramBuckets), never cut. The "no data" panel is a fixed three rows.
func renderHistogram(hist statsengine.HistogramSnapshot, title string, width, height int) string {
	buckets := hist.Buckets()
	if len(buckets) == 0 {
		return common.Current().PanelStyle.Render(title + ": no data")
	}
	if width <= 0 {
		width = 80
	}
	panelW := panelWidth(width)
	panelInner := panelInnerWidth(width)

	buckets = foldHistogramBuckets(buckets, histogramBucketRows(height))
	maxCount, labelWidth, countWidth := histogramMetrics(hist, buckets)
	barWidth := panelInner - labelWidth - countWidth - 6
	if barWidth < 8 {
		barWidth = 8
	}

	lines := make([]string, 0, len(buckets)+2)
	lines = append(lines, fmt.Sprintf("%s (total=%d)", title, hist.Total))
	for _, bucket := range buckets {
		bar := renderHistogramBar(bucket.Count, maxCount, barWidth)
		lines = append(lines, fmt.Sprintf("%-*s | %-*s %*d", labelWidth, bucket.Label, barWidth, bar, countWidth, bucket.Count))
	}
	lines = append(lines, "Scale: █▓▒░")
	return common.Current().PanelStyle.Width(panelW).Render(strings.Join(lines, "\n"))
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
// rows once the chrome is spent, at least one (a panel shorter than its chrome
// overflows and the caller clips it). height <= 0 means unbounded (0).
func histogramBucketRows(height int) int {
	if height <= 0 {
		return 0
	}
	return max(height-histogramChromeRows, 1)
}

// histogramMetrics computes the maximum count, maximum label width, and maximum
// count-digit width needed to align the histogram columns.
func histogramMetrics(hist statsengine.HistogramSnapshot, buckets []statsengine.HistogramBucketSnapshot) (maxCount uint64, labelWidth, countWidth int) {
	countWidth = len(strconv.FormatUint(hist.Total, 10))
	for _, bucket := range buckets {
		if bucket.Count > maxCount {
			maxCount = bucket.Count
		}
		if len(bucket.Label) > labelWidth {
			labelWidth = len(bucket.Label)
		}
		if digits := len(strconv.FormatUint(bucket.Count, 10)); digits > countWidth {
			countWidth = digits
		}
	}
	return maxCount, labelWidth, countWidth
}

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
