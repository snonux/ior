package dashboard

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
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

// renderHistogramSection stacks a histogram panel over a one-line sparkline
// panel and fits both into height rows (<= 0 means unbounded). The sparkline
// panel keeps its fixed size and the histogram gets the remaining rows, so a
// short terminal shows fewer buckets rather than overflowing; when not even
// one bucket row fits beside the sparkline, the sparkline is dropped.
func renderHistogramSection(hist statsengine.HistogramSnapshot, title, sparkLabel string, series []float64, width, height int) string {
	spark := common.Current().PanelStyle.Width(panelWidth(width)).Render(
		renderOverviewSparkline(sparkLabel, series, panelInnerWidth(width)),
	)
	if height <= 0 {
		return renderHistogram(hist, title, width, 0) + "\n" + spark
	}
	sparkRows := lipgloss.Height(spark)
	blocks := []string{renderHistogram(hist, title, width, max(height-sparkRows, 1)), spark}
	if lipgloss.Height(blocks[0])+sparkRows > height {
		// Not even one bucket row fits beside the sparkline: the histogram
		// is the section's subject, so the sparkline is what goes.
		blocks = []string{renderHistogram(hist, title, width, height)}
	}
	return fitBlocks(blocks, height)
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
// (<= 0 means unbounded); buckets beyond what fits are cut, always keeping at
// least one. The "no data" panel is a fixed three rows.
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

	buckets = clampHistogramBuckets(buckets, height)
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

// clampHistogramBuckets trims the bucket slice to the rows left in a panel of
// height rows once histogramChromeRows are spent (at least one bucket is kept,
// so a panel shorter than its chrome overflows and the caller clips it).
func clampHistogramBuckets(buckets []statsengine.HistogramBucketSnapshot, height int) []statsengine.HistogramBucketSnapshot {
	if height <= 0 {
		return buckets
	}
	maxRows := height - histogramChromeRows
	if maxRows < 1 {
		maxRows = 1
	}
	if len(buckets) > maxRows {
		return buckets[:maxRows]
	}
	return buckets
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
