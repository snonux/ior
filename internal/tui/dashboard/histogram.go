package dashboard

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

func renderLatencyTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.PanelStyle.Render("Latency: waiting for stats...")
	}

	panelW := panelWidth(width)
	panelInner := panelInnerWidth(width)
	hist := renderHistogram(snap.LatencyHistogram, "Latency Histogram", width, height)
	spark := common.PanelStyle.Width(panelW).Render(
		renderOverviewSparkline("Latency sparkline:", snap.LatencySeriesNs(), panelInner),
	)
	return strings.Join([]string{hist, spark}, "\n")
}

func renderGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.PanelStyle.Render("Gaps: waiting for stats...")
	}

	panelW := panelWidth(width)
	panelInner := panelInnerWidth(width)
	hist := renderHistogram(snap.GapHistogram, "Gap Histogram", width, height)
	spark := common.PanelStyle.Width(panelW).Render(
		renderOverviewSparkline("Gap sparkline:", snap.GapSeriesNs(), panelInner),
	)
	return strings.Join([]string{hist, spark}, "\n")
}

func renderLatencyGapsTab(snap *statsengine.Snapshot, width, height int) string {
	if snap == nil {
		return common.PanelStyle.Render("Latency+Gaps: waiting for stats...")
	}
	lat := renderLatencyTab(snap, width, height)
	gap := renderGapsTab(snap, width, height)
	return strings.Join([]string{lat, gap}, "\n")
}

func renderHistogram(hist statsengine.HistogramSnapshot, title string, width, height int) string {
	buckets := hist.Buckets()
	if len(buckets) == 0 {
		return common.PanelStyle.Render(title + ": no data")
	}

	if width <= 0 {
		width = 80
	}
	panelW := panelWidth(width)
	panelInner := panelInnerWidth(width)

	if height > 0 {
		maxRows := height - 3
		if maxRows < 1 {
			maxRows = 1
		}
		if len(buckets) > maxRows {
			buckets = buckets[:maxRows]
		}
	}

	maxCount := uint64(0)
	labelWidth := 0
	countWidth := len(strconv.FormatUint(hist.Total, 10))
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

	return common.PanelStyle.Width(panelW).Render(strings.Join(lines, "\n"))
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
