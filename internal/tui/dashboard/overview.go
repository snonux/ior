package dashboard

import (
	"fmt"
	"strings"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

// renderOverview renders the Overview tab: a row of summary boxes, the trend
// line, and three full-width panels (sparklines, top-N lists, histogram
// summaries). height is currently unused; the layout grows with content.
// The theme is loaded once and passed to the helpers so the whole tab is
// rendered from one consistent palette snapshot.
func renderOverview(snap *statsengine.Snapshot, width, height int) string {
	theme := common.Current()
	_ = height
	if snap == nil {
		return theme.PanelStyle.Render("Overview: waiting for stats...")
	}
	if width <= 0 {
		width = 80
	}

	boxWidth := summaryBoxWidth(width)
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		renderSyscallBox(snap, boxWidth),
		renderBytesBox(snap, boxWidth),
		renderErrorBox(snap, boxWidth),
	)
	panel := theme.PanelStyle.Width(panelWidth(width))
	return strings.Join(
		[]string{
			row,
			theme.HighlightStyle.Render(overviewTrendsLine(snap)),
			panel.Render(overviewSparklineLines(snap, panelInnerWidth(width))),
			panel.Render(overviewTopLines(snap)),
			panel.Render(overviewHistogramLines(snap)),
		},
		"\n",
	)
}

// overviewTrendsLine summarises the latency/gap/throughput trend arrows.
func overviewTrendsLine(snap *statsengine.Snapshot) string {
	return fmt.Sprintf(
		"Trends: latency %s  gap %s  throughput %s",
		trendWithArrow(snap.LatencyTrend),
		trendWithArrow(snap.GapTrend),
		trendWithArrow(snap.ThroughputTrend),
	)
}

// overviewSparklineLines renders the three sparklines with their labels padded
// to a common width so the graphs start in the same column.
func overviewSparklineLines(snap *statsengine.Snapshot, panelInner int) string {
	labelWidth := maxLabelWidth("Latency:", "Gap:", "Throughput:")
	return strings.Join([]string{
		renderOverviewSparklineAligned("Latency:", snap.LatencySeriesNs(), panelInner, labelWidth),
		renderOverviewSparklineAligned("Gap:", snap.GapSeriesNs(), panelInner, labelWidth),
		renderOverviewSparklineAligned("Throughput:", snap.ThroughputSeriesB(), panelInner, labelWidth),
	}, "\n")
}

// overviewTopLines lists the top syscalls, files and processes.
func overviewTopLines(snap *statsengine.Snapshot) string {
	return strings.Join([]string{
		"Top syscalls: " + summarizeTopSyscalls(snap),
		"Top files: " + summarizeTopFiles(snap),
		"Top processes: " + summarizeTopProcesses(snap),
	}, "\n")
}

// overviewHistogramLines gives the brief latency and gap bucket summaries.
func overviewHistogramLines(snap *statsengine.Snapshot) string {
	return strings.Join([]string{
		"Latency buckets: " + summarizeHistogramBrief(snap.LatencyHistogram),
		"Gap buckets: " + summarizeHistogramBrief(snap.GapHistogram),
	}, "\n")
}

func renderSyscallBox(snap *statsengine.Snapshot, width int) string {
	generatedAt := "n/a"
	if !snap.GeneratedAt.IsZero() {
		generatedAt = snap.GeneratedAt.Format("15:04:05")
	}
	content := fmt.Sprintf(
		"Elapsed: %s\nSyscalls: %d\nRate: %.1f/s\nSnapshot: %s",
		formatElapsed(snap.Elapsed),
		snap.TotalSyscalls,
		snap.SyscallRatePerSec,
		generatedAt,
	)
	return common.Current().PanelStyle.Width(width).Height(5).Render(content)
}

func renderBytesBox(snap *statsengine.Snapshot, width int) string {
	content := fmt.Sprintf(
		"Read/s: %s\nWrite/s: %s\nTotal: %s",
		formatBytes(snap.ReadBytesPerSec),
		formatBytes(snap.WriteBytesPerSec),
		formatBytes(float64(snap.TotalBytes)),
	)
	return common.Current().PanelStyle.Width(width).Height(5).Render(content)
}

func renderErrorBox(snap *statsengine.Snapshot, width int) string {
	errPercent := 0.0
	if snap.TotalSyscalls > 0 {
		errPercent = float64(snap.TotalErrors) / float64(snap.TotalSyscalls) * 100
	}
	// The gap mean is between consecutive traced calls on a thread; under
	// sampling or for aggregate-only syscalls it spans untraced calls, so
	// the label says "traced" rather than suggesting a per-call gap. It is kept
	// short so it fits the box at 80 columns without wrapping.
	content := fmt.Sprintf(
		"Errors: %d\nError rate: %.2f%%\nError/s: %.2f\nLatency mean: %.0fns\nTraced gap: %.0fns",
		snap.TotalErrors,
		errPercent,
		snap.ErrorRatePerSec,
		snap.LatencyMeanNs,
		snap.GapMeanNs,
	)
	return common.Current().PanelStyle.Width(width).Height(5).Render(content)
}

func trendWithArrow(trend statsengine.Trend) string {
	switch trend.Direction {
	case statsengine.TrendRising:
		return fmt.Sprintf("↑ %.1f%%", trend.DeltaPercent)
	case statsengine.TrendFalling:
		return fmt.Sprintf("↓ %.1f%%", trend.DeltaPercent)
	default:
		return fmt.Sprintf("→ %.1f%%", trend.DeltaPercent)
	}
}

func summarizeTopSyscalls(snap *statsengine.Snapshot) string {
	syscalls := snap.TopNSyscalls(3)
	if len(syscalls) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(syscalls))
	for _, syscall := range syscalls {
		parts = append(parts, fmt.Sprintf("%s(%d)", syscall.Name, syscall.Count))
	}
	return strings.Join(parts, ", ")
}

func summarizeTopFiles(snap *statsengine.Snapshot) string {
	files := snap.TopNFiles(3)
	if len(files) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(files))
	for _, f := range files {
		parts = append(parts, fmt.Sprintf("%s(%d)", trimPathTail(f.Path, 24), f.Accesses))
	}
	return strings.Join(parts, ", ")
}

func summarizeTopProcesses(snap *statsengine.Snapshot) string {
	processes := snap.TopNProcesses(3)
	if len(processes) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(processes))
	for _, p := range processes {
		parts = append(parts, fmt.Sprintf("%s/%s(%d)", common.Sanitize(p.Comm), p.ID(), p.Syscalls))
	}
	return strings.Join(parts, ", ")
}

func summarizeHistogramBrief(hist statsengine.HistogramSnapshot) string {
	buckets := hist.Buckets()
	if len(buckets) == 0 || hist.Total == 0 {
		return "none"
	}

	parts := make([]string, 0, 3)
	for _, b := range buckets {
		if b.Count == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", b.Label, b.Count))
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// trimPathTail sanitises the traced path (common.Sanitize) and shortens it to
// at most max display cells, keeping its end (the file name) behind a "..."
// prefix. It delegates to common.TruncateLeft,
// which cuts on grapheme boundaries so multi-byte paths stay valid UTF-8.
func trimPathTail(path string, max int) string {
	return common.TruncateLeft(common.Sanitize(path), max, common.ASCIIEllipsis)
}

func formatElapsed(elapsed time.Duration) string {
	if elapsed <= 0 {
		return "0s"
	}
	return elapsed.Round(time.Second).String()
}

func formatBytes(value float64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	unit := 0
	for value >= 1024 && unit < len(units)-1 {
		value /= 1024
		unit++
	}
	if unit == 0 {
		return fmt.Sprintf("%.0f%s", value, units[unit])
	}
	return fmt.Sprintf("%.1f%s", value, units[unit])
}

func summaryBoxWidth(width int) int {
	if width <= 0 {
		return 24
	}
	w := width / 3
	if w < 18 {
		return 18
	}
	return w
}

func renderOverviewSparkline(label string, data []float64, panelInner int) string {
	w := panelInner - common.DisplayWidth(label) - 1 - sparklineSafetyMargin
	if w < 8 {
		w = 8
	}
	return renderLabeledSparkline(label, data, w)
}

func renderOverviewSparklineAligned(label string, data []float64, panelInner int, labelWidth int) string {
	paddedLabel := padLabelRight(label, labelWidth)
	w := panelInner - labelWidth - 1 - sparklineSafetyMargin
	if w < 8 {
		w = 8
	}
	return renderLabeledSparkline(paddedLabel, data, w)
}

// maxLabelWidth returns the widest label in terminal display cells (not
// runes), so a wide CJK/emoji label still lines the sparklines up.
func maxLabelWidth(labels ...string) int {
	max := 0
	for _, label := range labels {
		w := common.DisplayWidth(label)
		if w > max {
			max = w
		}
	}
	return max
}

// padLabelRight right-pads label with spaces to width display cells; a label
// already that wide is returned unchanged.
func padLabelRight(label string, width int) string {
	return common.PadRight(label, width)
}

func panelWidth(width int) int {
	if width <= 0 {
		width = 80
	}
	if width < 20 {
		return 20
	}
	return width
}

func panelInnerWidth(width int) int {
	inner := panelWidth(width) - panelHorizontalChrome
	if inner < 16 {
		return 16
	}
	return inner
}
