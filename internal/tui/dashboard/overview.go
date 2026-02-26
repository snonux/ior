package dashboard

import (
	"fmt"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
)

func renderOverview(snap *statsengine.Snapshot, width, height int) string {
	_ = height
	if snap == nil {
		return common.PanelStyle.Render("Overview: waiting for stats...")
	}
	if width <= 0 {
		width = 80
	}

	boxWidth := summaryBoxWidth(width)
	box1 := renderSyscallBox(snap, boxWidth)
	box2 := renderBytesBox(snap, boxWidth)
	box3 := renderErrorBox(snap, boxWidth)

	row := lipgloss.JoinHorizontal(lipgloss.Top, box1, box2, box3)
	trends := fmt.Sprintf(
		"Trends: latency %s  gap %s  throughput %s",
		trendWithArrow(snap.LatencyTrend),
		trendWithArrow(snap.GapTrend),
		trendWithArrow(snap.ThroughputTrend),
	)

	panelInner := panelInnerWidth(width)
	latencySpark := renderOverviewSparkline("Latency:", snap.LatencySeriesNs(), panelInner)
	gapSpark := renderOverviewSparkline("Gap:", snap.GapSeriesNs(), panelInner)
	throughputSpark := renderOverviewSparkline("Throughput:", snap.ThroughputSeriesB(), panelInner)
	topSyscalls := "Top syscalls: " + summarizeTopSyscalls(snap)
	topFiles := "Top files: " + summarizeTopFiles(snap)
	topProcesses := "Top processes: " + summarizeTopProcesses(snap)
	latencyHist := "Latency buckets: " + summarizeHistogramBrief(snap.LatencyHistogram)
	gapHist := "Gap buckets: " + summarizeHistogramBrief(snap.GapHistogram)

	panel := common.PanelStyle.Width(panelInner)
	sparkPanel := panel.Render(strings.Join([]string{latencySpark, "", gapSpark, "", throughputSpark}, "\n"))
	topPanel := panel.Render(strings.Join([]string{topSyscalls, topFiles, topProcesses}, "\n"))
	histPanel := panel.Render(strings.Join([]string{latencyHist, gapHist}, "\n"))

	return strings.Join(
		[]string{
			row,
			common.HighlightStyle.Render(trends),
			sparkPanel,
			topPanel,
			histPanel,
		},
		"\n",
	)
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
	return common.PanelStyle.Width(summaryBoxInnerWidth(width)).Height(5).Render(content)
}

func renderBytesBox(snap *statsengine.Snapshot, width int) string {
	content := fmt.Sprintf(
		"Read/s: %s\nWrite/s: %s\nTotal: %s",
		formatBytes(snap.ReadBytesPerSec),
		formatBytes(snap.WriteBytesPerSec),
		formatBytes(float64(snap.TotalBytes)),
	)
	return common.PanelStyle.Width(summaryBoxInnerWidth(width)).Height(5).Render(content)
}

func renderErrorBox(snap *statsengine.Snapshot, width int) string {
	errPercent := 0.0
	if snap.TotalSyscalls > 0 {
		errPercent = float64(snap.TotalErrors) / float64(snap.TotalSyscalls) * 100
	}
	content := fmt.Sprintf(
		"Errors: %d\nError rate: %.2f%%\nError/s: %.2f\nLatency mean: %.0fns\nGap mean: %.0fns",
		snap.TotalErrors,
		errPercent,
		snap.ErrorRatePerSec,
		snap.LatencyMeanNs,
		snap.GapMeanNs,
	)
	return common.PanelStyle.Width(summaryBoxInnerWidth(width)).Height(5).Render(content)
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
		parts = append(parts, fmt.Sprintf("%s/%d(%d)", p.Comm, p.PID, p.Syscalls))
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

func trimPathTail(path string, max int) string {
	if len(path) <= max {
		return path
	}
	if max <= 3 {
		return path[len(path)-max:]
	}
	return "..." + path[len(path)-max+3:]
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

func summaryBoxInnerWidth(width int) int {
	inner := width - panelHorizontalChrome
	if inner < 14 {
		return 14
	}
	return inner
}

func renderOverviewSparkline(label string, data []float64, panelInner int) string {
	w := panelInner - utf8.RuneCountInString(label) - 1 - sparklineSafetyMargin
	if w < 8 {
		w = 8
	}
	return renderLabeledSparkline(label, data, w)
}

func panelInnerWidth(width int) int {
	if width <= 0 {
		width = 80
	}
	inner := width - panelHorizontalChrome
	if inner < 20 {
		return 20
	}
	return inner
}
