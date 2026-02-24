package dashboard

import (
	"fmt"
	"ior/internal/statsengine"
	"ior/internal/tui"
	"strings"
	"time"
)

func renderOverview(snap *statsengine.Snapshot, width, height int) string {
	_ = height
	if snap == nil {
		return tui.PanelStyle.Render("Overview: waiting for stats...")
	}

	boxWidth := summaryBoxWidth(width)
	box1 := renderSyscallBox(snap, boxWidth)
	box2 := renderBytesBox(snap, boxWidth)
	box3 := renderErrorBox(snap, boxWidth)

	row := strings.Join([]string{box1, box2, box3}, "\n")
	trends := fmt.Sprintf(
		"Trends: latency %s  gap %s  throughput %s",
		trendWithArrow(snap.LatencyTrend),
		trendWithArrow(snap.GapTrend),
		trendWithArrow(snap.ThroughputTrend),
	)

	latencySpark := "Latency: " + renderSparkline(snap.LatencySeriesNs(), sparklineWidth(width))
	throughputSpark := "Throughput: " + renderSparkline(snap.ThroughputSeriesB(), sparklineWidth(width))
	topSyscalls := "Top syscalls: " + summarizeTopSyscalls(snap)

	return strings.Join(
		[]string{
			row,
			tui.HighlightStyle.Render(trends),
			tui.PanelStyle.Render(latencySpark),
			tui.PanelStyle.Render(throughputSpark),
			tui.PanelStyle.Render(topSyscalls),
		},
		"\n",
	)
}

func renderSyscallBox(snap *statsengine.Snapshot, width int) string {
	content := fmt.Sprintf(
		"Elapsed: %s\nSyscalls: %d\nRate: %.1f/s",
		formatElapsed(snap.Elapsed),
		snap.TotalSyscalls,
		snap.SyscallRatePerSec,
	)
	return tui.PanelStyle.Width(width).Render(content)
}

func renderBytesBox(snap *statsengine.Snapshot, width int) string {
	content := fmt.Sprintf(
		"Read/s: %s\nWrite/s: %s\nTotal: %s",
		formatBytes(snap.ReadBytesPerSec),
		formatBytes(snap.WriteBytesPerSec),
		formatBytes(float64(snap.TotalBytes)),
	)
	return tui.PanelStyle.Width(width).Render(content)
}

func renderErrorBox(snap *statsengine.Snapshot, width int) string {
	errPercent := 0.0
	if snap.TotalSyscalls > 0 {
		errPercent = float64(snap.TotalErrors) / float64(snap.TotalSyscalls) * 100
	}
	content := fmt.Sprintf(
		"Errors: %d\nError rate: %.2f%%\nLatency mean: %.0fns",
		snap.TotalErrors,
		errPercent,
		snap.LatencyMeanNs,
	)
	return tui.PanelStyle.Width(width).Render(content)
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
	syscalls := snap.Syscalls()
	if len(syscalls) == 0 {
		return "none"
	}

	limit := 3
	if len(syscalls) < limit {
		limit = len(syscalls)
	}

	parts := make([]string, 0, limit)
	for _, syscall := range syscalls[:limit] {
		parts = append(parts, fmt.Sprintf("%s(%d)", syscall.Name, syscall.Count))
	}
	return strings.Join(parts, ", ")
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
	w := (width - 4) / 3
	if w < 18 {
		return 18
	}
	return w
}

func sparklineWidth(width int) int {
	if width <= 0 {
		return 20
	}
	w := width - 14
	if w < 8 {
		return 8
	}
	if w > 80 {
		return 80
	}
	return w
}
