package dashboard

import (
	"fmt"
	"ior/internal/flags"
	"ior/internal/statsengine"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/table"
)

func renderProcesses(snap *statsengine.Snapshot, width, height int) string {
	return renderProcessesWithOffset(snap, width, height, 0)
}

func renderProcessesWithOffset(snap *statsengine.Snapshot, width, height, offset int) string {
	if snap == nil {
		return "Processes: waiting for stats..."
	}

	rows := processRows(snap.Processes())
	if len(rows) == 0 {
		return "Processes: no data"
	}

	columns := []table.Column{
		{Title: "PID", Width: 8},
		{Title: "Comm", Width: 18},
		{Title: "Syscalls", Width: 10},
		{Title: "Rate/s", Width: 8},
		{Title: "Total Bytes", Width: 12},
		{Title: "Avg Latency", Width: 12},
	}

	tbl := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)
	tbl.SetHeight(syscallTableHeight(height))
	tbl.SetWidth(tableWidth(width))
	tbl.SetCursor(clampOffset(offset, len(rows)))

	out := tbl.View()
	if flags.Get().PidFilter > 0 {
		out += "\n" + "Note: this tab is most useful with All PIDs."
	}
	return out
}

func processRows(processes []statsengine.ProcessSnapshot) []table.Row {
	rows := make([]table.Row, 0, len(processes))
	for _, p := range processes {
		rows = append(rows, table.Row{
			strconv.FormatUint(uint64(p.PID), 10),
			truncateText(p.Comm, 18),
			strconv.FormatUint(p.Syscalls, 10),
			fmt.Sprintf("%.1f", p.RatePerSec),
			formatBytes(float64(p.Bytes)),
			formatDurationNs(p.AvgLatencyNs),
		})
	}
	return rows
}

func truncateText(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit <= 3 {
		return value[:limit]
	}
	return strings.TrimSpace(value[:limit-3]) + "..."
}
