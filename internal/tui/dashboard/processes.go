package dashboard

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

func renderProcesses(snap *statsengine.Snapshot, width, height int) string {
	return renderProcessesWithOffset(snap, width, height, 0, 0, -1)
}

func renderProcessesWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol, pidFilter int) string {
	if snap == nil {
		return "Processes: waiting for stats..."
	}

	rows := processRows(snap.Processes())
	if len(rows) == 0 {
		return "Processes: no data"
	}

	columns := processColumns()
	out := renderSelectableTable(columns, rows, height, offset, selectedCol, "enter:filter", "v:mode", "b:metric")
	if pidFilter > 0 {
		out += "\n" + "Note: this tab is most useful with All PIDs."
	}
	return out
}

func processColumns() []common.TableColumn {
	return []common.TableColumn{
		{Title: "PID", Width: 8},
		{Title: "Comm", Width: 18},
		{Title: "Syscalls", Width: 10},
		{Title: "Rate/s", Width: 8},
		{Title: "Total Bytes", Width: 12},
		{Title: "Avg Latency", Width: 12},
	}
}

func processRows(processes []statsengine.ProcessSnapshot) [][]string {
	rows := make([][]string, 0, len(processes))
	for _, p := range processes {
		rows = append(rows, []string{
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
