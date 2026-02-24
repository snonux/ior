package dashboard

import (
	"fmt"
	"ior/internal/statsengine"
	"strconv"

	"github.com/charmbracelet/bubbles/table"
)

func renderFiles(snap *statsengine.Snapshot, width, height int) string {
	return renderFilesWithOffset(snap, width, height, 0)
}

func renderFilesWithOffset(snap *statsengine.Snapshot, width, height, offset int) string {
	if snap == nil {
		return "Files: waiting for stats..."
	}

	rows := fileRows(snap.Files())
	if len(rows) == 0 {
		return "Files: no data"
	}

	columns := []table.Column{
		{Title: "Path", Width: filePathWidth(width)},
		{Title: "Accesses", Width: 8},
		{Title: "Read", Width: 9},
		{Title: "Write", Width: 9},
		{Title: "Avg Latency", Width: 11},
		{Title: "Max Latency", Width: 11},
	}

	tbl := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
	)
	tbl.SetHeight(syscallTableHeight(height))
	tbl.SetWidth(tableWidth(width))
	cursor := clampOffset(offset, len(rows))
	tbl.SetCursor(cursor)
	return tbl.View() + fmt.Sprintf("\nRow %d/%d", cursor+1, len(rows))
}

func fileRows(files []statsengine.FileSnapshot) []table.Row {
	rows := make([]table.Row, 0, len(files))
	for _, f := range files {
		rows = append(rows, table.Row{
			truncatePathMiddle(f.Path, 48),
			strconv.FormatUint(f.Accesses, 10),
			formatBytes(float64(f.BytesRead)),
			formatBytes(float64(f.BytesWritten)),
			formatDurationNs(f.AvgLatencyNs),
			formatDurationUintNs(f.MaxLatencyNs),
		})
	}
	return rows
}

func filePathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	// Reserve enough room for non-path columns and table separators so
	// latency columns remain visible even on narrower terminals.
	w := width - 70
	if w < 14 {
		return 14
	}
	if w > 52 {
		return 52
	}
	return w
}

func truncatePathMiddle(path string, limit int) string {
	if len(path) <= limit {
		return path
	}
	if limit <= 3 {
		return path[:limit]
	}

	head := (limit - 3) / 2
	tail := limit - 3 - head
	if tail <= 0 {
		return path[:limit]
	}
	return path[:head] + "..." + path[len(path)-tail:]
}
