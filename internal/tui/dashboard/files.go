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

	pathWidth := filePathWidth(width)
	rows := fileRows(snap.Files(), pathWidth)
	if len(rows) == 0 {
		return "Files: no data"
	}

	columns := []table.Column{
		{Title: "Accesses", Width: 8},
		{Title: "Read", Width: 9},
		{Title: "Write", Width: 9},
		{Title: "Avg Latency", Width: 11},
		{Title: "Max Latency", Width: 11},
		{Title: "Path", Width: pathWidth},
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

func fileRows(files []statsengine.FileSnapshot, pathWidth int) []table.Row {
	rows := make([]table.Row, 0, len(files))
	for _, f := range files {
		rows = append(rows, table.Row{
			strconv.FormatUint(f.Accesses, 10),
			formatBytes(float64(f.BytesRead)),
			formatBytes(float64(f.BytesWritten)),
			formatDurationNs(f.AvgLatencyNs),
			formatDurationUintNs(f.MaxLatencyNs),
			truncatePathMiddle(f.Path, pathWidth),
		})
	}
	return rows
}

func filePathWidth(width int) int {
	if width <= 0 {
		return 24
	}
	// Keep fixed metrics visible and let path consume the remaining space.
	// Fixed columns sum to 48 chars; reserve extra for separators/padding.
	w := width - 58
	if w < 14 {
		return 14
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
