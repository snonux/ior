package dashboard

import (
	"fmt"
	"strconv"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

func renderNonIO(snap *statsengine.Snapshot, width, height int) string {
	return renderNonIOWithOffset(snap, width, height, 0, 0)
}

func renderNonIOWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	if snap == nil {
		return "Non-IO: waiting for stats..."
	}

	rowsData := snap.NonIOFamilies()
	columns, rows := nonIOTableData(rowsData, width)
	if len(rows) == 0 {
		return "Non-IO: no data"
	}
	return renderSelectableTable(
		columns,
		rows,
		height,
		offset,
		selectedCol,
		"families excluding file/fd",
	)
}

func nonIOTableData(families []statsengine.FamilySnapshot, width int) ([]common.TableColumn, [][]string) {
	columns := nonIOColumns(width)
	if width < 130 {
		return columns, nonIORowsCompact(families)
	}
	return columns, nonIORowsFull(families)
}

func nonIOColumns(width int) []common.TableColumn {
	if width < 130 {
		return []common.TableColumn{
			{Title: "Family", Width: 10},
			{Title: "Count", Width: 7},
			{Title: "Rate/s", Width: 7},
			{Title: "Avg", Width: 8},
			{Title: "Bytes", Width: 8},
			{Title: "Errors", Width: 6},
		}
	}

	return []common.TableColumn{
		{Title: "Family", Width: 12},
		{Title: "Count", Width: 8},
		{Title: "Rate/s", Width: 8},
		{Title: "Avg", Width: 9},
		{Title: "Min", Width: 9},
		{Title: "Max", Width: 9},
		{Title: "Total", Width: 10},
		{Title: "Bytes", Width: 10},
		{Title: "Errors", Width: 8},
	}
}

func nonIORowsFull(families []statsengine.FamilySnapshot) [][]string {
	rows := make([][]string, 0, len(families))
	for _, f := range families {
		rows = append(rows, []string{
			f.Name,
			strconv.FormatUint(f.Count, 10),
			fmt.Sprintf("%.1f", f.RatePerSec),
			formatDurationNs(f.LatencyMeanNs),
			formatDurationUintNs(f.LatencyMinNs),
			formatDurationUintNs(f.LatencyMaxNs),
			formatDurationUintNs(f.TotalLatencyNs),
			formatBytes(float64(f.Bytes)),
			strconv.FormatUint(f.Errors, 10),
		})
	}
	return rows
}

func nonIORowsCompact(families []statsengine.FamilySnapshot) [][]string {
	rows := make([][]string, 0, len(families))
	for _, f := range families {
		rows = append(rows, []string{
			f.Name,
			strconv.FormatUint(f.Count, 10),
			fmt.Sprintf("%.1f", f.RatePerSec),
			formatDurationNs(f.LatencyMeanNs),
			formatBytes(float64(f.Bytes)),
			strconv.FormatUint(f.Errors, 10),
		})
	}
	return rows
}
