package dashboard

import (
	"fmt"
	"strconv"
	"time"

	"ior/internal/statsengine"

	"charm.land/bubbles/v2/table"
)

func renderSyscalls(snap *statsengine.Snapshot, width, height int) string {
	return renderSyscallsWithOffset(snap, width, height, 0)
}

func renderSyscallsWithOffset(snap *statsengine.Snapshot, width, height, offset int) string {
	if snap == nil {
		return "Syscalls: waiting for stats..."
	}

	columns, rows := syscallTableData(snap.Syscalls(), width)
	if len(rows) == 0 {
		return "Syscalls: no data"
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

func syscallTableData(syscalls []statsengine.SyscallSnapshot, width int) ([]table.Column, []table.Row) {
	if width < 140 {
		columns := []table.Column{
			{Title: "Syscall", Width: 14},
			{Title: "Count", Width: 6},
			{Title: "Rate/s", Width: 7},
			{Title: "Avg", Width: 8},
			{Title: "p95", Width: 8},
			{Title: "p99", Width: 8},
			{Title: "Bytes", Width: 8},
			{Title: "Errors", Width: 6},
		}
		return columns, syscallRowsCompact(syscalls)
	}

	columns := []table.Column{
		{Title: "Syscall", Width: 16},
		{Title: "Count", Width: 8},
		{Title: "Rate/s", Width: 8},
		{Title: "Avg", Width: 9},
		{Title: "Min", Width: 9},
		{Title: "Max", Width: 9},
		{Title: "p50", Width: 9},
		{Title: "p95", Width: 9},
		{Title: "p99", Width: 9},
		{Title: "Bytes", Width: 10},
		{Title: "Errors", Width: 8},
	}
	return columns, syscallRowsFull(syscalls)
}

func syscallRowsFull(syscalls []statsengine.SyscallSnapshot) []table.Row {
	rows := make([]table.Row, 0, len(syscalls))
	for _, s := range syscalls {
		rows = append(rows, table.Row{
			s.Name,
			strconv.FormatUint(s.Count, 10),
			fmt.Sprintf("%.1f", s.RatePerSec),
			formatDurationNs(s.LatencyMeanNs),
			formatDurationUintNs(s.LatencyMinNs),
			formatDurationUintNs(s.LatencyMaxNs),
			formatDurationUintNs(s.LatencyP50Ns),
			formatDurationUintNs(s.LatencyP95Ns),
			formatDurationUintNs(s.LatencyP99Ns),
			formatBytes(float64(s.Bytes)),
			strconv.FormatUint(s.Errors, 10),
		})
	}
	return rows
}

func syscallRowsCompact(syscalls []statsengine.SyscallSnapshot) []table.Row {
	rows := make([]table.Row, 0, len(syscalls))
	for _, s := range syscalls {
		rows = append(rows, table.Row{
			s.Name,
			strconv.FormatUint(s.Count, 10),
			fmt.Sprintf("%.1f", s.RatePerSec),
			formatDurationNs(s.LatencyMeanNs),
			formatDurationUintNs(s.LatencyP95Ns),
			formatDurationUintNs(s.LatencyP99Ns),
			formatBytes(float64(s.Bytes)),
			strconv.FormatUint(s.Errors, 10),
		})
	}
	return rows
}

func formatDurationUintNs(v uint64) string {
	return formatDurationNs(float64(v))
}

func formatDurationNs(v float64) string {
	if v < 1000 {
		return fmt.Sprintf("%.0fns", v)
	}
	us := v / 1000
	if us < 1000 {
		return fmt.Sprintf("%.1fµs", us)
	}
	ms := us / 1000
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	s := ms / 1000
	return (time.Duration(s * float64(time.Second))).String()
}

func syscallTableHeight(height int) int {
	if height <= 0 {
		return 10
	}
	h := height - 6
	if h < 5 {
		return 5
	}
	return h
}

func tableWidth(width int) int {
	if width <= 0 {
		return 80
	}
	if width < 60 {
		return 60
	}
	return width
}

func clampOffset(offset, size int) int {
	if size == 0 {
		return 0
	}
	if offset < 0 {
		return 0
	}
	if offset >= size {
		return size - 1
	}
	return offset
}
