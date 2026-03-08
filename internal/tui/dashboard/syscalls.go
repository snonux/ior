package dashboard

import (
	"fmt"
	"strconv"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

func renderSyscalls(snap *statsengine.Snapshot, width, height int) string {
	return renderSyscallsWithOffset(snap, width, height, 0, 0)
}

func renderSyscallsWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	if snap == nil {
		return "Syscalls: waiting for stats..."
	}

	columns, rows := syscallTableData(snap.Syscalls(), width)
	if len(rows) == 0 {
		return "Syscalls: no data"
	}
	return renderSelectableTable(columns, rows, height, offset, selectedCol, "enter:filter", "v:mode", "b:metric")
}

func syscallTableData(syscalls []statsengine.SyscallSnapshot, width int) ([]common.TableColumn, [][]string) {
	columns := syscallColumns(width)
	if width < 140 {
		return columns, syscallRowsCompact(syscalls)
	}
	return columns, syscallRowsFull(syscalls)
}

func syscallColumns(width int) []common.TableColumn {
	if width < 140 {
		return []common.TableColumn{
			{Title: "Syscall", Width: 14},
			{Title: "Count", Width: 6},
			{Title: "Rate/s", Width: 7},
			{Title: "Avg", Width: 8},
			{Title: "p95", Width: 8},
			{Title: "p99", Width: 8},
			{Title: "Bytes", Width: 8},
			{Title: "Errors", Width: 6},
		}
	}

	return []common.TableColumn{
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
}

func syscallRowsFull(syscalls []statsengine.SyscallSnapshot) [][]string {
	rows := make([][]string, 0, len(syscalls))
	for _, s := range syscalls {
		rows = append(rows, []string{
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

func syscallRowsCompact(syscalls []statsengine.SyscallSnapshot) [][]string {
	rows := make([][]string, 0, len(syscalls))
	for _, s := range syscalls {
		rows = append(rows, []string{
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
