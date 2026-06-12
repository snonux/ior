package dashboard

import (
	"fmt"
	"strconv"
	"time"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

type syscallSortKey uint8

const (
	syscallSortKeyName syscallSortKey = iota
	syscallSortKeyFamily
	syscallSortKeyCount
	syscallSortKeyRate
	syscallSortKeyAvg
	syscallSortKeyMin
	syscallSortKeyMax
	syscallSortKeyP50
	syscallSortKeyP95
	syscallSortKeyP99
	syscallSortKeyBytes
	syscallSortKeyErrors
)

func renderSyscalls(snap *statsengine.Snapshot, width, height int) string {
	return renderSyscallsWithSort(snap, width, height, 0, 0, tableSortState[syscallSortKey]{})
}

func renderSyscallsWithOffset(snap *statsengine.Snapshot, width, height, offset, selectedCol int) string {
	return renderSyscallsWithSort(snap, width, height, offset, selectedCol, tableSortState[syscallSortKey]{})
}

func renderSyscallsWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol int, sortState tableSortState[syscallSortKey]) string {
	if snap == nil {
		return "Syscalls: waiting for stats..."
	}

	rowsData := sortedSyscallSnapshots(snap.Syscalls(), sortState)
	columns, rows := syscallTableData(rowsData, width)
	if len(rows) == 0 {
		return "Syscalls: no data"
	}
	return renderSelectableTable(
		columns,
		rows,
		height,
		offset,
		selectedCol,
		"enter:filter",
		"s/S:sort",
		syscallSortHint(sortState),
		"v:mode",
		"b:metric",
	)
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
			{Title: "Family", Width: 9},
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
		{Title: "Family", Width: 10},
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

func sortedSyscallSnapshots(rows []statsengine.SyscallSnapshot, sortState tableSortState[syscallSortKey]) []statsengine.SyscallSnapshot {
	return sortedWithState(rows, sortState, compareSyscallBySort, compareSyscallDefault)
}

func compareSyscallBySort(left, right statsengine.SyscallSnapshot, key syscallSortKey) int {
	switch key {
	case syscallSortKeyName:
		return compareStringAsc(left.Name, right.Name)
	case syscallSortKeyFamily:
		if cmp := compareStringAsc(string(left.TraceID.Family()), string(right.TraceID.Family())); cmp != 0 {
			return cmp
		}
		return compareStringAsc(left.Name, right.Name)
	case syscallSortKeyCount:
		return compareUint64Desc(left.Count, right.Count)
	case syscallSortKeyRate:
		return compareFloat64Desc(left.RatePerSec, right.RatePerSec)
	case syscallSortKeyAvg:
		return compareFloat64Desc(left.LatencyMeanNs, right.LatencyMeanNs)
	case syscallSortKeyMin:
		return compareUint64Desc(left.LatencyMinNs, right.LatencyMinNs)
	case syscallSortKeyMax:
		return compareUint64Desc(left.LatencyMaxNs, right.LatencyMaxNs)
	case syscallSortKeyP50:
		return compareUint64Desc(left.LatencyP50Ns, right.LatencyP50Ns)
	case syscallSortKeyP95:
		return compareUint64Desc(left.LatencyP95Ns, right.LatencyP95Ns)
	case syscallSortKeyP99:
		return compareUint64Desc(left.LatencyP99Ns, right.LatencyP99Ns)
	case syscallSortKeyBytes:
		return compareUint64Desc(left.Bytes, right.Bytes)
	case syscallSortKeyErrors:
		return compareUint64Desc(left.Errors, right.Errors)
	default:
		return 0
	}
}

func compareSyscallDefault(left, right statsengine.SyscallSnapshot) int {
	if cmp := compareUint64Desc(left.Count, right.Count); cmp != 0 {
		return cmp
	}
	return compareStringAsc(left.Name, right.Name)
}

func syscallSortKeyForColumn(width, column int) (syscallSortKey, bool) {
	if width < 140 {
		return compactSyscallSortKey(column)
	}
	return fullSyscallSortKey(column)
}

func compactSyscallSortKey(column int) (syscallSortKey, bool) {
	switch column {
	case 0:
		return syscallSortKeyName, true
	case 1:
		return syscallSortKeyFamily, true
	case 2:
		return syscallSortKeyCount, true
	case 3:
		return syscallSortKeyRate, true
	case 4:
		return syscallSortKeyAvg, true
	case 5:
		return syscallSortKeyP95, true
	case 6:
		return syscallSortKeyP99, true
	case 7:
		return syscallSortKeyBytes, true
	case 8:
		return syscallSortKeyErrors, true
	default:
		return 0, false
	}
}

func fullSyscallSortKey(column int) (syscallSortKey, bool) {
	switch column {
	case 0:
		return syscallSortKeyName, true
	case 1:
		return syscallSortKeyFamily, true
	case 2:
		return syscallSortKeyCount, true
	case 3:
		return syscallSortKeyRate, true
	case 4:
		return syscallSortKeyAvg, true
	case 5:
		return syscallSortKeyMin, true
	case 6:
		return syscallSortKeyMax, true
	case 7:
		return syscallSortKeyP50, true
	case 8:
		return syscallSortKeyP95, true
	case 9:
		return syscallSortKeyP99, true
	case 10:
		return syscallSortKeyBytes, true
	case 11:
		return syscallSortKeyErrors, true
	default:
		return 0, false
	}
}

func syscallSortHint(sortState tableSortState[syscallSortKey]) string {
	return "sort: " + syscallSortLabel(sortState)
}

func syscallSortLabel(sortState tableSortState[syscallSortKey]) string {
	if !sortState.active {
		return "default"
	}
	switch sortState.key {
	case syscallSortKeyName:
		return sortLabelWithDirection("Syscall", true, sortState.reverse)
	case syscallSortKeyFamily:
		return sortLabelWithDirection("Family", true, sortState.reverse)
	case syscallSortKeyCount:
		return sortLabelWithDirection("Count", false, sortState.reverse)
	case syscallSortKeyRate:
		return sortLabelWithDirection("Rate/s", false, sortState.reverse)
	case syscallSortKeyAvg:
		return sortLabelWithDirection("Avg", false, sortState.reverse)
	case syscallSortKeyMin:
		return sortLabelWithDirection("Min", false, sortState.reverse)
	case syscallSortKeyMax:
		return sortLabelWithDirection("Max", false, sortState.reverse)
	case syscallSortKeyP50:
		return sortLabelWithDirection("p50", false, sortState.reverse)
	case syscallSortKeyP95:
		return sortLabelWithDirection("p95", false, sortState.reverse)
	case syscallSortKeyP99:
		return sortLabelWithDirection("p99", false, sortState.reverse)
	case syscallSortKeyBytes:
		return sortLabelWithDirection("Bytes", false, sortState.reverse)
	case syscallSortKeyErrors:
		return sortLabelWithDirection("Errors", false, sortState.reverse)
	default:
		return "default"
	}
}

func findSyscallOffset(rows []statsengine.SyscallSnapshot, name string) (int, bool) {
	for idx, row := range rows {
		if row.Name == name {
			return idx, true
		}
	}
	return 0, false
}

func syscallRowsFull(syscalls []statsengine.SyscallSnapshot) [][]string {
	rows := make([][]string, 0, len(syscalls))
	for _, s := range syscalls {
		rows = append(rows, []string{
			s.Name,
			string(s.TraceID.Family()),
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
			string(s.TraceID.Family()),
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
