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

// renderSyscallsWithSort renders the Syscalls table from the already
// filter-scoped row set rowsData (see Model.visibleSyscallRows). snap is passed
// only to distinguish the "waiting for stats" state (nil snapshot) from the
// "no data" state (non-nil snapshot but empty rows after filtering). Every
// line is at most width cells wide: the placeholders are cut, the table is
// fitted by renderSelectableTable (syscallTableSpec).
func renderSyscallsWithSort(snap *statsengine.Snapshot, rowsData []statsengine.SyscallSnapshot, width, height, offset, selectedCol int, sortState tableSortState[syscallSortKey]) string {
	if snap == nil {
		return fitTableLine("Syscalls: waiting for stats...", width)
	}

	rowsData = sortedSyscallSnapshots(rowsData, sortState)
	spec, rows := syscallTableData(rowsData, width)
	if len(rows) == 0 {
		return fitTableLine("Syscalls: no data", width)
	}
	return renderSelectableTable(
		spec,
		rows,
		width,
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

func syscallTableData(syscalls []statsengine.SyscallSnapshot, width int) (tableSpec, [][]string) {
	spec := syscallTableSpec(width)
	if width < 140 {
		return spec, syscallRowsCompact(syscalls)
	}
	return spec, syscallRowsFull(syscalls)
}

// syscallTableSpec is the Syscalls table with its narrow-terminal policy
// (fitTableColumns): the percentiles go first, then the family, bytes,
// errors, rate and finally the mean latency; the name (shrinking to 8 cells)
// and the count are required. Below 140 columns the compact column set
// applies, whose natural row is 82 cells wide, so from 81 columns down the
// policy takes over; the full set (125 cells) always fits from 140 on.
func syscallTableSpec(width int) tableSpec {
	spec := tableSpec{title: "Syscalls", columns: syscallColumns(width), flex: 0, flexMin: 8}
	if width < 140 {
		// Compact: 0 Syscall, 1 Family, 2 Count, 3 Rate/s, 4 Avg, 5 p95,
		// 6 p99, 7 Bytes, 8 Errors.
		spec.dropOrder = []int{6, 5, 1, 7, 8, 3, 4}
		return spec
	}
	// Full: 0 Syscall, 1 Family, 2 Count, 3 Rate/s, 4 Avg, 5 Min, 6 Max,
	// 7 p50, 8 p95, 9 p99, 10 Bytes, 11 Errors.
	spec.dropOrder = []int{7, 5, 9, 8, 6, 1, 10, 11, 3, 4}
	return spec
}

// syscallColumns returns the logical Syscalls columns at their natural widths:
// the compact set below 140 columns, the full set from 140 on. Their indexes
// are what the column selection and syscallSortKeyForColumn refer to.
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
			latencyCell(s.NoLatency, s.LatencyMeanNs),
			latencyCellUint(s.NoLatency, s.LatencyMinNs),
			latencyCellUint(s.NoLatency, s.LatencyMaxNs),
			latencyCellUint(s.NoLatency, s.LatencyP50Ns),
			latencyCellUint(s.NoLatency, s.LatencyP95Ns),
			latencyCellUint(s.NoLatency, s.LatencyP99Ns),
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
			latencyCell(s.NoLatency, s.LatencyMeanNs),
			latencyCellUint(s.NoLatency, s.LatencyP95Ns),
			latencyCellUint(s.NoLatency, s.LatencyP99Ns),
			formatBytes(float64(s.Bytes)),
			strconv.FormatUint(s.Errors, 10),
		})
	}
	return rows
}

// noLatencyCell is what a latency cell shows for a row without a single
// timed sample (statsengine SyscallSnapshot/ProcessSnapshot NoLatency), e.g.
// exit_group, exit and rt_sigreturn, which never reach sys_exit: their 0s are
// placeholders, not a measured 0ns. It is the Stream tab's "-" for the same
// rows' latency cell.
const noLatencyCell = "-"

// latencyCell formats a latency figure of a dashboard row, or noLatencyCell
// when the row has no timed sample (noLatency).
func latencyCell(noLatency bool, v float64) string {
	if noLatency {
		return noLatencyCell
	}
	return formatDurationNs(v)
}

// latencyCellUint is latencyCell for the uint64 figures (min, max,
// percentiles).
func latencyCellUint(noLatency bool, v uint64) string {
	return latencyCell(noLatency, float64(v))
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

// tableChromeRows is what a selectable table spends besides its data rows:
// the column header line and the "[Row x/N ...]" hint line.
const tableChromeRows = 2

// defaultTableRows is the data-row count of a table rendered without a height
// budget (height <= 0).
const defaultTableRows = 10

// tableRowBudget returns how many data rows a selectable table shows when its
// body gets height rows: whatever is left once the header and hint lines are
// paid for, at least one. The result is also the paging step's basis, so the
// rows the user sees are exactly the rows PageUp/PageDown move over. A body
// shorter than tableChromeRows+1 (never rendered; see minBodyRows) clips the
// hint line instead of keeping a minimum row count that would outgrow the
// terminal. height <= 0 means "no budget" and gives defaultTableRows.
func tableRowBudget(height int) int {
	if height <= 0 {
		return defaultTableRows
	}
	return max(height-tableChromeRows, 1)
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
