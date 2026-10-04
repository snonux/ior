package dashboard

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
)

type processSortKey uint8

const (
	processSortKeyPID processSortKey = iota
	processSortKeyComm
	processSortKeySyscalls
	processSortKeyRate
	processSortKeyBytes
	processSortKeyAvgLatency
)

func renderProcesses(snap *statsengine.Snapshot, width, height int) string {
	return renderProcessesWithSort(snap, width, height, 0, 0, -1, tableSortState[processSortKey]{})
}

// renderProcessesWithSort renders the Processes table. Every line is at most
// width cells wide: the placeholders and the PID-filter note are cut, the
// table is fitted by renderSelectableTable (processTableSpec).
func renderProcessesWithSort(snap *statsengine.Snapshot, width, height, offset, selectedCol, pidFilter int, sortState tableSortState[processSortKey]) string {
	if snap == nil {
		return fitTableLine("Processes: waiting for stats...", width)
	}

	rows := processRows(sortedProcessTableRows(snap.Processes(), sortState))
	if len(rows) == 0 {
		return fitTableLine("Processes: no data", width)
	}

	noteRows := processFilterNoteRows(pidFilter, height)
	out := renderSelectableTable(processTableSpec(), rows, width, height-noteRows, offset, selectedCol, "enter:filter", "s/S:sort", processSortHint(sortState), "v:mode", "b:metric")
	if noteRows > 0 {
		// Use a Builder to avoid an extra allocation for the PID-filter note suffix.
		var b strings.Builder
		b.WriteString(out)
		b.WriteString("\n")
		b.WriteString(fitTableLine(processFilterNote, width))
		return b.String()
	}
	return out
}

// processFilterNote is the line under the Processes table while a PID filter
// is active.
const processFilterNote = "Note: this tab is most useful with All PIDs."

// processFilterNoteMinHeight is the smallest body height that still has a row
// for the note: the table keeps its header, a row and its hint above it.
const processFilterNoteMinHeight = 5

// processFilterNoteRows is how many rows of a height-row body the PID-filter
// note takes: one while a PID filter is active and the body can spare it, else
// 0 (the note is dropped, never cut by the body clip, task 503). The table is
// laid out for the rest, and the paging step is derived from the same number
// (Model.activeTableHeight), so the table never draws a row the budget does
// not have.
func processFilterNoteRows(pidFilter, height int) int {
	// A non-positive height is the renderer's default body (renderSelectableTable
	// draws 10 rows then), which has room.
	if pidFilter > 0 && (height <= 0 || height >= processFilterNoteMinHeight) {
		return 1
	}
	return 0
}

// processColumns returns the logical Processes columns at their natural
// widths; their indexes are what processSortKeyForColumn refers to.
func processColumns() []common.TableColumn {
	return []common.TableColumn{
		// 10 cells fit a 7-digit PID (pid_max tops out at 4194304) plus a
		// "#n" lifetime suffix for a recycled PID's later rows.
		{Title: "PID", Width: 10},
		{Title: "Comm", Width: processCommWidth},
		{Title: "Syscalls", Width: 10},
		{Title: "Rate/s", Width: 8},
		{Title: "Total Bytes", Width: 12},
		{Title: "Avg Latency", Width: 12},
	}
}

// processCommWidth is the natural width of the Comm column (a 16-byte kernel
// comm plus room); processCommMinWidth the narrowest it is cut to before the
// table gives way to its notice.
const (
	processCommWidth    = 18
	processCommMinWidth = 8
)

// processTableSpec is the Processes table with its narrow-terminal policy
// (fitTableColumns): Rate/s goes first, then Total Bytes, Avg Latency and the
// Syscalls count; the PID and the comm (cut with "...", down to
// processCommMinWidth) are required. The natural row is 75 cells wide.
func processTableSpec() tableSpec {
	return tableSpec{
		title:   "Processes",
		columns: processColumns(),
		flex:    1,
		flexMin: processCommMinWidth,
		cut:     truncateText,
		// 0 PID, 1 Comm, 2 Syscalls, 3 Rate/s, 4 Total Bytes, 5 Avg Latency.
		dropOrder: []int{3, 4, 5, 2},
	}
}

func sortedProcessTableRows(rows []statsengine.ProcessSnapshot, sortState tableSortState[processSortKey]) []statsengine.ProcessSnapshot {
	return sortedWithState(rows, sortState, compareProcessBySort, compareProcessDefault)
}

func compareProcessBySort(left, right statsengine.ProcessSnapshot, key processSortKey) int {
	switch key {
	case processSortKeyPID:
		return compareUint64Asc(uint64(left.PID), uint64(right.PID))
	case processSortKeyComm:
		return compareStringAsc(left.Comm, right.Comm)
	case processSortKeySyscalls:
		return compareUint64Desc(left.Syscalls, right.Syscalls)
	case processSortKeyRate:
		return compareFloat64Desc(left.RatePerSec, right.RatePerSec)
	case processSortKeyBytes:
		return compareUint64Desc(left.Bytes, right.Bytes)
	case processSortKeyAvgLatency:
		return compareFloat64Desc(left.AvgLatencyNs, right.AvgLatencyNs)
	default:
		return 0
	}
}

func compareProcessDefault(left, right statsengine.ProcessSnapshot) int {
	if cmp := compareUint64Desc(left.Syscalls, right.Syscalls); cmp != 0 {
		return cmp
	}
	if cmp := compareUint64Desc(left.Bytes, right.Bytes); cmp != 0 {
		return cmp
	}
	if cmp := compareUint64Asc(uint64(left.PID), uint64(right.PID)); cmp != 0 {
		return cmp
	}
	// A recycled PID has one row per lifetime; order them oldest first.
	return compareUint64Asc(uint64(left.Lifetime), uint64(right.Lifetime))
}

func processSortKeyForColumn(column int) (processSortKey, bool) {
	switch column {
	case 0:
		return processSortKeyPID, true
	case 1:
		return processSortKeyComm, true
	case 2:
		return processSortKeySyscalls, true
	case 3:
		return processSortKeyRate, true
	case 4:
		return processSortKeyBytes, true
	case 5:
		return processSortKeyAvgLatency, true
	default:
		return 0, false
	}
}

func processSortHint(sortState tableSortState[processSortKey]) string {
	return "sort: " + processSortLabel(sortState)
}

func processSortLabel(sortState tableSortState[processSortKey]) string {
	if !sortState.active {
		return "default"
	}
	switch sortState.key {
	case processSortKeyPID:
		return sortLabelWithDirection("PID", true, sortState.reverse)
	case processSortKeyComm:
		return sortLabelWithDirection("Comm", true, sortState.reverse)
	case processSortKeySyscalls:
		return sortLabelWithDirection("Syscalls", false, sortState.reverse)
	case processSortKeyRate:
		return sortLabelWithDirection("Rate/s", false, sortState.reverse)
	case processSortKeyBytes:
		return sortLabelWithDirection("Total Bytes", false, sortState.reverse)
	case processSortKeyAvgLatency:
		return sortLabelWithDirection("Avg Latency", false, sortState.reverse)
	default:
		return "default"
	}
}

// findProcessOffset returns the index of the row with selection key key
// (processKey).
func findProcessOffset(rows []statsengine.ProcessSnapshot, key string) (int, bool) {
	for idx, row := range rows {
		if processRowKey(row) == key {
			return idx, true
		}
	}
	return 0, false
}

// processRows returns the Processes table rows. The comm cell is the whole
// sanitised comm: renderSelectableTable cuts it (truncateText) to the width
// its column gets on the terminal.
func processRows(processes []statsengine.ProcessSnapshot) [][]string {
	rows := make([][]string, 0, len(processes))
	for _, p := range processes {
		rows = append(rows, []string{
			p.ID(), // "PID#lifetime" for a recycled PID's later rows
			common.Sanitize(p.Comm),
			strconv.FormatUint(p.Syscalls, 10),
			fmt.Sprintf("%.1f", p.RatePerSec),
			formatBytes(float64(p.Bytes)),
			latencyCell(p.NoLatency, p.AvgLatencyNs),
		})
	}
	return rows
}

// truncateText sanitises value (it renders traced comm names, see
// common.Sanitize) and shortens it to at most limit display cells, ending in
// "..." with any trailing space before the marker trimmed. Limits of three cells or
// fewer hard-cut the value instead, as a lone "..." would hide all content.
// Cuts are grapheme- and display-width-aware (common.TruncateRight), so
// multi-byte comm names never turn into invalid UTF-8.
func truncateText(value string, limit int) string {
	value = common.Sanitize(value)
	if common.DisplayWidth(value) <= limit {
		return value
	}
	if limit <= len(common.ASCIIEllipsis) {
		return common.TruncateRight(value, limit, "")
	}
	head := common.TruncateRight(value, limit-len(common.ASCIIEllipsis), "")
	return strings.TrimSpace(head) + common.ASCIIEllipsis
}
