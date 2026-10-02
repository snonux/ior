package eventstream

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/common"
	"ior/internal/types"

	"charm.land/lipgloss/v2"
)

type columnLayout struct {
	gap     int
	latency int
	comm    int
	pid     int
	tid     int
	syscall int
	fd      int
	ret     int
	bytes   int
	file    int
}

// columnShrinkSteps lists, in order, which column gives up width (and down to
// which floor) when the compact layout still exceeds the available width. Less
// telling columns (TID, Gap, Bytes) go first; the final pass takes every
// column down to a single cell so the row fits whenever width allows it.
var columnShrinkSteps = []struct{ col, floor int }{
	{streamColTID, 3}, {streamColGap, 5}, {streamColBytes, 5}, {streamColLatency, 6},
	{streamColComm, 5}, {streamColPID, 5}, {streamColSyscall, 5}, {streamColRet, 3},
	{streamColFile, 6},
	{streamColTID, 1}, {streamColGap, 1}, {streamColBytes, 1}, {streamColLatency, 1},
	{streamColComm, 1}, {streamColPID, 1}, {streamColSyscall, 1}, {streamColRet, 1},
	{streamColFD, 1}, {streamColFile, 1},
}

// syscallCommonWidth is the Syscall column's first growth target: it holds
// all but a handful of the generated syscall names (clock_nanosleep,
// name_to_handle_at, process_vm_writev, ...; the exceptions are a few sched_*
// and landlock_* names and set_mempolicy_home_node), so a mid-sized terminal
// shows practically every name whole without taking the 23 cells of the
// longest one from the File column. A test pins that it keeps covering the
// generated table.
const syscallCommonWidth = 17

// syscallFullWidth is the widest name a traced row can carry in its Syscall
// cell, the bound of that column: no terminal width makes it wider.
var syscallFullWidth = longestSyscallNameWidth()

// longestSyscallNameWidth measures the generated syscall table, the names
// streamrow.New stores in a row (TraceId.Name of the sys_enter tracepoint;
// they are ASCII, one cell per byte). The bound is the table and not the rows
// in view or the names seen so far: a column sized by its rows changes width,
// and shifts every column right of it, whenever a longer name scrolls in.
func longestSyscallNameWidth() int {
	longest := 0
	for _, id := range types.EnterTraceIDs() {
		longest = max(longest, len(id.Name()))
	}
	return longest
}

// columnGrowSteps lists, in order, which column takes the width a terminal
// has beyond the compact layout, and up to which width; the File column takes
// whatever the last step leaves. It is the counterpart of columnShrinkSteps
// and, like it, depends on the width only, so the table is stable while rows
// scroll. The order is by what a cut cell costs: a readable File cell first,
// whole PIDs and TIDs (7 digits with the default pid_max), then whole syscall
// names - the Syscall column used to stay at 9 or 11 cells at any width, so
// a 200-column terminal showed "cloc...leep" beside a hundred-cell File
// column (task 923) - then, alternating with more room for paths, the less
// often cut Comm, FD, Ret and Bytes cells, the few names longer than
// syscallCommonWidth, and the roomier Comm/PID/TID of very wide terminals.
var columnGrowSteps = []struct{ col, ceil int }{
	{streamColFile, 20},
	{streamColPID, 7}, {streamColTID, 7},
	{streamColSyscall, syscallCommonWidth},
	{streamColFile, 28},
	{streamColComm, 10}, {streamColFD, 4}, {streamColRet, 5}, {streamColBytes, 8},
	{streamColFile, 40},
	{streamColSyscall, syscallFullWidth},
	{streamColFile, 60},
	{streamColComm, 12}, {streamColPID, 8}, {streamColTID, 8},
}

// RenderStreamTable renders the stream tab's main panel: status line, filter
// line and the (selected) event rows, fitted to width. filteredCount is the
// length of the rows the model keeps after filterRows, so it includes synthetic
// warning rows that bypass the user filter (task ur2): "filtered" is the number
// of rows shown, not strictly the number of syscalls that matched.
func RenderStreamTable(width int, paused bool, totalCount, filteredCount, bufferLen, bufferCap int, filter Filter, filterStack []string, events []StreamEvent, selectedVisibleIdx int, selectedCol int) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)
	columns := streamColumns(panelTextWidth(contentWidth))

	lines := make([]string, 0, len(events)+4)
	lines = append(lines, renderStatusLine(paused, totalCount, filteredCount, bufferLen, bufferCap))
	lines = append(lines, renderFilterLine(filter))
	if len(filterStack) > 0 {
		lines = append(lines, renderFilterStackLine(filterStack))
	}
	lines = append(lines, common.RenderTableHeader(columns))
	for i, ev := range events {
		lines = append(lines, renderEventRow(ev, columns, i == selectedVisibleIdx, selectedCol))
	}

	return renderPanel(contentWidth, lines)
}

// RenderFDTraceTable renders the fd-trace view: all events of one pid/fd
// pair, the stream tab's drill-down from a selected row.
func RenderFDTraceTable(width int, pid uint32, fd int32, totalCount int, events []StreamEvent) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)

	lines := make([]string, 0, len(events)+3)
	lines = append(lines, common.Current().HeaderStyle.Render("FD Trace (ring snapshot)"))
	lines = append(lines, fmt.Sprintf("PID:%d FD:%d matched:%d", pid, fd, totalCount))
	columns := streamColumns(panelTextWidth(contentWidth))
	lines = append(lines, common.RenderTableHeader(columns))
	for _, ev := range events {
		lines = append(lines, renderEventRow(ev, columns, false, -1))
	}

	return renderPanel(contentWidth, lines)
}

// renderPanel boxes lines in the shared panel style at contentWidth. Every
// line is first cut to the panel's text width (display-width and ANSI aware)
// so nothing wraps: model.visibleRows budgets exactly one terminal line per
// event row, and a wrapped row would push the footer and status lines
// off-screen on narrow terminals. The cut is common.TruncateRight without a
// marker, not lipgloss MaxWidth: MaxWidth counts an ASCII base followed by
// U+FE0F / U+20E3 (a keycap such as "1\ufe0f\u20e3") as one cell although the
// cluster is two, so a label with keycaps stayed one cell per cluster too
// wide and widened the panel (task vp2).
func renderPanel(contentWidth int, lines []string) string {
	textWidth := panelTextWidth(contentWidth)
	for i, line := range lines {
		// Rows are already laid out to textWidth; only cut overflowing lines.
		if lipgloss.Width(line) > textWidth {
			lines[i] = common.TruncateRight(line, textWidth, "")
		}
	}
	return common.Current().PanelStyle.Width(contentWidth).Render(strings.Join(lines, "\n"))
}

func renderStatusLine(paused bool, totalCount, filteredCount, bufferLen, bufferCap int) string {
	theme := common.Current()
	state := theme.HighlightStyle.Render("LIVE")
	if paused {
		state = theme.ErrorStyle.Render("PAUSED")
	}
	buffer := strconv.Itoa(bufferLen)
	if bufferCap > 0 {
		buffer = fmt.Sprintf("%d/%d", bufferLen, bufferCap)
	}
	return fmt.Sprintf("%s | total:%d filtered:%d buffer:%s", state, totalCount, filteredCount, buffer)
}

// renderFilterLine shows the active filter. Its patterns are often copied from
// traced comm/file values, so the summary is sanitised before styling.
func renderFilterLine(filter Filter) string {
	theme := common.Current()
	summary := common.Sanitize(presenter.FilterSummary(filter))
	if summary == "all" {
		summary = theme.HighlightStyle.Render(summary)
	}
	return theme.HeaderStyle.Render("Filter:") + " " + summary
}

// renderFilterStackLine shows the undo stack labels; like the filter line they
// can contain traced values and are sanitised.
func renderFilterStackLine(filterStack []string) string {
	return common.Current().HeaderStyle.Render("Stack:") + " " + common.Sanitize(strings.Join(filterStack, " | "))
}

func streamColumns(width int) []common.TableColumn {
	cols := computeColumnLayout(width)
	return []common.TableColumn{
		{Title: "Gap", Width: cols.gap},
		{Title: "Latency", Width: cols.latency},
		{Title: "Comm", Width: cols.comm},
		{Title: "PID", Width: cols.pid},
		{Title: "TID", Width: cols.tid},
		{Title: "Syscall", Width: cols.syscall},
		{Title: "FD", Width: cols.fd},
		{Title: "Ret", Width: cols.ret},
		{Title: "Bytes", Width: cols.bytes},
		{Title: "File", Width: cols.file},
	}
}

// renderEventRow renders one row of the stream or fd-trace table: the ten
// cells of a syscall row, or the spanning line of a warning row.
func renderEventRow(ev StreamEvent, columns []common.TableColumn, selected bool, selectedCol int) string {
	if ev.IsWarning {
		return renderWarningRow(ev, columns, selected)
	}
	fd := "-"
	if ev.FD >= 0 {
		fd = strconv.FormatInt(int64(ev.FD), 10)
	}
	// A noreturn syscall (exit, exit_group, rt_sigreturn) has neither a
	// latency nor a return value; its 0s are placeholders, shown as "-" like
	// an absent descriptor.
	latency, ret := formatDurationNs(ev.DurationNs), strconv.FormatInt(ev.RetVal, 10)
	if ev.NoReturn {
		latency, ret = "-", "-"
	}
	cells := []string{
		fitCell(formatDurationNs(ev.GapNs), columns[0].Width),
		fitCell(latency, columns[1].Width),
		fitCell(ev.Comm, columns[2].Width),
		fitCell(strconv.FormatUint(uint64(ev.PID), 10), columns[3].Width),
		fitCell(strconv.FormatUint(uint64(ev.TID), 10), columns[4].Width),
		fitCell(ev.Syscall, columns[5].Width),
		fitCell(fd, columns[6].Width),
		fitCell(ret, columns[7].Width),
		fitCell(strconv.FormatUint(ev.Bytes, 10), columns[8].Width),
		fitCell(ev.FileName, columns[9].Width),
	}
	if ev.IsError {
		return common.RenderTableRow(columns, cells, selected, selectedCol, common.Current().ErrorStyle)
	}
	return common.RenderTableRow(columns, cells, selected, selectedCol, lipgloss.Style{})
}

// renderWarningRow renders a synthetic warning row (streamrow.NewWarning) as
// one line across the whole row: its label ("warning", the row's Syscall
// text), a colon and the message, cut at the END when it is too long. The
// row has nothing else to show - its other cells are placeholders (pid 0,
// ret -1, 0 bytes) - and a message drawn in the File column alone was cut to
// that column and, like a path, in the middle, which removed exactly the
// cause a warning names early on: "(t...may be unnamed" at 220 columns (task
// 923). A row is one terminal line (model.visibleRows), so the message
// cannot wrap; what the end cut drops is the trailing advice. The message is
// foreign text (libbpf output, error strings) and is sanitised like a cell.
//
// The line is exactly as wide as the columns with their separators, so it
// fills the panel like every other row. Selected, it takes the row
// selection style as a whole: it has no cells to mark, and Enter builds no
// filter from it (requestGlobalFilterFromSelectedCell).
func renderWarningRow(ev StreamEvent, columns []common.TableColumn, selected bool) string {
	width := len(columns) - 1
	for _, col := range columns {
		width += col.Width
	}
	line := common.FitRight(common.Sanitize(ev.Syscall+": "+ev.FileName), width, common.ASCIIEllipsis)
	theme := common.Current()
	if selected {
		return theme.TableSelectedRowStyle.Render(line)
	}
	return theme.ErrorStyle.Render(line)
}

// computeColumnLayout sizes the columns for a row of width cells. It starts
// from the compact layout (78 cells: every column at the smallest width that
// still reads well, File at 12) and then either shrinks it (shrinkToFit) so
// that a narrow row fits exactly and the panel never wraps it onto a second
// line, or hands out the spare width (growToFill).
func computeColumnLayout(width int) columnLayout {
	if width <= 0 {
		width = 100
	}
	cols := columnLayout{gap: 7, latency: 8, comm: 8, pid: 6, tid: 6, syscall: 8, fd: 3, ret: 4, bytes: 7, file: 12}
	if rowWidth(&cols) > width {
		shrinkToFit(&cols, width)
		return cols
	}
	growToFill(&cols, width)
	return cols
}

// growToFill widens the columns following columnGrowSteps while the row is
// narrower than width, then gives what is left to the File column, so the row
// is exactly width cells wide.
func growToFill(cols *columnLayout, width int) {
	fields := columnFields(cols)
	for _, step := range columnGrowSteps {
		spare := width - rowWidth(cols)
		if spare <= 0 {
			return
		}
		field := fields[step.col]
		*field += max(min(spare, step.ceil-*field), 0)
	}
	cols.file += max(width-rowWidth(cols), 0)
}

// shrinkToFit reduces column widths following columnShrinkSteps until the row
// (cells plus single-space separators) is no wider than width. When even the
// all-ones layout is too wide, the caller's line truncation is the backstop.
func shrinkToFit(cols *columnLayout, width int) {
	fields := columnFields(cols)
	for _, step := range columnShrinkSteps {
		excess := rowWidth(cols) - width
		if excess <= 0 {
			return
		}
		field := fields[step.col]
		*field -= max(min(excess, *field-step.floor), 0)
	}
}

// columnFields maps stream column indices (streamCol*) to the layout fields.
func columnFields(cols *columnLayout) []*int {
	return []*int{&cols.gap, &cols.latency, &cols.comm, &cols.pid, &cols.tid, &cols.syscall, &cols.fd, &cols.ret, &cols.bytes, &cols.file}
}

// rowWidth is the display width of a row: every cell plus one space between
// adjacent cells (common.RenderTableRow joins cells with " ").
func rowWidth(cols *columnLayout) int {
	return nonFileWidth(*cols) + cols.file
}

// nonFileWidth is the width taken by all columns except File, including all
// streamColumnCount-1 separators.
func nonFileWidth(cols columnLayout) int {
	return cols.gap + cols.latency + cols.comm + cols.pid + cols.tid + cols.syscall + cols.fd + cols.ret + cols.bytes + streamColumnCount - 1
}

func formatDurationNs(v uint64) string {
	if v < 1000 {
		return fmt.Sprintf("%dns", v)
	}
	us := float64(v) / 1000
	if us < 1000 {
		return fmt.Sprintf("%.1fus", us)
	}
	ms := us / 1000
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	s := ms / 1000
	return fmt.Sprintf("%.2fs", s)
}

// fitCell neutralises control characters in s (common.Sanitize: traced comm
// and file names are attacker-controlled, and newlines/tabs flatten to
// spaces) and shortens it to at most width display cells, keeping both ends
// joined by "..." (the middle of a long path is the least informative part).
// The cut is grapheme- and display-width-aware, so non-ASCII file names never
// turn into invalid UTF-8; the table pads the rest.
func fitCell(s string, width int) string {
	return common.TruncateMiddle(common.Sanitize(s), width, common.ASCIIEllipsis)
}

// panelContentWidth is the value passed to PanelStyle.Width for a given
// terminal width. lipgloss v2 counts border and padding as part of Width, so
// the panel spans the full terminal width like the dashboard's other panels.
// It only grows past width when the terminal is narrower than the panel frame
// plus one text cell, the smallest panel that can hold any content.
func panelContentWidth(width int) int {
	return max(width, common.Current().PanelStyle.GetHorizontalFrameSize()+1)
}

// panelTextWidth is the width available to text inside a panel rendered with
// PanelStyle.Width(contentWidth). lipgloss v2 counts border and padding as
// part of Width, so the text area is contentWidth minus the panel's
// horizontal frame (border + padding); table rows must be laid out for this
// width, not contentWidth, or every row wraps.
func panelTextWidth(contentWidth int) int {
	return max(contentWidth-common.Current().PanelStyle.GetHorizontalFrameSize(), 1)
}
