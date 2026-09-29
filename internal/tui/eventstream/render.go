package eventstream

import (
	"fmt"
	"strconv"
	"strings"

	"ior/internal/globalfilter/presenter"
	"ior/internal/tui/common"

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
// which floor) when a narrow row still exceeds the available width. Less
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

// RenderStreamTable renders the stream tab's main panel: status line, filter
// line and the (selected) event rows, fitted to width.
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
// line is first cut to the panel's text width (display-width and ANSI aware
// via MaxWidth) so nothing wraps: model.visibleRows budgets exactly one
// terminal line per event row, and a wrapped row would push the footer and
// status lines off-screen on narrow terminals.
func renderPanel(contentWidth int, lines []string) string {
	textWidth := panelTextWidth(contentWidth)
	fit := lipgloss.NewStyle().MaxWidth(textWidth)
	for i, line := range lines {
		// Rows are already laid out to textWidth; only restyle overflowing lines.
		if lipgloss.Width(line) > textWidth {
			lines[i] = fit.Render(line)
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

func renderFilterLine(filter Filter) string {
	theme := common.Current()
	summary := presenter.FilterSummary(filter)
	if summary == "all" {
		summary = theme.HighlightStyle.Render(summary)
	}
	return theme.HeaderStyle.Render("Filter:") + " " + summary
}

func renderFilterStackLine(filterStack []string) string {
	return common.Current().HeaderStyle.Render("Stack:") + " " + strings.Join(filterStack, " | ")
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

func renderEventRow(ev StreamEvent, columns []common.TableColumn, selected bool, selectedCol int) string {
	fd := "-"
	if ev.FD >= 0 {
		fd = strconv.FormatInt(int64(ev.FD), 10)
	}
	cells := []string{
		fitCell(formatDurationNs(ev.GapNs), columns[0].Width),
		fitCell(formatDurationNs(ev.DurationNs), columns[1].Width),
		fitCell(ev.Comm, columns[2].Width),
		fitCell(strconv.FormatUint(uint64(ev.PID), 10), columns[3].Width),
		fitCell(strconv.FormatUint(uint64(ev.TID), 10), columns[4].Width),
		fitCell(ev.Syscall, columns[5].Width),
		fitCell(fd, columns[6].Width),
		fitCell(strconv.FormatInt(ev.RetVal, 10), columns[7].Width),
		fitCell(strconv.FormatUint(ev.Bytes, 10), columns[8].Width),
		fitCell(ev.FileName, columns[9].Width),
	}
	if ev.IsError {
		return common.RenderTableRow(columns, cells, selected, selectedCol, common.Current().ErrorStyle)
	}
	return common.RenderTableRow(columns, cells, selected, selectedCol, lipgloss.Style{})
}

func computeColumnLayout(width int) columnLayout {
	if width <= 0 {
		width = 100
	}

	// Keep non-file columns compact so file paths can use most of the row.
	cols := columnLayout{gap: 7, latency: 8, comm: 10, pid: 7, tid: 7, syscall: 9, fd: 4, ret: 5, bytes: 8}
	cols.file = width - nonFileWidth(cols)
	if cols.file >= 28 {
		// On wider terminals, give a little more room back to descriptive columns.
		if width >= 140 {
			cols.comm, cols.syscall, cols.pid, cols.tid = 12, 11, 8, 8
			cols.file = width - nonFileWidth(cols)
		}
		return cols
	}

	// Narrow widths: compress the fixed columns, keep the file column readable
	// where possible, then shrink further until the row fits width exactly so
	// the panel never wraps a row onto a second line.
	cols = columnLayout{gap: 7, latency: 8, comm: 8, pid: 6, tid: 6, syscall: 8, fd: 3, ret: 4, bytes: 7}
	cols.file = max(width-nonFileWidth(cols), 12)
	shrinkToFit(&cols, width)
	return cols
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

func truncateMiddle(path string, limit int) string {
	if limit <= 0 {
		return ""
	}
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

func fitCell(s string, width int) string {
	return truncateMiddle(sanitizeOneLine(s), width)
}

func sanitizeOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
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
