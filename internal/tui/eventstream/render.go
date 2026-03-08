package eventstream

import (
	"fmt"
	"strconv"
	"strings"

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

func RenderStreamTable(width int, paused bool, totalCount, filteredCount, bufferLen, bufferCap int, filter Filter, filterStack []string, events []StreamEvent, selectedVisibleIdx int, selectedCol int) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)
	columns := streamColumns(contentWidth)

	lines := make([]string, 0, len(events)+3)
	lines = append(lines, renderStatusLine(paused, totalCount, filteredCount, bufferLen, bufferCap))
	lines = append(lines, renderFilterLine(filter))
	if len(filterStack) > 0 {
		lines = append(lines, renderFilterStackLine(filterStack))
	}
	lines = append(lines, common.RenderTableHeader(columns))
	for i, ev := range events {
		lines = append(lines, renderEventRow(ev, columns, i == selectedVisibleIdx, selectedCol))
	}

	return common.PanelStyle.Width(contentWidth).Render(strings.Join(lines, "\n"))
}

func RenderFDTraceTable(width int, pid uint32, fd int32, totalCount int, events []StreamEvent) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)

	lines := make([]string, 0, len(events)+3)
	lines = append(lines, common.HeaderStyle.Render("FD Trace (ring snapshot)"))
	lines = append(lines, fmt.Sprintf("PID:%d FD:%d matched:%d", pid, fd, totalCount))
	columns := streamColumns(contentWidth)
	lines = append(lines, common.RenderTableHeader(columns))
	for _, ev := range events {
		lines = append(lines, renderEventRow(ev, columns, false, -1))
	}

	return common.PanelStyle.Width(contentWidth).Render(strings.Join(lines, "\n"))
}

func renderStatusLine(paused bool, totalCount, filteredCount, bufferLen, bufferCap int) string {
	state := common.HighlightStyle.Render("LIVE")
	if paused {
		state = common.ErrorStyle.Render("PAUSED")
	}
	buffer := strconv.Itoa(bufferLen)
	if bufferCap > 0 {
		buffer = fmt.Sprintf("%d/%d", bufferLen, bufferCap)
	}
	return fmt.Sprintf("%s | total:%d filtered:%d buffer:%s", state, totalCount, filteredCount, buffer)
}

func renderFilterLine(filter Filter) string {
	summary := filter.Summary()
	if summary == "all" {
		summary = common.HighlightStyle.Render(summary)
	}
	return common.HeaderStyle.Render("Filter:") + " " + summary
}

func renderFilterStackLine(filterStack []string) string {
	return common.HeaderStyle.Render("Stack:") + " " + strings.Join(filterStack, " | ")
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
		return common.RenderTableRow(columns, cells, selected, selectedCol, common.ErrorStyle)
	}
	return common.RenderTableRow(columns, cells, selected, selectedCol, lipgloss.Style{})
}

func computeColumnLayout(width int) columnLayout {
	if width <= 0 {
		width = 100
	}

	// Keep non-file columns compact so file paths can use most of the row.
	gap := 7
	latency := 8
	comm := 10
	pid := 7
	tid := 7
	syscall := 9
	fd := 4
	ret := 5
	bytes := 8
	fixed := gap + latency + comm + pid + tid + syscall + fd + ret + bytes + 9
	file := width - fixed
	if file >= 28 {
		// On wider terminals, give a little more room back to descriptive columns.
		if width >= 140 {
			comm = 12
			syscall = 11
			pid = 8
			tid = 8
			fixed = gap + latency + comm + pid + tid + syscall + fd + ret + bytes + 9
			file = width - fixed
		}
		return columnLayout{gap: gap, latency: latency, comm: comm, pid: pid, tid: tid, syscall: syscall, fd: fd, ret: ret, bytes: bytes, file: file}
	}

	// Very narrow widths: compress further but keep file column readable.
	comm = 8
	pid = 6
	tid = 6
	syscall = 8
	fd = 3
	ret = 4
	bytes = 7
	fixed = gap + latency + comm + pid + tid + syscall + fd + ret + bytes + 9
	file = width - fixed
	if file < 12 {
		file = 12
	}
	return columnLayout{gap: gap, latency: latency, comm: comm, pid: pid, tid: tid, syscall: syscall, fd: fd, ret: ret, bytes: bytes, file: file}
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

func panelContentWidth(width int) int {
	// common.PanelStyle uses 1-char border on each side and 1-char horizontal
	// padding on each side: subtract 4 from total width for content.
	inner := width - 4
	if inner < 20 {
		return 20
	}
	return inner
}
