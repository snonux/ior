package eventstream

import (
	"fmt"
	"ior/internal/tui/common"
	"strconv"
	"strings"

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

var selectedRowStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(common.ColorBackground).
	Background(common.ColorPrimary)

var selectedCellStyle = lipgloss.NewStyle().
	Bold(true).
	Foreground(common.ColorBackground).
	Background(common.ColorAccent)

func RenderStreamTable(width int, paused bool, totalCount, filteredCount, bufferLen, bufferCap int, filter Filter, events []StreamEvent, selectedVisibleIdx int, selectedCol int) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)

	lines := make([]string, 0, len(events)+3)
	lines = append(lines, renderStatusLine(paused, totalCount, filteredCount, bufferLen, bufferCap))
	lines = append(lines, renderFilterLine(filter))
	lines = append(lines, renderColumnHeader(contentWidth))
	for i, ev := range events {
		col := -1
		if i == selectedVisibleIdx {
			col = selectedCol
		}
		lines = append(lines, renderEventRow(ev, contentWidth, i == selectedVisibleIdx, col))
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
	lines = append(lines, renderColumnHeader(contentWidth))
	for _, ev := range events {
		lines = append(lines, renderEventRow(ev, contentWidth, false, -1))
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

func renderColumnHeader(width int) string {
	cols := computeColumnLayout(width)
	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %s",
		cols.gap, "Gap",
		cols.latency, "Latency",
		cols.comm, "Comm",
		cols.pid, "PID",
		cols.tid, "TID",
		cols.syscall, "Syscall",
		cols.fd, "FD",
		cols.ret, "Ret",
		cols.bytes, "Bytes",
		"File",
	)
	return common.HelpBarStyle.Render(header)
}

func renderEventRow(ev StreamEvent, width int, selected bool, selectedCol int) string {
	cols := computeColumnLayout(width)
	fd := "-"
	if ev.FD >= 0 {
		fd = strconv.FormatInt(int64(ev.FD), 10)
	}
	cells := []string{
		fmt.Sprintf("%-*s", cols.gap, fitCell(formatDurationNs(ev.GapNs), cols.gap)),
		fmt.Sprintf("%-*s", cols.latency, fitCell(formatDurationNs(ev.DurationNs), cols.latency)),
		fmt.Sprintf("%-*s", cols.comm, fitCell(ev.Comm, cols.comm)),
		fmt.Sprintf("%-*s", cols.pid, fitCell(strconv.FormatUint(uint64(ev.PID), 10), cols.pid)),
		fmt.Sprintf("%-*s", cols.tid, fitCell(strconv.FormatUint(uint64(ev.TID), 10), cols.tid)),
		fmt.Sprintf("%-*s", cols.syscall, fitCell(ev.Syscall, cols.syscall)),
		fmt.Sprintf("%-*s", cols.fd, fitCell(fd, cols.fd)),
		fmt.Sprintf("%-*s", cols.ret, fitCell(strconv.FormatInt(ev.RetVal, 10), cols.ret)),
		fmt.Sprintf("%-*s", cols.bytes, fitCell(strconv.FormatUint(ev.Bytes, 10), cols.bytes)),
		fitCell(ev.FileName, cols.file),
	}
	if selected {
		for i := range cells {
			if i == selectedCol {
				cells[i] = selectedCellStyle.Render(cells[i])
			} else {
				cells[i] = selectedRowStyle.Render(cells[i])
			}
		}
		return strings.Join(cells, " ")
	}
	if ev.IsError {
		return common.ErrorStyle.Render(strings.Join(cells, " "))
	}
	return strings.Join(cells, " ")
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
