package eventstream

import (
	"fmt"
	"ior/internal/tui/common"
	"strconv"
	"strings"
)

type columnLayout struct {
	gap     int
	latency int
	comm    int
	pidTid  int
	syscall int
	ret     int
	bytes   int
	file    int
}

func RenderStreamTable(width int, paused bool, totalCount, filteredCount, bufferLen, bufferCap int, filter Filter, events []StreamEvent) string {
	if width <= 0 {
		width = 100
	}
	contentWidth := panelContentWidth(width)

	lines := make([]string, 0, len(events)+3)
	lines = append(lines, renderStatusLine(paused, totalCount, filteredCount, bufferLen, bufferCap))
	lines = append(lines, renderFilterLine(filter))
	lines = append(lines, renderColumnHeader(contentWidth))
	for _, ev := range events {
		lines = append(lines, renderEventRow(ev, contentWidth))
	}

	return common.PanelStyle.Width(width).Render(strings.Join(lines, "\n"))
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
	header := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %s",
		cols.gap, "Gap",
		cols.latency, "Latency",
		cols.comm, "Comm",
		cols.pidTid, "PID.TID",
		cols.syscall, "Syscall",
		cols.ret, "Ret",
		cols.bytes, "Bytes",
		"File",
	)
	return common.HelpBarStyle.Render(header)
}

func renderEventRow(ev StreamEvent, width int) string {
	cols := computeColumnLayout(width)
	pidTid := fmt.Sprintf("%d.%d", ev.PID, ev.TID)
	row := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %s",
		cols.gap, fitCell(formatDurationNs(ev.GapNs), cols.gap),
		cols.latency, fitCell(formatDurationNs(ev.DurationNs), cols.latency),
		cols.comm, fitCell(ev.Comm, cols.comm),
		cols.pidTid, fitCell(pidTid, cols.pidTid),
		cols.syscall, fitCell(ev.Syscall, cols.syscall),
		cols.ret, fitCell(strconv.FormatInt(ev.RetVal, 10), cols.ret),
		cols.bytes, fitCell(strconv.FormatUint(ev.Bytes, 10), cols.bytes),
		fitCell(ev.FileName, cols.file),
	)
	if ev.IsError {
		return common.ErrorStyle.Render(row)
	}
	return row
}

func computeColumnLayout(width int) columnLayout {
	if width <= 0 {
		width = 100
	}

	gap := 8
	latency := 9
	comm := 14
	pidTid := 12
	syscall := 11
	ret := 6
	bytes := 10
	fixed := gap + latency + comm + pidTid + syscall + ret + bytes + 7
	file := width - fixed
	if file >= 18 {
		return columnLayout{gap: gap, latency: latency, comm: comm, pidTid: pidTid, syscall: syscall, ret: ret, bytes: bytes, file: file}
	}

	if width < 90 {
		comm = 10
		syscall = 9
	} else {
		comm = 12
		syscall = 10
	}
	fixed = gap + latency + comm + pidTid + syscall + ret + bytes + 7
	file = width - fixed
	if file < 8 {
		file = 8
	}
	return columnLayout{gap: gap, latency: latency, comm: comm, pidTid: pidTid, syscall: syscall, ret: ret, bytes: bytes, file: file}
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
