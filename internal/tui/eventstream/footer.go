package eventstream

import (
	"fmt"
	"strings"

	"ior/internal/tui/common"
)

// Footer lines sit below the stream panel, outside its border, so nothing
// else fits them to the terminal width. model.visibleRows budgets exactly one
// terminal line for each of them (the Row/Sel footer and the optional status
// message); a line wider than the view would wrap and push the panel's top
// off-screen on narrow terminals. Every footer line is therefore fitted to
// the view width here, measured in display cells (common.DisplayWidth), not
// bytes, so wide runes in status messages cannot overflow either.

// footerSep joins footer segments.
const footerSep = " | "

// footerTail marks a footer line that had to be cut mid-segment.
const footerTail = "..."

// appendStreamFooter appends the Row/Sel footer line and then the optional
// status message line to the rendered table, each fitted to width, as far
// as spare rows allow: with no spare row the table is returned as is, with
// one the status message is the line left out. On a short terminal the table
// (which keeps one event row) takes priority, and the message is transient
// anyway (the next key clears or replaces it).
func (m *Model) appendStreamFooter(base string, start, spare int) string {
	if spare < 1 {
		return base
	}
	// Use a Builder to avoid a redundant allocation for the optional status-message
	// line appended conditionally on every render call.
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("\n")
	b.WriteString(fitFooterSegments(m.streamFooterSegments(start), m.width))
	if m.statusMessage != "" && spare >= 2 {
		// The message can echo export paths, error text and search terms,
		// so it is sanitised like every other foreign string before being
		// cut to the view width (the width helpers expect sanitised input).
		b.WriteString("\n")
		b.WriteString(common.TruncateRight(common.Sanitize(m.statusMessage), m.width, footerTail))
	}
	return b.String()
}

// streamFooterSegments returns the stream footer's segments in priority
// order, because fitFooterSegments drops trailing segments first on narrow
// terminals. While paused, the selection and the "Esc/F undo" way back out
// come first and the pure "Row x/N" scroll position (also implied by Sel)
// comes last; the live footer is just the position.
func (m *Model) streamFooterSegments(start int) []string {
	total := len(m.filtered)
	row := fmt.Sprintf("Row %d/%d", rowNumber(start, total), total)
	if !m.paused || m.selectedIdx < 0 {
		return []string{row}
	}
	sel := fmt.Sprintf("Sel %d/%d Col %d/%d", rowNumber(m.selectedIdx, total), total, m.selectedCol+1, streamColumnCount)
	return []string{sel, "Esc/F undo", "Enter push-filter", "T fd-trace", row}
}

// fdTraceFooterLine renders the fd-trace view's footer fitted to width. The
// "esc:back" exit hint leads so it survives the narrowest terminals.
func fdTraceFooterLine(width, row, total int) string {
	return fitFooterSegments([]string{"esc:back", fmt.Sprintf("FD Trace Row %d/%d", row, total), "j/k:scroll"}, width)
}

// fitFooterSegments joins segments with footerSep, keeping the longest prefix
// of whole segments that fits width display cells, so narrow terminals get a
// compact footer (e.g. just "Sel x/N Col x/N | Esc/F undo") instead of hints cut
// mid-word. Only when not even the first segment fits is it truncated with
// footerTail. Segments are ior-generated (counters and fixed hints), so they
// need no sanitising. A width of zero or less yields "".
func fitFooterSegments(segments []string, width int) string {
	if len(segments) == 0 || width <= 0 {
		return ""
	}
	line := segments[0]
	used := common.DisplayWidth(line)
	if used > width {
		return common.TruncateRight(line, width, footerTail)
	}
	for _, seg := range segments[1:] {
		next := used + len(footerSep) + common.DisplayWidth(seg)
		if next > width {
			break
		}
		line += footerSep + seg
		used = next
	}
	return line
}
