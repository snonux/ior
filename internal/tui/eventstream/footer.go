package eventstream

import (
	"fmt"
	"strings"

	"ior/internal/tui/common"

	"charm.land/lipgloss/v2"
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
// as spare rows allow. Row/Sel is drawn only while footerShown (help bar on,
// or paused); the status message is drawn in every state, because it is how
// a failed export or open, an invalid regex or a missed search reaches the
// user, and with the help bar off and the stream live it used to be set but
// never shown (task iz2). On a short terminal the table (which keeps one
// event row) takes priority: with no spare row the table is returned as is,
// and with exactly one the status message, when there is one, takes that row
// in place of the Row/Sel line, so it does not vanish on a 9-10 row
// terminal; Row/Sel is only lost while the message stands (the next key
// clears or replaces it) and the table still marks the selection. The
// filter-stack line above the table yields its row to the message too
// (fittingFilterStack keeps that row free before the table is drawn), so the
// message is the last line besides the table to go.
func (m *Model) appendStreamFooter(base string, start, spare int) string {
	if spare < 1 {
		return base
	}
	var lines []string
	if m.footerShown() {
		lines = append(lines, fitFooterSegments(m.streamFooterSegments(start), m.width))
	}
	if m.statusMessage != "" {
		// The message can echo export paths, error text and search terms, so
		// it is sanitised like every other foreign string before being cut
		// to the view width (the width helpers expect sanitised input).
		lines = append(lines, common.TruncateRight(common.Sanitize(m.statusMessage), m.width, footerTail))
	}
	// Keep the last lines that fit: the message is last, so it outlives
	// Row/Sel when only one row is spare.
	if len(lines) > spare {
		lines = lines[len(lines)-spare:]
	}
	if len(lines) == 0 {
		return base
	}
	return base + "\n" + strings.Join(lines, "\n")
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

// fitFooterSegments joins footer segments with footerSep to fit width
// display cells, cutting with footerTail (see common.FitSegments). Segments are
// ior-generated (counters and fixed hints), so they need no sanitising.
func fitFooterSegments(segments []string, width int) string {
	return common.FitSegments(segments, footerSep, footerTail, width)
}

// UndrawnStatusMessage returns the status message (sanitised) when the table
// leaves no spare row to draw it in, "" otherwise (task 403). A terminal at
// the Stream tab's minimum body (6 rows: the panel alone) has no row for the
// footer, so "Export failed", "Open failed", "Invalid regex" and "No match"
// would never reach the user; the dashboard shows them in the status line's
// badge slot instead, which the Stream tab leaves free. It answers from the
// same geometry View uses (renderStreamBase and the view height), without
// waiting for a frame, and says nothing while a modal or the FD trace owns the
// view: the message is not drawn there either.
func (m *Model) UndrawnStatusMessage() string {
	if m.statusMessage == "" || m.height <= 0 || m.width <= 0 || m.fdTraceView.visible ||
		m.exportModal.Visible() || m.searchModal.Visible() {
		return ""
	}
	base, _ := m.renderStreamBase(m.width)
	if m.height-lipgloss.Height(base) >= 1 {
		return ""
	}
	return common.Sanitize(m.statusMessage)
}
