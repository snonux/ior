package export

import (
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

const (
	// title is the modal's heading line.
	title = "Export Stream CSV"
	// hintSep separates the segments of the key hint.
	hintSep = " • "
	// hint is the key hint shown while no export is running.
	hint = "Enter confirm" + hintSep + "Esc cancel"

	// preferredBoxWidth and minBoxWidth are the modal's preferred box width
	// and the narrowest it is made while the view has room for it, borders
	// and padding included.
	preferredBoxWidth = 48
	minBoxWidth       = 30
	// boxChrome is the cells the box spends on its rounded border and two
	// cells of horizontal padding on each side.
	boxChrome = 2 + 2*2
)

// boxLayout is one arrangement of the modal, from roomy to compact: whether
// the box keeps a blank row of padding above and below its text (vpad),
// separates its sections by blank lines (blanks), word-wraps the paused note
// and the status message instead of cutting them to one line (wrap), and
// shows the title and the paused note.
type boxLayout struct {
	vpad, blanks, wrap, title, note bool
}

// boxLayouts lists the arrangements Box tries, roomiest first. Each sheds
// one thing more: padding, the blank separators, the wrapping, the title,
// and last the paused note (the status message outranks it: it is the
// export's result). The options and, while not exporting, the key hint are
// always shown, so the most compact box is five rows tall (six with a
// status message) inside a whole border.
var boxLayouts = []boxLayout{
	{vpad: true, blanks: true, wrap: true, title: true, note: true},
	{blanks: true, wrap: true, title: true, note: true},
	{wrap: true, title: true, note: true},
	{title: true, note: true},
	{note: true},
	{},
}

// Box renders the modal as a bare bordered box (not placed in a view) that
// fits a width x height area: it is at most width cells wide (from seven
// columns up, the narrowest box with a text cell), every line cut to the
// box rather than wrapped past it, and it takes the roomiest of boxLayouts
// that is at most height rows tall. Only an area shorter than the most
// compact layout gets a taller box, which the caller clips. Zero or negative
// sizes fall back to 80x24. Box returns "" while the modal is hidden.
//
// The dashboard draws this box over its screen (task ns2): the old View was
// a full-screen centred modal that tui.go stacked above the whole dashboard
// view, so every frame with the modal open was about twice the terminal's
// height and the status line scrolled off.
func (m Model) Box(width, height int) string {
	if !m.visible {
		return ""
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	boxWidth := fitBoxWidth(width)
	textWidth := boxWidth - boxChrome
	var box string
	for _, layout := range boxLayouts {
		box = renderBox(m.boxLines(layout, textWidth), layout.vpad, boxWidth)
		if lipgloss.Height(box) <= height {
			break
		}
	}
	return box
}

// fitBoxWidth is the box width for a view width cells wide: the preferred
// width with a two-cell margin on each side, not narrower than minBoxWidth
// while that fits, never wider than the view, and at least one text cell
// wide.
func fitBoxWidth(width int) int {
	boxWidth := max(min(preferredBoxWidth, width-4), minBoxWidth)
	return max(min(boxWidth, width), boxChrome+1)
}

// boxLines is the modal's text in layout for a box textWidth cells wide:
// the title, the options with the selection marker, the paused note, the
// status message and the key hint, in sections separated by a blank line
// when layout.blanks is set. No line is wider than textWidth: each is cut
// to it except, in a wrapping layout, the note and the status, which are
// wrapped to it (fitMessage).
func (m Model) boxLines(layout boxLayout, textWidth int) []string {
	var sections [][]string
	if layout.title {
		sections = append(sections, []string{cutLine(title, textWidth, "")})
	}
	options := make([]string, 0, len(optionLabels))
	for i, label := range optionLabels {
		prefix := "  "
		if i == m.selected && !m.exporting {
			prefix = "> "
		}
		options = append(options, cutLine(prefix+label, textWidth, ""))
	}
	sections = append(sections, options)
	for _, text := range m.messages(layout) {
		sections = append(sections, fitMessage(text, textWidth, layout.wrap))
	}
	if !m.exporting {
		sections = append(sections, []string{fitHint(hint, textWidth)})
	}
	return joinSections(sections, layout.blanks)
}

// messages is the paused note (when the stream was paused and layout shows
// it) and the status message, if any, sanitised: it echoes the export path
// and error text.
func (m Model) messages(layout boxLayout) []string {
	var out []string
	if m.livePaused && layout.note {
		out = append(out, PausedNote)
	}
	if m.status != "" {
		out = append(out, common.Sanitize(m.status))
	}
	return out
}

// fitMessage fits a note or status message to textWidth cells: when wrap is
// set, word-wrapped at spaces and then hard-wrapped inside words still
// longer than the width (a path), else cut to one line ending in "…". The
// wrapping is done here rather than by the box style: lipgloss's own wrap
// of a word longer than a narrow box let lines through wider than the box,
// which widened it past the view. (ansi.Wrap, which does both in one pass,
// drops the " - " of PausedNote when it breaks there.)
func fitMessage(text string, textWidth int, wrap bool) []string {
	if !wrap {
		return []string{cutLine(text, textWidth, common.Ellipsis)}
	}
	lines := strings.Split(ansi.Hardwrap(ansi.Wordwrap(text, textWidth, ""), textWidth, true), "\n")
	for i, line := range lines {
		lines[i] = cutLine(strings.TrimRight(line, " "), textWidth, "")
	}
	return lines
}

// joinSections flattens sections, with a blank line between two sections
// when blanks is set.
func joinSections(sections [][]string, blanks bool) []string {
	var lines []string
	for i, section := range sections {
		if blanks && i > 0 {
			lines = append(lines, "")
		}
		lines = append(lines, section...)
	}
	return lines
}

// renderBox boxes lines, none wider than the box's text width, in a rounded
// border boxWidth cells wide with two cells of horizontal padding and, with
// vpad, one blank row above and below.
func renderBox(lines []string, vpad bool, boxWidth int) string {
	vertical := 0
	if vpad {
		vertical = 1
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(vertical, 2).
		Width(boxWidth).
		Render(strings.Join(lines, "\n"))
}

// cutLine cuts line to width cells, ending in tail when cut.
func cutLine(line string, width int, tail string) string {
	if common.DisplayWidth(line) <= width {
		return line
	}
	return common.TruncateRight(line, width, tail)
}

// fitHint keeps the longest prefix of whole hintSep-separated segments of h
// that fits width cells, so a narrow box drops "• Esc cancel" rather than
// showing "Esc cance". Only when not even the first segment fits is it cut,
// ending in "…". (eventstream's fitSegments does the same for the stream
// modals; it is not exported.)
func fitHint(h string, width int) string {
	segments := strings.Split(h, hintSep)
	line := segments[0]
	if common.DisplayWidth(line) > width {
		return common.TruncateRight(line, width, common.Ellipsis)
	}
	for _, seg := range segments[1:] {
		next := line + hintSep + seg
		if common.DisplayWidth(next) > width {
			break
		}
		line = next
	}
	return line
}
