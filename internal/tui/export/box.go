package export

import (
	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

const (
	// title is the modal's heading line.
	title = "Export Stream CSV"
	// hint is the key hint shown while no export is running.
	hint = "Enter confirm" + common.HintSep + "Esc cancel"

	// preferredBoxWidth and minBoxWidth are the modal's preferred box width
	// and the narrowest it is made while the view has room for it, borders
	// and padding included.
	preferredBoxWidth = 48
	minBoxWidth       = 30
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
	textWidth := boxWidth - common.ModalBoxChrome
	var box string
	for _, layout := range boxLayouts {
		box = common.RenderModalBox(m.boxLines(layout, textWidth), layout.vpad, boxWidth)
		if lipgloss.Height(box) <= height {
			break
		}
	}
	return box
}

// fitBoxWidth is the box width for a view width cells wide: the preferred
// width with a two-cell margin on each side, not narrower than minBoxWidth
// while that fits, never wider than the view, and at least one text cell
// wide (common.ModalBoxWidth).
func fitBoxWidth(width int) int {
	return common.ModalBoxWidth(preferredBoxWidth, minBoxWidth, width)
}

// boxLines is the modal's text in layout for a box textWidth cells wide:
// the title, the options with the selection marker, the paused note, the
// status message and the key hint, in sections separated by a blank line
// when layout.blanks is set. No line is wider than textWidth: each is cut
// to it except, in a wrapping layout, the note and the status, which are
// wrapped to it (fitMessage); the key hint keeps whole segments
// (common.FitHint: a narrow box drops "• Esc cancel" rather than showing
// "Esc cance").
func (m Model) boxLines(layout boxLayout, textWidth int) []string {
	var sections [][]string
	if layout.title {
		sections = append(sections, []string{common.CutLine(title, textWidth, "")})
	}
	options := make([]string, 0, len(optionLabels))
	for i, label := range optionLabels {
		prefix := "  "
		if i == m.selected && !m.exporting {
			prefix = "> "
		}
		options = append(options, common.CutLine(prefix+label, textWidth, ""))
	}
	sections = append(sections, options)
	for _, text := range m.messages(layout) {
		sections = append(sections, fitMessage(text, textWidth, layout.wrap))
	}
	if !m.exporting {
		sections = append(sections, []string{common.FitHint(hint, textWidth)})
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
// set, wrapped at whitespace only and hard-wrapped inside words still longer
// than the width (a path), by common.FitWrapped, so a path that fits a line
// is never broken at its hyphens and the " - " of PausedNote never stands on
// a line of its own; else cut to one line ending in "…". The wrapping is
// done here rather than by the box style: lipgloss's own wrap of a word
// longer than a narrow box let lines through wider than the box, which
// widened it past the view. Each line is cut to the width as well:
// common.WrapAtSpaces puts a wide rune wider than a one-cell text area (a
// 7-column view) on a line of its own two cells wide, which the cut leaves
// empty, so the box keeps to its view (TestBoxFitsItsArea's wide-rune
// cases). (export/wrap.go held the wrapping until task rz2 moved it to
// common for the other top-level modals.)
func fitMessage(text string, textWidth int, wrap bool) []string {
	if !wrap {
		return []string{common.CutLine(text, textWidth, common.Ellipsis)}
	}
	return common.FitWrapped(text, textWidth)
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
