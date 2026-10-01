package eventstream

import (
	"strings"

	"ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
)

// modalForm is the content of a stream input modal (search, export): a title,
// a label above the input line, the input line itself, an optional error and
// the key hint, whose segments are joined by modalHintSep.
type modalForm struct {
	title, label, input, err, hint string
}

// modalSize is a modal's preferred and smallest box width in cells, borders
// and padding included.
type modalSize struct {
	preferred, min int
}

// modalBoxChrome is the cells a modal box spends on its rounded border and
// two cells of horizontal padding on each side.
const modalBoxChrome = 2 + 2*2

// modalBoxWidth is the box width of a modal in a view width cells wide: the
// preferred width with a two-cell margin on each side, not narrower than the
// modal's minimum while that fits, but never wider than the view (from seven
// columns up, the narrowest box with a text cell). A wider box soft-wraps
// every line in the terminal and pushes the dashboard status line off the
// bottom (task ls2).
func modalBoxWidth(size modalSize, width int) int {
	boxWidth := max(min(size.preferred, width-4), size.min)
	return max(min(boxWidth, width), modalBoxChrome+1)
}

// modalInputWidth is the text-input width that keeps the input line of a box
// boxWidth cells wide on one row: the box's text width less reserved cells
// (a "/" prefix) and the cursor cell textinput draws past its width (or the
// extra rune its window holds when it starts at the cursor). It is at least
// one cell, so a box with fewer than reserved+2 text cells (views under 8
// columns for export, 9 for search) or a wide rune in reserved+2 cells
// cannot show the typed text and the cursor together, and the line is cut.
func modalInputWidth(boxWidth, reserved int) int {
	return max(boxWidth-modalBoxChrome-reserved-1, 1)
}

// fitModalInput sets ti to width cells and re-anchors its scroll window
// around the cursor, keeping its value and cursor position.
//
// textinput keeps the window of the value it draws (and so where the cursor
// sits in it) in private offsets that its handleOverflow recomputes only
// when the cursor lies outside the window; SetWidth only stores the width.
// Two cases left a window the box cannot draw (task ls2): a window left
// from a wider width, and an insert, paste or delete inside the window,
// after which the window is not recomputed even though its runes changed.
// With two-cell runes that window can outgrow width plus the cursor cell,
// and renderModalBox, which cuts every line to the box, cut the cursor off
// (e.g. "/検f" with an empty cursor at 10 columns); with ASCII, moving right
// past the window could leave the cursor over a blank mid-value.
//
// So the window is recomputed on every call: the cursor is moved to the end
// (always outside or on the window's right edge, so the window is rebuilt
// ending at the value's end) and back to its position (rebuilt starting at
// the cursor if it lies left of that window). Either way the window then
// fits width, plus the cursor cell modalInputWidth reserves, and holds the
// cursor. The cost is two linear passes over the value per call, nothing
// next to rendering the box. The window thus always either ends at the
// value's end or starts at the cursor, rather than scrolling minimally.
//
// The modals keep their stored width in step with the view (Resize, called
// by the stream Model on every size change and render) so Update scrolls
// with the real width; their View calls it as well, on a copy, so the
// window drawn is re-anchored after every edit, and for a caller that
// skipped Resize.
func fitModalInput(ti *textinput.Model, width int) {
	ti.SetWidth(width)
	pos := ti.Position()
	ti.CursorEnd()
	ti.SetCursor(pos)
}

// renderModal draws form as a bordered box centred in a width x height view.
// The box never outgrows the view: it is at most width cells wide (every line
// cut to the box's text width rather than wrapped), and when the full layout
// is taller than height it sheds, in order, the vertical padding, the blank
// separator lines, the label and the title, so down to five rows (four
// without an error) the input line and the key hint stay on screen inside a
// whole border. Only a shorter view clips the box, which the dashboard never
// asks for: the Stream tab is drawn from six body rows (streamTableMinRows).
// The key hint is fitted by whole segments (fitModalHint) rather than cut,
// so a narrow box drops "• Esc cancel" instead of showing "Esc cance".
func renderModal(form modalForm, size modalSize, width, height int) string {
	boxWidth := modalBoxWidth(size, width)
	textWidth := boxWidth - modalBoxChrome
	form.hint = fitModalHint(form.hint, textWidth)
	var box string
	for _, layout := range modalLayouts(form) {
		box = renderModalBox(layout.lines, layout.vpad, boxWidth, textWidth)
		if lipgloss.Height(box) <= height {
			break
		}
	}
	return clipModal(lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box), height)
}

// modalLayout is one candidate arrangement of a modal: its lines and whether
// the box keeps one blank row of padding above and below them.
type modalLayout struct {
	lines []string
	vpad  bool
}

// modalLayouts lists form's arrangements from the roomiest to the most
// compact; renderModal takes the first one that fits the view height.
func modalLayouts(form modalForm) []modalLayout {
	withErr := func(lines ...string) []string {
		if form.err == "" {
			return lines
		}
		return append(lines[:len(lines):len(lines)], "Error: "+common.Sanitize(form.err))
	}
	full := append(withErr(form.title, "", form.label, form.input), "", form.hint)
	compact := append(withErr(form.title, form.label, form.input), form.hint)
	return []modalLayout{
		{lines: full, vpad: true},
		{lines: full},
		{lines: compact},
		{lines: append(withErr(form.title, form.input), form.hint)},
		{lines: append(withErr(form.input), form.hint)},
	}
}

// modalHintSep separates the segments of a modal's key hint.
const modalHintSep = " • "

// fitModalHint fits a key hint to textWidth cells by whole segments
// (fitSegments): trailing segments are dropped first, and only when not even
// the first one fits is it cut, ending in "…", so the hint never shows a
// word cut without a marker (except in a one-cell box, where common's marker
// rule keeps the first letter). The hints are ior-generated literals.
func fitModalHint(hint string, textWidth int) string {
	return fitSegments(strings.Split(hint, modalHintSep), modalHintSep, common.Ellipsis, textWidth)
}

// renderModalBox boxes lines, each cut to textWidth cells, in a rounded
// border boxWidth cells wide with two cells of horizontal padding.
func renderModalBox(lines []string, vpad bool, boxWidth, textWidth int) string {
	cut := make([]string, len(lines))
	for i, line := range lines {
		cut[i] = line
		if lipgloss.Width(line) > textWidth {
			cut[i] = common.TruncateRight(line, textWidth, "")
		}
	}
	vertical := 0
	if vpad {
		vertical = 1
	}
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(vertical, 2).
		Width(boxWidth).
		Render(strings.Join(cut, "\n"))
}

// clipModal keeps the first height lines of a placed modal, the last resort
// for a view shorter than the most compact layout.
func clipModal(s string, height int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= height {
		return s
	}
	return strings.Join(lines[:max(height, 0)], "\n")
}
