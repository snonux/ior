package eventstream

import (
	"strings"

	"ior/internal/tui/common"

	"charm.land/bubbles/v2/textinput"
	"charm.land/lipgloss/v2"
	"github.com/mattn/go-runewidth"
	"github.com/rivo/uniseg"
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

// fitModalInput sets ti to width cells and scrolls its window to start at
// rune start, or as little away from it as keeps the cursor drawn, keeping
// ti's value and cursor position. It returns the start drawn, which the
// modal keeps for its next call: the window the user last saw.
//
// textinput keeps its window in private offsets that its handleOverflow
// recomputes only when the cursor lies outside the window; SetWidth only
// stores the width. That left windows the box cannot draw (task ls2): one
// from a wider width, and one whose runes an insert, paste or delete inside
// it changed, so with two-cell runes it outgrew the box and renderModalBox
// cut the cursor off ("/検f" with an empty cursor at 10 columns), and moving
// right past its edge put the cursor over a blank mid-value (textinput then
// ends the window at the cursor, not past it). Re-anchoring on every render
// around the cursor alone fixed that but jumped: a cursor left of the value's
// last screenful pinned the window's start to it, hiding what was just typed
// mid-value. So the modal remembers the window start and modalWindowStart
// keeps it unless the cursor would not be drawn over its rune.
//
// The window is applied through textinput's public cursor moves: the cursor
// to the end rebuilds the window ending at the value's end (the cursor is on
// or past its right edge), to start (left of that window unless start is its
// start) rebuilds it starting there, and back to the cursor position, inside
// that window, leaves it. The cost is a few linear passes over the value per
// call, nothing next to rendering the box.
//
// The modals call it after every Update, from Resize (called by the stream
// Model on every size change and render) and from View on a copy, for a
// caller that skipped Resize; with the remembered start the three agree.
func fitModalInput(ti *textinput.Model, start, width int) int {
	ti.SetWidth(width)
	value, pos := []rune(ti.Value()), ti.Position()
	start = modalWindowStart(value, pos, start, width)
	ti.CursorEnd()
	ti.SetCursor(start)
	ti.SetCursor(pos)
	return start
}

// modalWindowStart is the rune index the input window of a width-cell
// textinput holding value, the cursor at pos, starts at, given the window
// started at start before: start itself while the window from there still
// draws the cursor over its rune, else the nearest start that does. The
// window moves left only to the cursor, when the cursor left it, and right
// only as far as the rune under the cursor needs to come in; it never starts
// past the tail window (the last screenful, which ends at the value's end and
// leaves room for the cursor past it). A value that fits is drawn whole.
func modalWindowStart(value []rune, pos, start, width int) int {
	if width <= 0 || uniseg.StringWidth(string(value)) <= width {
		return 0
	}
	tail := tailWindowStart(value, width)
	start = max(min(start, pos, tail), 0)
	for start < tail && pos >= headWindowEnd(value, start, width) {
		start++
	}
	return start
}

// headWindowEnd is where textinput ends a window it starts at start (its
// handleOverflow for a cursor left of the window): runes are taken while
// their cells stay within width plus one, the cursor cell modalInputWidth
// reserves.
func headWindowEnd(value []rune, start, width int) int {
	cells, end := 0, start
	for end < len(value) && cells <= width {
		cells += runewidth.RuneWidth(value[end])
		if cells <= width+1 {
			end++
		}
	}
	return end
}

// tailWindowStart is where textinput starts the window it ends at the
// value's end (its handleOverflow for a cursor right of the window): runes
// are taken back from the end while their cells stay within width, leaving
// the cursor cell past the end; as in textinput, the first rune is never
// counted (the value is wider than width when this is asked).
func tailWindowStart(value []rune, width int) int {
	cells, i := 0, len(value)-1
	for i > 0 && cells < width {
		cells += runewidth.RuneWidth(value[i])
		if cells <= width {
			i--
		}
	}
	return i + 1
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
