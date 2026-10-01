package eventstream

import (
	"strings"

	"ior/internal/tui/common"

	"charm.land/lipgloss/v2"
)

// modalForm is the content of a stream input modal (search, export): a title,
// a label above the input line, the input line itself, an optional error and
// the key hint.
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
// (a "/" prefix) and the cursor cell textinput draws past its width.
func modalInputWidth(boxWidth, reserved int) int {
	return max(boxWidth-modalBoxChrome-reserved-1, 1)
}

// renderModal draws form as a bordered box centred in a width x height view.
// The box never outgrows the view: it is at most width cells wide (every line
// cut to the box's text width rather than wrapped), and when the full layout
// is taller than height it sheds, in order, the vertical padding, the blank
// separator lines, the label and the title, so down to five rows (four
// without an error) the input line and the key hint stay on screen inside a
// whole border. Only a shorter view clips the box, which the dashboard never
// asks for: the Stream tab is drawn from six body rows (streamTableMinRows).
func renderModal(form modalForm, size modalSize, width, height int) string {
	boxWidth := modalBoxWidth(size, width)
	textWidth := boxWidth - modalBoxChrome
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
