package eventstream

import (
	"fmt"
	"strings"

	"ior/internal/tui/common"
)

// WarningModal shows the whole message of one warning row (task b23). The
// row itself is a single terminal line cut at its end (renderWarningRow), so
// a long warning - the boot clock one is about 390 cells - lost the advice
// in its tail at any width, and nothing else in the TUI showed it. Paused
// Enter on a warning row opens this modal instead of doing nothing; like the
// search and export modals it replaces the stream body, takes every key and
// never outgrows the view (common.PlaceModal).
//
// The message is foreign text (libbpf output, error strings quoting a path),
// so it is sanitised, but with its line feeds kept (common.SanitizeLines):
// the row has to flatten them, the modal has the rows to show a multi-line
// message as it was written. Each of its lines is wrapped at spaces to the
// box's text width, a longer word hard-wrapped by display cells
// (common.FitWrapped), so wide runes never overflow the box.
//
// A message with more lines than the view has rows is shown through a window
// that j/k, the arrows, PgUp/PgDn and g/G move, named in the title ("Warning,
// lines 1-6 of 11"); Esc, Enter and q close.
type WarningModal struct {
	visible bool
	// message is the sanitised message, lines separated by "\n".
	message string
	// offset is the first wrapped line shown; View and Update clamp it to
	// the view they are given, so a resize cannot leave it past the end.
	offset int
}

// Warning box widths, border and padding included: the box is as wide as
// the message's longest line needs, at least wide enough for its hint and
// title, and at most a comfortable line length (ModalBoxWidth then keeps it
// inside a narrower view).
const (
	warningModalMinWidth = 40
	warningModalMaxWidth = 100
)

// warningCompactChrome is the rows of the most compact box besides the
// message: the two borders, the title and the key hint.
const warningCompactChrome = 4

const (
	warningModalTitle      = "Warning"
	warningModalCloseHint  = "Esc/Enter close"
	warningModalScrollHint = "j/k scroll"
)

// Open returns the modal showing ev's message from its first line.
func (m WarningModal) Open(ev StreamEvent) WarningModal {
	message := strings.Trim(common.SanitizeLines(ev.FileName), "\n")
	return WarningModal{visible: true, message: message}
}

// Close returns the closed modal, its message dropped.
func (m WarningModal) Close() WarningModal {
	return WarningModal{}
}

// Visible reports whether the modal is open.
func (m WarningModal) Visible() bool {
	return m.visible
}

// warningFrame is the modal's geometry in one view: the box width, the
// message wrapped to the box's text width and how many of those lines the
// view has rows for.
type warningFrame struct {
	boxWidth  int
	textWidth int
	lines     []string
	rows      int
}

// maxOffset is the last offset that still fills the window.
func (f warningFrame) maxOffset() int {
	return max(len(f.lines)-f.rows, 0)
}

// frame lays the message out for a width x height view. All lines are shown
// while the most compact box (title, lines, hint) fits the height; otherwise
// the window is what that box leaves, at least one line.
func (m WarningModal) frame(width, height int) warningFrame {
	width, height = warningViewSize(width, height)
	messageLines := strings.Split(m.message, "\n")
	preferred := warningModalMinWidth
	for _, line := range messageLines {
		preferred = max(preferred, common.DisplayWidth(line)+common.ModalBoxChrome)
	}
	boxWidth := common.ModalBoxWidth(min(preferred, warningModalMaxWidth), warningModalMinWidth, width)
	f := warningFrame{boxWidth: boxWidth, textWidth: common.ModalTextWidth(boxWidth, width)}
	for _, line := range messageLines {
		f.lines = append(f.lines, common.FitWrapped(line, f.textWidth)...)
	}
	f.rows = len(f.lines)
	if f.rows+warningCompactChrome > height {
		f.rows = min(max(height-warningCompactChrome, 1), len(f.lines))
	}
	return f
}

// warningViewSize replaces an unknown (zero or negative) view size by the
// defaults the other stream modals use.
func warningViewSize(width, height int) (int, int) {
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	return width, height
}

// Update handles one key press, named as tea.KeyPressMsg.String spells it,
// in a width x height view: Esc, Enter and q close the modal (q also arrives
// as esc, re-routed by the top-level model), the row keys move the window of
// a message taller than the view, and every other key is ignored. The
// caller reports each key as consumed: the modal owns the keyboard.
func (m WarningModal) Update(keyStr string, width, height int) WarningModal {
	f := m.frame(width, height)
	page := max(f.rows-1, 1)
	switch keyStr {
	case "esc", "enter", "q":
		return m.Close()
	case "j", "down":
		m.offset++
	case "k", "up":
		m.offset--
	case "pgdown", "pgdn", "pagedown":
		m.offset += page
	case "pgup", "pageup":
		m.offset -= page
	case "g":
		m.offset = 0
	case "G":
		m.offset = f.maxOffset()
	}
	m.offset = clamp(m.offset, 0, f.maxOffset())
	return m
}

// View renders the modal centred in a width x height view and exactly that
// size. The roomiest box that fits is drawn (blank rows around the message,
// then without them); a view too small for any box gets the bare lines, the
// message before the hint before the title.
func (m WarningModal) View(width, height int) string {
	if !m.visible {
		return ""
	}
	width, height = warningViewSize(width, height)
	f := m.frame(width, height)
	offset := clamp(m.offset, 0, f.maxOffset())
	body := f.lines[offset : offset+f.rows]
	title, hint := warningModalTitle, warningModalCloseHint
	if f.rows < len(f.lines) {
		// Both additions go when the box is too narrow for them, whole
		// (FitSegments), so neither line ends in a cut word.
		window := fmt.Sprintf("lines %d-%d of %d", offset+1, offset+f.rows, len(f.lines))
		title = common.FitSegments([]string{title, window}, ", ", common.Ellipsis, f.textWidth)
		hint += common.HintSep + warningModalScrollHint
	}
	hint = common.FitHint(hint, f.textWidth)

	full := append(append([]string{title, ""}, body...), "", hint)
	compact := append(append([]string{title}, body...), hint)
	layouts := []common.ModalLayout{{Lines: full, VPad: true}, {Lines: full}, {Lines: compact}}
	return common.PlaceModal(width, height, f.boxWidth, layouts, warningBareLines(title, hint, body))
}

// warningBareLines ranks the lines of the borderless fallback: the message
// window first, then the hint that says how to leave, then the title.
func warningBareLines(title, hint string, body []string) []common.RankedLine {
	bare := []common.RankedLine{{Text: title, Rank: 2}}
	for _, line := range body {
		bare = append(bare, common.RankedLine{Text: line, Rank: 0})
	}
	return append(bare, common.RankedLine{Text: hint, Rank: 1})
}
