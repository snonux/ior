package tui

import (
	"fmt"
	"strings"

	common "ior/internal/tui/common"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// errorScreenView renders the full-screen error: the error text wrapped to the
// terminal width, a blank line and the key hint, fitted into width x height.
//
// The error text is the only explanation a failed trace setup gives: it
// carries up to 8 libbpf warning rows of up to 512 bytes each, which wrap
// into 50+ lines on an 80-column terminal. lipgloss.Place (placeToViewport)
// pads short content but never shortens tall content, so the end of the text
// and, worse, the hint saying how to leave used to fall off the bottom. The
// body is therefore cut to the rows left above the hint, with an explicit
// "... (N more lines)" marker, so the hint's key line stays on screen at
// every height from 1 up (at 1 row its top border goes, see lastLines). The hint is also cut to the width (errorScreenHintText): it is
// 13 columns ("q / esc  quit"), 21 for the recoverable one, and on a narrower
// terminal it showed past the right edge; there it keeps its start, so the
// first key stays readable down to one column. The wrapped body is clamped
// to the width as well (clampLinesToWidth), so no line of the screen is wider
// than the terminal at any width from 1 up. A zero width or height means "no
// size known yet": no wrap, no cut.
func (m *Model) errorScreenView(width, height int) string {
	theme := common.Current()
	hint := theme.HelpBarStyle.Render(m.errorScreenHintText(width))
	// Errors can echo traced or user-supplied paths; SanitizeLines keeps
	// intentional line breaks but no escape sequence.
	errStyle := theme.ErrorStyle
	if width > 0 {
		errStyle = errStyle.Width(width)
	}
	body := errStyle.Render(common.SanitizeLines(m.lastErr.Error()))
	if width > 0 {
		body = clampLinesToWidth(body, width)
	}
	screen := hint
	if height > 0 {
		// One row goes to the blank line between body and hint.
		body = fitErrorBody(body, height-lipgloss.Height(hint)-1, width)
	}
	if body != "" {
		screen = body + "\n\n" + hint
	}
	return placeToViewport(width, height, lastLines(theme.ScreenStyle.Render(screen), height))
}

// errorScreenHintText is the key hint cut to width display cells (ending in
// "…" when there is room for it; uncut for width <= 0, "no size known yet").
// The hint style's top border is as wide as this text, so cutting the text is
// enough to keep both hint lines within the terminal.
func (m *Model) errorScreenHintText(width int) string {
	hint := m.errorScreenHint()
	if width <= 0 {
		return hint
	}
	return common.TruncateRight(hint, width, common.Ellipsis)
}

// errorScreenHint names the keys that leave the error screen.
func (m *Model) errorScreenHint() string {
	if m.errorKind == errorScreenRecoverable {
		return "esc  back  •  q  quit"
	}
	return "q / esc  quit"
}

// clampLinesToWidth makes every line of the styled body at most width cells.
// ErrorStyle.Width wraps on words, but lipgloss keeps a line's leading
// whitespace whole, so on a terminal narrower than a warning row's "  - "
// indent plus one character that row's first line stayed wider than the
// screen. ansi.Hardwrap breaks such lines (keeping the text and the escape
// codes); a grapheme wider than the whole terminal (a 2-cell rune at width 1)
// cannot be wrapped and is cut by the ANSI-aware truncation instead.
func clampLinesToWidth(body string, width int) string {
	lines := strings.Split(ansi.Hardwrap(body, width, true), "\n")
	for i, line := range lines {
		if ansi.StringWidth(line) > width {
			lines[i] = ansi.Truncate(line, width, "")
		}
	}
	return strings.Join(lines, "\n")
}

// fitErrorBody cuts the wrapped (and styled, line by line) body to at most
// rows lines. A cut body keeps its first lines - the error itself comes
// first, the warnings after it - and ends with a "... (N more lines)" row
// counting the hidden ones, truncated to width. A cut hides at least two
// lines (the marker takes the place of one), so the plural is always right.
// No room at all yields "", leaving the screen to the hint.
func fitErrorBody(body string, rows, width int) string {
	lines := strings.Split(body, "\n")
	if len(lines) <= rows {
		return body
	}
	if rows <= 0 {
		return ""
	}
	keep := rows - 1
	marker := fmt.Sprintf("... (%d more lines)", len(lines)-keep)
	if width > 0 {
		marker = ansi.Truncate(marker, width, "")
	}
	return strings.Join(append(lines[:keep:keep], common.Current().ErrorStyle.Render(marker)), "\n")
}

// lastLines keeps the last height lines of s (all of them for height <= 0).
// It only bites on a terminal too short for the hint itself, whose top border
// is then the part that goes, so the keys stay readable.
func lastLines(s string, height int) string {
	if height <= 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= height {
		return s
	}
	return strings.Join(lines[len(lines)-height:], "\n")
}
