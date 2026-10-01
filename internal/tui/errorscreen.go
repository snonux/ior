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
// "... (N more lines)" marker; the hint always stays on screen. A zero width
// or height means "no size known yet": no wrap, no cut.
func (m *Model) errorScreenView(width, height int) string {
	theme := common.Current()
	hint := theme.HelpBarStyle.Render(m.errorScreenHint())
	// Errors can echo traced or user-supplied paths; SanitizeLines keeps
	// intentional line breaks but no escape sequence.
	errStyle := theme.ErrorStyle
	if width > 0 {
		errStyle = errStyle.Width(width)
	}
	body := errStyle.Render(common.SanitizeLines(m.lastErr.Error()))
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

// errorScreenHint names the keys that leave the error screen.
func (m *Model) errorScreenHint() string {
	if m.errorKind == errorScreenRecoverable {
		return "esc  back  •  q  quit"
	}
	return "q / esc  quit"
}

// fitErrorBody cuts the wrapped (and styled, line by line) body to at most
// rows lines. A cut body keeps its first lines - the error itself comes
// first, the warnings after it - and ends with a "... (N more lines)" row
// counting the hidden ones, truncated to width. No room at all yields "",
// leaving the screen to the hint.
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
