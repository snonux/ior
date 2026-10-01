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
// every height from 1 up (at 1 row its top border goes, see lastLines).
//
// The hint is also cut to the width (errorScreenHintText): it is 13 columns
// ("q / esc  quit"), 21 for the recoverable one, and on a narrower terminal
// it showed past the right edge; there it keeps its start, so the first key
// stays readable down to one column. The body is wrapped by wrapErrorText
// before it is styled, so no line of the screen is wider than the terminal
// at any width from 1 up and no grapheme is split across lines. A zero width
// or height means "no size known yet": no wrap, no cut.
func (m *Model) errorScreenView(width, height int) string {
	theme := common.Current()
	hint := theme.HelpBarStyle.Render(m.errorScreenHintText(width))
	// Errors can echo traced or user-supplied paths; SanitizeLines keeps
	// intentional line breaks but no escape sequence.
	text := common.SanitizeLines(m.lastErr.Error())
	if width > 0 {
		text = wrapErrorText(text, width)
	}
	// Render styles each line on its own, so a wrapped line keeps the colour.
	body := theme.ErrorStyle.Render(text)
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

// wrapErrorText wraps the plain error text to at most width cells per line,
// measured with ansi.StringWidth (the measure lipgloss and the terminal use).
// It used to be wrapped by ErrorStyle.Width, but lipgloss splits a grapheme
// cluster at a line end ("yyyye\u0301x" at 5 put the combining accent at the
// start of the next line) and keeps a line's leading whitespace whole, so a
// row's "  - " indent stayed wider than a 1..3-column terminal. ansi.Wordwrap
// breaks at spaces and keeps clusters whole but lets a word longer than the
// width overflow; ansi.Hardwrap then breaks those (again between clusters,
// keeping leading spaces). Both count an ASCII base plus U+FE0F / U+20E3 (a
// keycap such as "1\ufe0f\u20e3") as one cell where StringWidth counts two,
// so their lines can still be too wide; splitToWidth re-measures every line
// and breaks it again (see common.TruncateRight / graphemePrefix).
//
// The text must already be sanitised (common.SanitizeLines, as
// errorScreenView does): no tab or control character, so every rune has a
// width and lipgloss's Render has no tab to expand into a wider line later.
//
// A grapheme is never split, with one harmless exception: Wordwrap breaks at
// a space even when a combining mark follows it ("x \u0301y" at 2 gives
// "x" and "\u0301y"), dropping the space as at any break and leaving the
// zero-width mark at the start of the next line, which stays within width.
// Any error text with a space before a combining mark hits this (SanitizeLines
// keeps a literal space, and turns a tab or CR into one); the mark is kept,
// only its pairing with the dropped space is lost, so it is documented
// rather than special-cased.
func wrapErrorText(text string, width int) string {
	wrapped := strings.Split(ansi.Hardwrap(ansi.Wordwrap(text, width, ""), width, true), "\n")
	lines := make([]string, 0, len(wrapped))
	for _, line := range wrapped {
		lines = append(lines, splitToWidth(line, width)...)
	}
	return strings.Join(lines, "\n")
}

// splitToWidth breaks line into pieces of at most width cells (StringWidth),
// each the longest grapheme-whole prefix that fits (common.TruncateRight
// re-measures its cut, unlike ansi.Truncate). Only a grapheme wider than the
// whole terminal (a 2-cell rune or keycap at width 1) cannot be shown and is
// dropped, so a line holding only that grapheme becomes empty. TruncateRight
// can return "" although the first grapheme fits: an orphan combining mark
// (from the space+mark break above) before a keycap at width 1 is cut by
// ansi.Truncate as one cell with the keycap, which StringWidth measures as 2.
// Such a grapheme is kept, never dropped with what follows it: a zero-width
// one leads the next piece, a wider one that fits is a piece of its own. A
// line that fits is returned as is. width must be positive: every round
// consumes at least one grapheme, so the loop ends, but at width <= 0 every
// visible grapheme would be dropped.
func splitToWidth(line string, width int) []string {
	var pieces []string
	lead := "" // zero-width graphemes waiting to lead the next piece
	for ansi.StringWidth(line) > width {
		head := common.TruncateRight(line, width, "")
		if head == "" {
			first, _ := ansi.FirstGraphemeCluster(line, ansi.GraphemeWidth)
			line = line[len(first):]
			switch w := ansi.StringWidth(first); {
			case w > width: // cannot be shown at all: dropped
				continue
			case w == 0: // a mark: it leads the next piece, not a line of its own
				lead += first
				continue
			}
			head = first // fits, though TruncateRight did not take it
		} else {
			line = line[len(head):]
		}
		pieces = append(pieces, withLead(lead, head, width)...)
		lead = ""
	}
	return append(pieces, withLead(lead, line, width)...)
}

// withLead prefixes the piece s with the zero-width lead carried by
// splitToWidth. Should the joined text measure wider than width (a lead
// merging with s into a wider cluster), lead becomes a piece of its own.
func withLead(lead, s string, width int) []string {
	if lead == "" {
		return []string{s}
	}
	if joined := lead + s; ansi.StringWidth(joined) <= width {
		return []string{joined}
	}
	return []string{lead, s}
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
