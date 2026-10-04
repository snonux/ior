package common

import (
	"charm.land/bubbles/v2/textinput"
	"github.com/mattn/go-runewidth"
	"github.com/rivo/uniseg"
)

// FitTextInput sets ti to width cells (at least one) and scrolls its window
// to start at rune start, or as little away from it as keeps the cursor
// drawn, keeping ti's value and cursor position. It returns the start drawn,
// which the modal keeps for its next call: the window the user last saw.
// The line ti.View draws is then at most width+1 cells wide (the cursor cell
// past the width), so a caller gives it its line's cells less one.
//
// textinput keeps its window in private offsets that its handleOverflow
// recomputes only when the cursor lies outside the window; SetWidth only
// stores the width. That left windows a box cannot draw (task ls2): one
// from a wider width, and one whose runes an insert, paste or delete inside
// it changed, so with two-cell runes it outgrew the box and the box's cut
// took the cursor off, and moving right past its edge put the cursor over a
// blank mid-value (textinput then ends the window at the cursor, not past
// it). Re-anchoring on every render around the cursor alone fixed that but
// jumped: a cursor left of the value's last screenful pinned the window's
// start to it, hiding what was just typed mid-value. So the modal remembers
// the window start and the window is kept unless the cursor would not be
// drawn over its rune (WindowStart).
//
// The window is applied through textinput's public cursor moves: the cursor
// to the end rebuilds the window ending at the value's end (the cursor is on
// or past its right edge), to start (left of that window unless start is its
// start) rebuilds it starting there, and back to the cursor position, inside
// that window, leaves it. The cost is a few linear passes over the value per
// call, nothing next to rendering the box.
//
// A modal calls it after every Update, from its Resize (on every size
// change) and from View on a copy, for a caller that skipped Resize; with
// the remembered start the three agree. This is the stream modals'
// fitModalInput (task ls2) made shared for the top-level filter, record and
// probes modals (task rz2).
func FitTextInput(ti *textinput.Model, start, width int) int {
	width = max(width, 1)
	ti.SetWidth(width)
	value, pos := []rune(ti.Value()), ti.Position()
	start = WindowStart(value, pos, start, width)
	ti.CursorEnd()
	ti.SetCursor(start)
	ti.SetCursor(pos)
	return start
}

// WindowStart is the rune index the input window of a width-cell textinput
// holding value, the cursor at pos, starts at, given the window started at
// start before: start itself while the window from there still draws the
// cursor over its rune, else the nearest start that does. The window moves
// left only to the cursor, when the cursor left it, and right only as far as
// the rune under the cursor needs to come in; it never starts past the tail
// window (the last screenful, which ends at the value's end and leaves room
// for the cursor past it). A value that fits is drawn whole.
func WindowStart(value []rune, pos, start, width int) int {
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
// their cells stay within width plus one, the cursor cell FitTextInput's
// callers reserve.
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

// InputView is ti.View() for a line width cells wide: the view as is when it
// fits, else the cursor alone, drawn over the rune under it (blank when that
// rune is wider than the line or the cursor is past the value's end). Only a
// one-cell line gets there when ti was fitted with FitTextInput to width-1
// cells (FitTextInput keeps at least one cell, so the window's rune and the
// cursor cell take two): the box's per-line cut would keep the rune and drop
// the cursor, so the user would no longer see where typing goes.
func InputView(ti textinput.Model, width int) string {
	view := ti.View()
	if DisplayWidth(view) <= width || !ti.Focused() {
		return view
	}
	value, pos := []rune(ti.Value()), ti.Position()
	under := ""
	if pos < len(value) && runewidth.RuneWidth(value[pos]) <= width {
		under = string(value[pos])
	}
	ti.Prompt = ""
	ti.SetWidth(1)
	ti.SetValue(under)
	ti.SetCursor(0)
	return ti.View()
}
