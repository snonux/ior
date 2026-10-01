package export

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// wrapAtSpaces wraps text to lines of at most width cells, breaking only at
// spaces: words are filled greedily, and a word wider than a whole line (a
// long path) starts a line of its own and is hard-wrapped (ansi.Hardwrap,
// grapheme- and ANSI-aware), its last piece continuing the line. Runs of
// spaces collapse to one.
//
// ansi.Wordwrap and ansi.Wrap are not used because they also break after
// every '-': an export path such as ".../ior-stream-20261001-161322.csv"
// came out as ".../ior-" over "stream-...", although it fitted a line, and
// the " - " of PausedNote stood on a line of its own (task ns2).
//
// With spaces as the only breaks, the " - " of PausedNote stays at the end
// of the line before when it fits there, else it opens the next line
// followed by the word after it ("- use x ..."), which reads as the
// continuation it is; it is alone on a line only below five cells
// ("- use"). Greedy filling gives that without a rule of its own: the dash
// is a one-cell word.
//
// A wide rune wider than width (width 1) still yields a line wider than
// width; the caller cuts each line (fitMessage).
func wrapAtSpaces(text string, width int) []string {
	w := spaceWrapper{width: max(width, 1)}
	for _, word := range strings.Fields(text) {
		w.add(word)
	}
	return w.finish()
}

// spaceWrapper accumulates the lines of wrapAtSpaces.
type spaceWrapper struct {
	width int
	lines []string
	line  string
}

// fits reports whether word still fits on the current line after a space.
func (w *spaceWrapper) fits(word string) bool {
	return w.line != "" && ansi.StringWidth(w.line)+1+ansi.StringWidth(word) <= w.width
}

// add appends word to the current line, starts a new line with it, or, when
// it is wider than a whole line, hard-wraps it onto lines of its own.
func (w *spaceWrapper) add(word string) {
	switch {
	case w.fits(word):
		w.line += " " + word
		return
	case w.line != "":
		w.lines = append(w.lines, w.line)
		w.line = ""
	}
	if ansi.StringWidth(word) <= w.width {
		w.line = word
		return
	}
	pieces := strings.Split(ansi.Hardwrap(word, w.width, true), "\n")
	w.lines = append(w.lines, pieces[:len(pieces)-1]...)
	w.line = pieces[len(pieces)-1]
}

// finish returns the lines, the current one included; at least one line.
func (w *spaceWrapper) finish() []string {
	if w.line != "" || len(w.lines) == 0 {
		w.lines = append(w.lines, w.line)
	}
	return w.lines
}
