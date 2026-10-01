package export

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// wrapAtSpaces wraps text to lines of at most width cells, breaking only at
// whitespace (strings.Fields: any Unicode white space, so a tab or a no-break
// space is a break point too): words are filled greedily, and a word wider
// than a whole line (a long path) starts a line of its own and is
// hard-wrapped (ansi.Hardwrap, grapheme- and ANSI-aware), its last piece
// continuing the line. Runs of whitespace collapse to one plain space.
//
// ansi.Wordwrap and ansi.Wrap are not used because they also break after
// every '-': an export path such as ".../ior-stream-20261001-161322.csv"
// came out as ".../ior-" over "stream-...", although it fitted a line, and
// the " - " of PausedNote stood on a line of its own (task ns2).
//
// With whitespace as the only break, the " - " of PausedNote stays at the end
// of the line before when it fits there, else it opens the next line
// followed by the word after it ("- use x ..."), which reads as the
// continuation it is; it is alone on a line only below five cells
// ("- use"). Greedy filling gives that without a rule of its own: the dash
// is a one-cell word.
//
// A wide rune wider than width (width 1) still comes out on a line of its
// own, wider than width. ansi.Hardwrap puts out an empty line before such a
// rune when it opens the word ("日本" gives "\n日\n本"); add drops that
// empty piece. The caller cuts each line to the width (fitMessage), which
// leaves the rune's line empty: in a one-cell text area (a 7-column view) a
// wide rune shows as a blank row rather than widening the box.
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
	pieces := hardwrapPieces(word, w.width)
	w.lines = append(w.lines, pieces[:len(pieces)-1]...)
	w.line = pieces[len(pieces)-1]
}

// hardwrapPieces hard-wraps word, which is wider than width, into its lines,
// without the empty line ansi.Hardwrap puts out before a leading rune wider
// than width (width 1 and a wide rune); word is not empty, so neither is
// the result.
func hardwrapPieces(word string, width int) []string {
	pieces := strings.Split(ansi.Hardwrap(word, width, true), "\n")
	if len(pieces) > 1 && pieces[0] == "" {
		pieces = pieces[1:]
	}
	return pieces
}

// finish returns the lines, the current one included; at least one line.
func (w *spaceWrapper) finish() []string {
	if w.line != "" || len(w.lines) == 0 {
		w.lines = append(w.lines, w.line)
	}
	return w.lines
}
