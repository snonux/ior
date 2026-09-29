package common

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Truncation markers shared by the TUI helpers below. Ellipsis is the single
// cell "…"; ASCIIEllipsis is the three-cell "..." used by the table views.
const (
	Ellipsis      = "…"
	ASCIIEllipsis = "..."
)

// The helpers in this file are the single place where TUI code shortens or
// pads text to a column budget. They all measure in terminal display cells
// (ansi.StringWidth) and cut on grapheme-cluster boundaries (ansi.Truncate /
// ansi.TruncateLeft), never on bytes or runes:
//
//   - byte slicing (s[:n]) splits multi-byte UTF-8 sequences and emits invalid
//     glyphs for any non-ASCII path or comm;
//   - rune counting treats a two-cell CJK/emoji rune as one cell and a
//     combining mark as one cell, so padded columns drift out of alignment.
//
// Because a wide rune cannot be split, a cut result can be one cell narrower
// than requested; callers needing an exact width pad afterwards (FitRight).
//
// Marker rule (tail, head or middle separator): the marker is added only when
// it is narrower than width, i.e. it leaves room for at least one content cell.
// Otherwise the text is hard-cut without a marker, because in a column of 1-3
// cells a prefix of the real text says more than a lone "...". The exception
// is when the hard cut would show nothing at all (the first grapheme is wider
// than width): then the marker is returned if it fits, so a non-empty value
// never renders as blank.
//
// These helpers do not sanitise control characters; callers pass printable
// text (see task io2 for control-character handling).

// DisplayWidth returns the number of terminal cells s occupies.
func DisplayWidth(s string) int {
	return ansi.StringWidth(s)
}

// PadRight right-pads s with spaces to width display cells. It never
// truncates: s already at least width cells wide is returned unchanged.
func PadRight(s string, width int) string {
	if pad := width - ansi.StringWidth(s); pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// FitRight returns s in exactly width display cells: truncated on the right
// with tail when too wide (see TruncateRight), then space-padded. A width of
// zero or less yields "".
func FitRight(s string, width int, tail string) string {
	if width <= 0 {
		return ""
	}
	return PadRight(TruncateRight(s, width, tail), width)
}

// TruncateRight shortens s to at most width display cells, keeping the start
// and ending in tail when anything was cut (subject to the marker rule above).
// A width of zero or less yields "".
func TruncateRight(s string, width int, tail string) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= width {
		return s
	}
	if ansi.StringWidth(tail) < width {
		return ansi.Truncate(s, width, tail)
	}
	return orMarker(ansi.Truncate(s, width, ""), tail, width)
}

// TruncateLeft shortens s to at most width display cells, keeping the end and
// starting with head when anything was cut (subject to the marker rule
// above). It suits paths, whose file name is the most useful part. A width of
// zero or less yields "".
func TruncateLeft(s string, width int, head string) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= width {
		return s
	}
	if headWidth := ansi.StringWidth(head); headWidth < width {
		return head + keepRight(s, width-headWidth)
	}
	return orMarker(keepRight(s, width), head, width)
}

// TruncateMiddle shortens s to at most width display cells, keeping both its
// start and end joined by sep when anything was cut (subject to the marker
// rule above; without room for sep it degrades to a plain right cut). The
// start gets the smaller half of the budget; when a wide rune stops the start
// short, the spare cell goes to the end. A width of zero or less yields "".
func TruncateMiddle(s string, width int, sep string) string {
	if width <= 0 {
		return ""
	}
	if ansi.StringWidth(s) <= width {
		return s
	}
	sepWidth := ansi.StringWidth(sep)
	if sepWidth >= width {
		return TruncateRight(s, width, sep)
	}
	head := ansi.Truncate(s, (width-sepWidth)/2, "")
	tailWidth := width - sepWidth - ansi.StringWidth(head)
	return head + sep + keepRight(s, tailWidth)
}

// keepRight returns the longest suffix of s that is at most width cells wide.
// ansi.TruncateLeft removes n cells but keeps a wide rune that straddles the
// cut, which would leave the result one cell too wide, so the cut is widened
// by a cell until the suffix fits (at most one retry for two-cell runes).
func keepRight(s string, width int) string {
	if width <= 0 {
		return ""
	}
	total := ansi.StringWidth(s)
	for cut := total - width; cut <= total; cut++ {
		if kept := ansi.TruncateLeft(s, cut, ""); ansi.StringWidth(kept) <= width {
			return kept
		}
	}
	return ""
}

// orMarker returns cut, or marker instead when cut is empty and marker fits
// in width, so a hard cut never blanks out a non-empty value.
func orMarker(cut, marker string, width int) string {
	if cut == "" && ansi.StringWidth(marker) <= width {
		return marker
	}
	return cut
}
