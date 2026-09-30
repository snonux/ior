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
// ansi.TruncateLeft, each result re-measured with StringWidth because the cut
// functions and StringWidth disagree about ASCII+U+FE0F and keycap clusters,
// see graphemePrefix and keepRight), never on bytes or runes:
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
// These helpers do not sanitise control characters themselves; callers pass
// traced or foreign text through Sanitize (sanitize.go) first, so no escape
// sequence reaches the terminal and every rune has a well-defined width.

// DisplayWidth returns the number of terminal cells s occupies.
func DisplayWidth(s string) int {
	w, _ := measure(s)
	return w
}

// PadRight right-pads s with spaces to width display cells. It never
// truncates: s already at least width cells wide is returned unchanged.
func PadRight(s string, width int) string {
	w, _ := measure(s)
	return padTo(s, w, width)
}

// FitRight returns s in exactly width display cells: truncated on the right
// with tail when too wide (see TruncateRight), then space-padded. A width of
// zero or less yields "". s is measured once; only a cut result is measured
// again (it is at most width cells, so that is cheap).
func FitRight(s string, width int, tail string) string {
	if width <= 0 {
		return ""
	}
	w, ascii := measure(s)
	if w <= width {
		return padTo(s, w, width)
	}
	return PadRight(truncateRight(s, ascii, width, tail), width)
}

// TruncateRight shortens s to at most width display cells, keeping the start
// and ending in tail when anything was cut (subject to the marker rule above).
// A width of zero or less yields "".
func TruncateRight(s string, width int, tail string) string {
	if width <= 0 {
		return ""
	}
	w, ascii := measure(s)
	if w <= width {
		return s
	}
	return truncateRight(s, ascii, width, tail)
}

// TruncateLeft shortens s to at most width display cells, keeping the end and
// starting with head when anything was cut (subject to the marker rule
// above). It suits paths, whose file name is the most useful part. A width of
// zero or less yields "".
func TruncateLeft(s string, width int, head string) string {
	if width <= 0 {
		return ""
	}
	w, ascii := measure(s)
	if w <= width {
		return s
	}
	return truncateLeft(s, w, ascii, width, head)
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
	w, ascii := measure(s)
	if w <= width {
		return s
	}
	return truncateMiddle(s, w, ascii, width, sep)
}

// measure returns the display width of s and whether s is printable ASCII
// (bytes 0x20..0x7E). Printable ASCII is the common case on the event-stream
// hot path (paths, comms, numbers): there every byte is one grapheme of one
// cell, so the width is len(s) and byte slicing is safe, which is orders of
// magnitude cheaper than ansi's grapheme segmentation. Anything else, control
// bytes included, takes the exact ansi.StringWidth path.
func measure(s string) (int, bool) {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
			if s == Ellipsis {
				return 1, false
			}
			return ansi.StringWidth(s), false
		}
	}
	return len(s), true
}

// truncateRight cuts s (known to be wider than width > 0) to at most width
// cells, applying the marker rule for tail. ascii reports whether s is
// printable ASCII, enabling byte slicing.
func truncateRight(s string, ascii bool, width int, tail string) string {
	if tw, _ := measure(tail); tw < width {
		return prefix(s, ascii, width-tw) + tail
	}
	return orMarker(prefix(s, ascii, width), tail, width)
}

// truncateLeft cuts s (total cells wide, known to exceed width > 0) keeping
// its end, applying the marker rule for head.
func truncateLeft(s string, total int, ascii bool, width int, head string) string {
	if hw, _ := measure(head); hw < width {
		return head + keepRight(s, total, ascii, width-hw)
	}
	return orMarker(keepRight(s, total, ascii, width), head, width)
}

// truncateMiddle cuts s (total cells wide, known to exceed width > 0) keeping
// both ends joined by sep.
func truncateMiddle(s string, total int, ascii bool, width int, sep string) string {
	sw, _ := measure(sep)
	if sw >= width {
		return truncateRight(s, ascii, width, sep)
	}
	headWidth := (width - sw) / 2
	head := prefix(s, ascii, headWidth)
	if !ascii {
		headWidth = ansi.StringWidth(head)
	}
	return head + sep + keepRight(s, total, ascii, width-sw-headWidth)
}

// prefix returns the longest prefix of s at most width cells wide, never
// splitting a grapheme.
func prefix(s string, ascii bool, width int) string {
	if ascii {
		return s[:min(width, len(s))]
	}
	return graphemePrefix(s, width)
}

// graphemePrefix is the non-ASCII path of prefix. ansi.Truncate does not
// agree with ansi.StringWidth about every cluster: it counts an ASCII
// base followed by U+FE0F or U+20E3 ("1\ufe0f\u20e3", "#\ufe0f\u20e3", "a\ufe0f")
// as one cell plus two zero-width pieces, while StringWidth (and so measure,
// lipgloss.Width and the terminal) counts the whole cluster as two cells.
// Trusting Truncate's budget therefore returned a prefix up to one cell per
// such cluster too wide, which overflowed padded columns and shifted every
// hit span computed from DisplayWidth. Instead the result is re-measured with
// StringWidth, the same measure every caller uses, and the Truncate budget is
// lowered until the prefix really fits. Truncate's prefix grows
// monotonically with its budget and so does the real width, so the first fit
// found going down is the longest one. Truncate is kept (rather than a
// hand-rolled grapheme walk) because it also passes ANSI sequences through
// without counting them. The loop runs only for text with miscounted clusters
// (one extra iteration per overshooting cluster); other text fits at once.
func graphemePrefix(s string, width int) string {
	for budget := width; budget > 0; budget-- {
		if cut := ansi.Truncate(s, budget, ""); ansi.StringWidth(cut) <= width {
			return cut
		}
	}
	return ""
}

// keepRight returns the longest suffix of s (total cells wide) that is at
// most width cells wide. ansi.TruncateLeft removes n cells but has two
// quirks, so its result is re-measured with StringWidth and the cut adjusted
// in both directions (the suffix width only ever shrinks as the cut grows,
// so the smallest fitting cut is the longest suffix):
//
//   - it keeps a wide rune that straddles the cut, which leaves the result
//     one cell too wide, so the cut is widened until the suffix fits (at most
//     one retry per straddled two-cell rune);
//   - like ansi.Truncate (see graphemePrefix) it counts an ASCII base plus
//     U+FE0F / U+20E3 as one cell, so it removes the whole cluster for a cut
//     of one cell and the suffix can be shorter than it could be; the cut is
//     narrowed while the longer suffix still fits.
//
// Neither direction splits a cluster, so no orphaned U+FE0F or U+20E3 is left
// at the start of the result.
func keepRight(s string, total int, ascii bool, width int) string {
	if width <= 0 {
		return ""
	}
	if ascii {
		return s[max(len(s)-width, 0):]
	}
	cut := max(total-width, 0)
	kept := ansi.TruncateLeft(s, cut, "")
	if ansi.StringWidth(kept) <= width {
		return widenSuffix(s, kept, cut, width)
	}
	for cut++; cut <= total; cut++ {
		if kept = ansi.TruncateLeft(s, cut, ""); ansi.StringWidth(kept) <= width {
			return kept
		}
	}
	return ""
}

// widenSuffix lowers the cut of an already fitting suffix (kept = s cut by
// cut cells) while the longer suffix still fits width. It runs one probe for
// text without miscounted clusters and stops there.
func widenSuffix(s, kept string, cut, width int) string {
	for ; cut > 0; cut-- {
		longer := ansi.TruncateLeft(s, cut-1, "")
		if ansi.StringWidth(longer) > width {
			break
		}
		kept = longer
	}
	return kept
}

// padTo right-pads s, which is w cells wide, with spaces to width cells.
func padTo(s string, w, width int) string {
	if pad := width - w; pad > 0 {
		return s + strings.Repeat(" ", pad)
	}
	return s
}

// orMarker returns cut, or marker instead when cut is empty and marker fits
// in width, so a hard cut never blanks out a non-empty value.
func orMarker(cut, marker string, width int) string {
	if mw, _ := measure(marker); cut == "" && mw <= width {
		return marker
	}
	return cut
}
