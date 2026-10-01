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

// cutProbeHook, when non-nil, is called once per ansi.Truncate or
// ansi.TruncateLeft call made by the searches below. It is nil in production
// and exists only so tests can bound the number of full-string cuts
// deterministically (a wall-clock bound would be flaky).
var cutProbeHook func()

// truncateProbe is ansi.Truncate without a tail, counted for cutProbeHook.
func truncateProbe(s string, budget int) string {
	if cutProbeHook != nil {
		cutProbeHook()
	}
	return ansi.Truncate(s, budget, "")
}

// truncateLeftProbe is ansi.TruncateLeft without a prefix, counted for
// cutProbeHook.
func truncateLeftProbe(s string, cut int) string {
	if cutProbeHook != nil {
		cutProbeHook()
	}
	return ansi.TruncateLeft(s, cut, "")
}

// graphemePrefix is the non-ASCII path of prefix. ansi.Truncate does not
// agree with ansi.StringWidth about every cluster: it counts an ASCII base
// followed by U+FE0F or U+20E3 ("1\ufe0f\u20e3", "#\ufe0f\u20e3", "a\ufe0f")
// as a single cell (the cluster is kept whole, never split), while
// StringWidth (and so measure, lipgloss.Width and the terminal) counts the
// whole cluster as two cells. Trusting Truncate's budget therefore returned a
// prefix up to one cell per such cluster too wide, which overflowed padded
// columns and shifted every hit span computed from DisplayWidth. Instead the
// result is re-measured with StringWidth, the same measure every caller uses,
// and the Truncate budget is lowered until the prefix really fits.
//
// Truncate's prefix grows monotonically with its budget and so does its real
// width, hence the largest fitting budget yields the longest fitting prefix.
// The budget is never above width (a prefix's real width is at least what
// Truncate counted), and budget 0 yields "", so the largest fitting budget is
// found by binary search over [0, width]. A walk down from width, one cell at
// a time, cost one full-string Truncate+StringWidth per step, which for a
// long run of keycaps (real width twice the counted width) added up to
// O(width * len(s)); the search needs O(log(width)) probes. Text without
// miscounted clusters fits on the first probe. Truncate is kept (rather than a
// hand-rolled grapheme walk) because it also passes ANSI sequences through
// without counting them.
func graphemePrefix(s string, width int) string {
	best := truncateProbe(s, width)
	if ansi.StringWidth(best) <= width {
		return best
	}
	// Invariant: budget lo fits (lo = 0 yields ""), budget hi (> lo) does not.
	lo, hi := 0, width
	best = ""
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if cut := truncateProbe(s, mid); ansi.StringWidth(cut) <= width {
			lo, best = mid, cut
		} else {
			hi = mid
		}
	}
	return best
}

// keepRight returns the longest suffix of s (total cells wide) that is at
// most width cells wide. ansi.TruncateLeft removes n cells but has two
// quirks, so its result is re-measured with StringWidth and the cut adjusted
// in both directions. The suffix width only ever shrinks as the cut grows, so
// the smallest fitting cut is the longest suffix:
//
//   - it keeps a wide rune that straddles the cut, which leaves the result
//     one cell too wide, so the cut is widened until the suffix fits (at most
//     one retry per straddled two-cell rune);
//   - like ansi.Truncate (see graphemePrefix) it counts an ASCII base plus
//     U+FE0F / U+20E3 as one cell, so a cut of n "cells" removes up to 2n real
//     cells and the suffix can be shorter than it could be (or, since
//     total-width counts real cells, the cut can overshoot the end of s
//     altogether); the cut is narrowed while the longer suffix still fits.
//
// total-width is the right first guess for text without miscounted clusters,
// and one neighbour probe settles it. When the guess is wrong the distance to
// the answer can be as large as the number of miscounted clusters (about half
// the string for a long run of keycaps), so the smallest fitting cut is then
// found by binary search over the remaining range. Stepping one cell at a
// time re-cut the whole string per step and made a 4KB keycap path cost tens
// of milliseconds per call. Neither direction splits a cluster, so no orphaned
// U+FE0F or U+20E3 is left at the start of the result.
func keepRight(s string, total int, ascii bool, width int) string {
	if width <= 0 {
		return ""
	}
	if ascii {
		return s[max(len(s)-width, 0):]
	}
	guess := max(total-width, 0)
	kept := truncateLeftProbe(s, guess)
	if ansi.StringWidth(kept) <= width {
		return narrowCut(s, kept, guess, width)
	}
	return widenCut(s, guess, total, width)
}

// narrowCut lowers the cut of an already fitting suffix (kept = s cut by cut
// cells) to the smallest cut whose suffix still fits width. One probe settles
// text without miscounted clusters; otherwise the smallest fitting cut in
// [0, cut) is found by binary search.
func narrowCut(s, kept string, cut, width int) string {
	if cut == 0 {
		return kept
	}
	longer := truncateLeftProbe(s, cut-1)
	if ansi.StringWidth(longer) > width {
		return kept
	}
	kept = longer
	// Invariant: cut hi fits (kept is its suffix), cut lo-1 may or may not.
	lo, hi := 0, cut-1
	for lo < hi {
		mid := lo + (hi-lo)/2
		if cand := truncateLeftProbe(s, mid); ansi.StringWidth(cand) <= width {
			hi, kept = mid, cand
		} else {
			lo = mid + 1
		}
	}
	return kept
}

// widenCut finds the smallest cut above guess (which left a suffix wider than
// width) whose suffix fits, by trying guess+1 first (a straddled two-cell rune
// needs exactly one more cell) and binary searching up to total, where the
// suffix is empty. It returns "" if even that does not fit.
func widenCut(s string, guess, total, width int) string {
	if guess >= total {
		return ""
	}
	kept := truncateLeftProbe(s, guess+1)
	if ansi.StringWidth(kept) <= width {
		return kept
	}
	// Invariant: cut lo does not fit, cut hi is the smallest candidate that
	// might (total always does: it leaves at most the empty suffix).
	lo, hi := guess+1, total
	kept = ""
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if cand := truncateLeftProbe(s, mid); ansi.StringWidth(cand) <= width {
			hi, kept = mid, cand
		} else {
			lo = mid
		}
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

// orMarker returns cut, or marker instead when cut shows nothing and marker
// fits in width, so a hard cut never blanks out a non-empty value. A cut that
// holds only ANSI sequences (the cut kept the escapes around a cluster too
// wide to keep) shows nothing as well, so it is replaced the same way; the
// escape scan is skipped for escape-free cuts.
func orMarker(cut, marker string, width int) string {
	if mw, _ := measure(marker); mw <= width && showsNothing(cut) {
		return marker
	}
	return cut
}

// showsNothing reports whether cut renders no cell: it is empty or consists of
// ANSI sequences only.
func showsNothing(cut string) bool {
	return cut == "" || (strings.IndexByte(cut, 0x1b) >= 0 && ansi.StringWidth(cut) == 0)
}
