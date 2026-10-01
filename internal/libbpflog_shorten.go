package internal

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	// progLoadLogBegin and progLoadLogEnd delimit the verifier log in libbpf's
	// failed-program-load WARN (bpf_object__load_progs in libbpf.c):
	//
	//	prog 'x': -- BEGIN PROG LOAD LOG --\n<log>-- END PROG LOAD LOG --\n
	//
	// It is ONE message, so by the time a row is built the banner is the
	// first line and the verifier's actual reason is at the very end.
	progLoadLogBegin = "-- BEGIN PROG LOAD LOG --"
	progLoadLogEnd   = "-- END PROG LOAD LOG --"
	// verifierTailLines is how many non-empty lines of the log are kept. The
	// verifier prints the offending instruction, the reason ("R1 invalid mem
	// access 'scalar'") and its "processed N insns" statistics last, so the
	// tail answers "why was the program rejected" while the 100s of lines
	// before it are the per-instruction state dump.
	verifierTailLines = 3
	// maxVerifierPrefixBytes bounds the "libbpf: prog 'name':" part of the
	// row (ellipsis included), so a pathological program name cannot eat the
	// line budget. A limit below four times this shrinks it to a quarter of
	// the limit.
	maxVerifierPrefixBytes = 96
	// verifierLabel and verifierSep join the program name and the kept log
	// lines into one row; verifierEmptyLog stands in for a log without text.
	verifierLabel    = " verifier: "
	verifierSep      = " | "
	verifierEmptyLog = "(empty log)"
	// moreLinesPrefix and moreLinesSuffix frame the "... (N more lines)"
	// marker that says how much of a multi-line warning was left out;
	// moreLineSuffix is the singular form, used when exactly one was.
	moreLinesPrefix = " ... ("
	moreLinesSuffix = " more lines)"
	moreLineSuffix  = " more line)"
	cutEllipsis     = "..."
)

// shortenWarning turns one warning into one single-line row of at most limit
// bytes - marker and "..." ellipses included, before any escaping.
//
//   - A failed program load (a message with a PROG LOAD LOG banner) becomes
//     the program name plus the verifier log's last lines, see
//     summarizeProgLoadLog: those lines are the reason, the banner alone is
//     useless.
//   - Any other multi-line message keeps its first line plus a "(N more
//     lines)" marker counting the non-blank lines it left out.
//   - A message that already carries such a marker (a row the libbpf route
//     shaped earlier) is cut in its content only, so the marker survives
//     being shortened again.
//
// Because every result is a single line within limit, and such a line is
// returned unchanged, shortening is idempotent: shortenWarning(
// shortenWarning(x, n), n) == shortenWarning(x, n). That is what lets
// explainFailure re-shorten a routed row with the same bound without cutting
// it twice. Carriage returns are dropped so a CRLF log does not leave a stray
// "\r" in a row.
//
// The fixed-point argument: a second pass sees one line (so no PROG LOAD LOG
// body follows a banner), trims a trailing "\r", splits off a marker and
// rejoins it, and returns the row unchanged when it fits. The one thing that
// pass changes is a trailing "\r", so the result never ends in one: a cut
// below 3 bytes has no ellipsis and can stop right after a "\r" from the
// middle of a line ("a\rb" at limit 2 was "a\r", then "a" on the second pass).
func shortenWarning(msg string, limit int) string {
	return strings.TrimRight(shapeWarning(msg, limit), "\r")
}

// shapeWarning is shortenWarning before its final trailing "\r" trim: the
// verifier summary for a PROG LOAD LOG, else the first line plus marker.
func shapeWarning(msg string, limit int) string {
	if row, ok := summarizeProgLoadLog(msg, limit); ok {
		return row
	}
	first, rest, multiline := strings.Cut(msg, "\n")
	first = strings.TrimRight(first, "\r")
	marker := ""
	if multiline {
		marker = moreLinesMarker(countNonBlankLines(rest))
	} else {
		first, marker = splitMoreLinesMarker(first)
	}
	return fitWithMarker(first, marker, limit)
}

// fitWithMarker joins content and marker into at most limit bytes, cutting the
// content only. When the limit cannot even hold the marker plus an ellipsis
// the whole row is cut instead (degenerate limits; production uses 512).
func fitWithMarker(content, marker string, limit int) string {
	if len(content)+len(marker) <= limit {
		return content + marker
	}
	if len(marker)+len(cutEllipsis) > limit {
		return cutBytes(content+marker, limit)
	}
	return cutBytes(content, limit-len(marker)) + marker
}

// moreLinesMarker renders the " ... (N more lines)" marker, " ... (1 more
// line)" for a single one, and nothing for zero.
func moreLinesMarker(omitted int) string {
	switch {
	case omitted <= 0:
		return ""
	case omitted == 1:
		return moreLinesPrefix + "1" + moreLineSuffix
	}
	return fmt.Sprintf("%s%d%s", moreLinesPrefix, omitted, moreLinesSuffix)
}

// summarizeProgLoadLog condenses a PROG LOAD LOG warning into
//
//	<text before the banner> verifier: <last lines of the log> ... (N more lines)
//
// on ONE row of at most limit bytes, where N counts the non-blank log lines
// that were not kept (the marker is absent when all were). A log without any
// text becomes "verifier: (empty log)". Only the banner's own line
// contributes its prefix; anything before it in the same message is ignored,
// which never happens with libbpf (it reports the load failure as a separate
// WARN).
//
// It reports false, so the caller falls back to the generic first-line cut,
// when there is no banner or nothing follows the banner's line. A missing END
// marker (a truncated message) just means the log runs to the end.
//
// This runs under the libbpf logger's mutex and the log can be megabytes, so
// the kept lines are found by scanning backwards from the END marker and the
// omitted ones are only counted, never split into a slice.
func summarizeProgLoadLog(msg string, limit int) (string, bool) {
	begin := strings.Index(msg, progLoadLogBegin)
	if begin < 0 {
		return "", false
	}
	prefix := strings.TrimSpace(msg[strings.LastIndex(msg[:begin], "\n")+1 : begin])
	_, body, hasBody := strings.Cut(msg[begin:], "\n")
	if !hasBody {
		return "", false
	}
	if end := strings.LastIndex(body, progLoadLogEnd); end >= 0 {
		body = body[:end]
	}
	kept, head := lastNonBlankLines(body, verifierTailLines)
	if len(kept) == 0 {
		return verifierRow(prefix, []string{verifierEmptyLog}, 0, limit), true
	}
	return verifierRow(prefix, kept, countNonBlankLines(head), limit), true
}

// verifierRow assembles the verifier row within limit: the prefix is capped
// first, then the kept lines share what is left after the fixed parts (label,
// separators, marker), see fairShares. A limit too small for even that is
// handled by a final hard cut, which may cost the marker.
func verifierRow(prefix string, kept []string, omitted, limit int) string {
	prefix = cutBytes(prefix, min(maxVerifierPrefixBytes, limit/4))
	marker := moreLinesMarker(omitted)
	budget := limit - len(prefix) - len(verifierLabel) - len(verifierSep)*(len(kept)-1) - len(marker)
	lengths := make([]int, len(kept))
	for i, line := range kept {
		lengths[i] = len(line)
	}
	for i, share := range fairShares(lengths, budget) {
		kept[i] = cutBytes(kept[i], share)
	}
	row := strings.TrimSpace(prefix+verifierLabel+strings.Join(kept, verifierSep)) + marker
	return cutBytes(row, limit)
}

// fairShares splits budget bytes between lines of the given lengths by
// max-min fairness: a line that fits its equal share keeps its real length
// and leaves the rest to the others, so one 166-byte reason between two short
// lines is not cut while the row has room. Lines are served shortest first
// and, among equal lengths, earliest first; the integer-division remainder
// therefore lands on the longest lines and, on a tie, the later ones - the
// end of the log, where the verifier puts its reason. The shares never sum to
// more than budget (none is negative).
func fairShares(lengths []int, budget int) []int {
	order := make([]int, len(lengths))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return lengths[a] - lengths[b] })
	shares := make([]int, len(lengths))
	remaining := max(budget, 0)
	for served, i := range order {
		share := remaining / (len(order) - served)
		shares[i] = min(lengths[i], share)
		remaining -= shares[i]
	}
	return shares
}

// lastNonBlankLines returns up to n of text's last non-blank lines in their
// original order, trimmed (which also drops CRLF's "\r"), plus the text that
// precedes them. It scans backwards and allocates only the kept lines.
func lastNonBlankLines(text string, n int) (kept []string, head string) {
	for len(kept) < n && text != "" {
		nl := strings.LastIndexByte(text, '\n')
		line := strings.TrimSpace(text[nl+1:])
		text = text[:max(nl, 0)]
		if line != "" {
			kept = append(kept, line)
		}
	}
	slices.Reverse(kept)
	return kept, text
}

// countNonBlankLines counts text's lines that hold more than whitespace,
// without allocating, so a "(N more lines)" marker counts no blank line.
func countNonBlankLines(text string) int {
	count := 0
	for text != "" {
		var line string
		line, text, _ = strings.Cut(text, "\n")
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

// splitMoreLinesMarker separates a trailing " ... (N more lines)" (or "... (1
// more line)") marker from row, so callers can shorten the content without
// eating the marker. Recognised are the singular with a count of 1 and the
// plural with any other run of digits: every form moreLinesMarker renders,
// plus counts it never renders (0, 007), which only a warning's own text can
// hold; such a marker is kept whole too, which is harmless and idempotent.
func splitMoreLinesMarker(row string) (content, marker string) {
	suffix := moreLinesSuffix
	if strings.HasSuffix(row, moreLineSuffix) {
		suffix = moreLineSuffix
	} else if !strings.HasSuffix(row, moreLinesSuffix) {
		return row, ""
	}
	at := strings.LastIndex(row, moreLinesPrefix)
	if at < 0 {
		return row, ""
	}
	count := row[at+len(moreLinesPrefix) : len(row)-len(suffix)]
	if count == "" || strings.Trim(count, "0123456789") != "" || (count == "1") != (suffix == moreLineSuffix) {
		return row, ""
	}
	return row[:at], row[at:]
}

// cutBytes limits s to at most limit bytes, the "..." that marks a cut
// included; a limit too small for the ellipsis cuts without one, and a limit
// of zero or less yields "" (checked first: runeCut indexes s at the cut, so
// it must never see an empty s or a negative cut). Text within the limit is
// returned unchanged, so cutting is idempotent.
func cutBytes(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	if limit < len(cutEllipsis) {
		return s[:runeCut(s, limit)]
	}
	return s[:runeCut(s, limit-len(cutEllipsis))] + cutEllipsis
}

// runeCut moves cut (0 <= cut < len(s)) back to the start of the rune it
// would split; cutBytes guarantees that range.
// It looks back at most utf8.UTFMax-1 bytes, the most a valid rune can
// straddle: past that the bytes are not valid UTF-8, nothing can be split,
// and stepping further would throw away content - a run of 600 stray
// continuation bytes used to be cut down to nothing but "...".
func runeCut(s string, cut int) int {
	for i := cut; i >= 0 && i > cut-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			return i
		}
	}
	return cut
}
