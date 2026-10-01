package internal

import (
	"fmt"
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
	// row, so a pathological program name cannot eat the line budget.
	maxVerifierPrefixBytes = 96
	// minVerifierLineBytes is the least each kept log line may be cut to,
	// even when a small limit leaves almost no budget.
	minVerifierLineBytes = 24
	// verifierLabel and verifierSep join the program name and the kept log
	// lines into one row.
	verifierLabel = " verifier: "
	verifierSep   = " | "
	// moreLinesPrefix and moreLinesSuffix frame the "... (N more lines)"
	// marker that says how much of a multi-line warning was left out.
	moreLinesPrefix = " ... ("
	moreLinesSuffix = " more lines)"
	cutEllipsis     = "..."
)

// shortenWarning turns one warning into one bounded single-line row.
//
//   - A failed program load (a message with a PROG LOAD LOG banner) becomes
//     the program name plus the verifier log's last lines, see
//     summarizeProgLoadLog: those lines are the reason, the banner alone is
//     useless.
//   - Any other multi-line message keeps its first line plus a "(N more
//     lines)" marker.
//   - A message that already carries such a marker (a row the libbpf route
//     shaped earlier) is cut in its content only, so the marker survives
//     being shortened again.
//
// limit bounds the content in bytes (cut on a rune boundary, "..." appended
// where something was cut); the marker comes on top, as do the ellipses of the
// verifier row's individual lines. Carriage returns are dropped so a CRLF log
// does not leave a stray "\r" in a row.
func shortenWarning(msg string, limit int) string {
	if row, ok := summarizeProgLoadLog(msg, limit); ok {
		return row
	}
	first, rest, multiline := strings.Cut(msg, "\n")
	first = strings.TrimRight(first, "\r")
	marker := ""
	if multiline {
		marker = fmt.Sprintf("%s%d%s", moreLinesPrefix, strings.Count(rest, "\n")+1, moreLinesSuffix)
	} else {
		first, marker = splitMoreLinesMarker(first)
	}
	return cutBytes(first, limit) + marker
}

// summarizeProgLoadLog condenses a PROG LOAD LOG warning into
//
//	<text before the banner> verifier: <last lines of the log> ... (N more lines)
//
// on ONE row, where N counts the log lines that were not kept (the marker is
// absent when all were). The kept lines share limit between them. Only the
// banner's own line contributes its prefix; anything before it in the same
// message is ignored, which never happens with libbpf (it reports the load
// failure as a separate WARN).
//
// It reports false, so the caller falls back to the generic first-line cut,
// when there is no banner or the log between the markers has no text. A
// missing END marker (a truncated message) just means the log runs to the end.
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
	lines := nonEmptyLines(body)
	if len(lines) == 0 {
		return "", false
	}
	kept := lines[max(0, len(lines)-verifierTailLines):]

	prefix = cutBytes(prefix, maxVerifierPrefixBytes)
	budget := limit - len(prefix) - len(verifierLabel) - len(verifierSep)*(len(kept)-1)
	perLine := max(budget/len(kept), minVerifierLineBytes)
	for i, line := range kept {
		kept[i] = cutBytes(line, perLine)
	}
	row := prefix + verifierLabel + strings.Join(kept, verifierSep)
	if omitted := len(lines) - len(kept); omitted > 0 {
		row += fmt.Sprintf("%s%d%s", moreLinesPrefix, omitted, moreLinesSuffix)
	}
	return strings.TrimSpace(row), true
}

// nonEmptyLines splits text into its lines with surrounding blanks (and the
// "\r" of CRLF) removed, dropping the empty ones.
func nonEmptyLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// splitMoreLinesMarker separates a trailing " ... (N more lines)" marker from
// row, so callers can shorten the content without eating the marker.
func splitMoreLinesMarker(row string) (content, marker string) {
	if !strings.HasSuffix(row, moreLinesSuffix) {
		return row, ""
	}
	at := strings.LastIndex(row, moreLinesPrefix)
	if at < 0 {
		return row, ""
	}
	count := row[at+len(moreLinesPrefix) : len(row)-len(moreLinesSuffix)]
	if count == "" || strings.Trim(count, "0123456789") != "" {
		return row, ""
	}
	return row[:at], row[at:]
}

// cutBytes limits s to limit bytes on a rune boundary and marks the cut with
// "...". Text that already ends in "..." and is at most the ellipsis longer
// than the limit is left alone: it is a row that was cut to the same limit
// before, and cutting it again would only move the dots.
func cutBytes(s string, limit int) string {
	if len(s) <= limit || (strings.HasSuffix(s, cutEllipsis) && len(s) <= limit+len(cutEllipsis)) {
		return s
	}
	cut := max(limit, 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + cutEllipsis
}
