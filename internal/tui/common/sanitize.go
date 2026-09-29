package common

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Placeholders used by Sanitize. Both are single-cell printable ASCII, so a
// sanitised string's display width is exactly one cell per replaced rune or
// byte and the width helpers in truncate.go keep their ASCII fast path.
const (
	// ControlPlaceholder replaces non-whitespace control runes (ESC, BEL,
	// DEL, C1 U+0080..U+009F, ...) and every byte of invalid UTF-8. '?' is
	// used rather than U+FFFD or a Control Pictures glyph such as U+241B,
	// because those are East-Asian-ambiguous or font-dependent and could
	// render two cells wide, breaking column alignment.
	ControlPlaceholder = '?'
	// WhitespacePlaceholder replaces TAB, LF, VT, FF and CR, so multi-line
	// values (argv with embedded newlines, file names containing tabs)
	// flatten onto one row and stay readable instead of turning into '?'.
	WhitespacePlaceholder = ' '
)

// Sanitize makes a traced or otherwise foreign string safe to write to the
// terminal. Paths, comm names, other users' argv and flamegraph frame names
// are attacker-controlled: a local unprivileged user can name a file
// "\x1b]8;;http://evil\x07click\x1b]8;;\x07" and plant a spoofed OSC 8 link,
// or hide text with SGR "\x1b[8m", in a root operator's TUI. Bubble Tea
// passes such sequences through, so every such string must go through
// Sanitize before it is rendered.
//
// Every rune for which unicode.IsControl reports true (C0 incl. ESC, DEL and
// C1 U+0080..U+009F) is replaced: whitespace controls by
// WhitespacePlaceholder, all others by ControlPlaceholder. Each byte of
// invalid UTF-8 becomes ControlPlaceholder too, because a raw 0x9b byte is
// interpreted as the C1 CSI introducer by 8-bit terminals. Printable
// non-ASCII text (CJK, emoji, combining marks) is kept unchanged.
//
// Sanitize runs per cell per frame, so a clean string is returned as is
// without allocating; printable ASCII is checked byte-wise without decoding.
//
// Sanitize is for terminal rendering only: exports (CSV/Parquet) must keep
// the raw values.
func Sanitize(s string) string {
	i := firstUnsafe(s, false)
	if i < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	b.WriteString(s[:i])
	for i < len(s) {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteByte(ControlPlaceholder)
		case isWhitespaceControl(r):
			b.WriteByte(WhitespacePlaceholder)
		case unicode.IsControl(r):
			b.WriteByte(ControlPlaceholder)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// firstUnsafe returns the byte offset of the first rune Sanitize would
// replace, or -1 when s is already safe. keepLF treats '\n' as safe (for
// SanitizeLines). Printable ASCII bytes are skipped without UTF-8 decoding,
// which keeps the common case cheap.
func firstUnsafe(s string, keepLF bool) int {
	for i := 0; i < len(s); {
		c := s[i]
		if (c >= 0x20 && c < 0x7f) || (keepLF && c == '\n') {
			i++
			continue
		}
		if c < 0x80 {
			return i // C0 control or DEL
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) {
			return i
		}
		i += size
	}
	return -1
}

// isWhitespaceControl reports whether r is a control rune that only moves
// the cursor (TAB, LF, VT, FF, CR) and is therefore shown as a space.
func isWhitespaceControl(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// SanitizeLines is Sanitize for multi-line text such as error screens: line
// feeds are kept so the text keeps its intended layout, every other control
// rune and invalid byte is replaced exactly as Sanitize does.
func SanitizeLines(s string) string {
	if firstUnsafe(s, true) < 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = Sanitize(line)
	}
	return strings.Join(lines, "\n")
}
