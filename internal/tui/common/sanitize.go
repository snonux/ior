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
	// DEL, C1 U+0080..U+009F, ...), invisible format runes (bidi controls,
	// zero-width characters, see isInvisibleFormat) and every byte of
	// invalid UTF-8. '?' is
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
// interpreted as the C1 CSI introducer by 8-bit terminals.
//
// Invisible format runes (isInvisibleFormat) become ControlPlaceholder as
// well: a file named "invoice\u202Efdp.exe" would otherwise render as
// "invoiceexe.pdf" (Trojan-Source style bidi spoofing), and zero-width runes
// can hide text or make two different paths look identical. Replacing them
// with a visible one-cell placeholder both exposes the trick and keeps the
// measured width equal to the rendered width. Printable non-ASCII text (CJK,
// emoji incl. ZWJ sequences, variation selectors and skin-tone modifiers,
// combining marks) is kept unchanged.
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
		case unicode.IsControl(r) || isInvisibleFormat(r):
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
		if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) || isInvisibleFormat(r) {
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

// isInvisibleFormat reports whether r is a zero-width or direction-changing
// format rune that can spoof or hide traced text:
//
//   - bidi controls: U+061C ALM, U+200E/U+200F LRM/RLM, U+202A..U+202E
//     embeddings and overrides, U+2066..U+2069 isolates;
//   - U+2028/U+2029 line and paragraph separators (terminals may break the
//     row on them);
//   - U+00AD soft hyphen, U+200B zero-width space, U+FEFF BOM/ZWNBSP,
//     U+FFF9..U+FFFB interlinear annotation marks and the U+E0000..U+E007F
//     tag block (also used by subdivision flags such as England's, which
//     therefore degrade to a black flag followed by '?' cells).
//
// U+200D ZWJ, U+FE0E/U+FE0F variation selectors and U+1F3FB..U+1F3FF skin
// tones are deliberately not listed: they glue emoji sequences together and
// the width helpers measure those sequences as one grapheme cluster.
//
// Every listed rune is >= U+00AD, so the common non-ASCII range below it
// (Latin-1 letters) is rejected with a single comparison.
func isInvisibleFormat(r rune) bool {
	switch {
	case r < 0xAD:
		return false
	case r == 0xAD, r == 0x061C, r == 0x200B, r == 0x200E, r == 0x200F, r == 0xFEFF:
		return true
	case r >= 0x2028 && r <= 0x202E: // U+2028/2029 separators, U+202A..202E bidi
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0xFFF9 && r <= 0xFFFB:
		return true
	case r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return false
}

// SanitizeLines is Sanitize for multi-line text such as error screens: line
// feeds are kept so the text keeps its intended layout, every other control
// rune, invisible format rune and invalid byte is replaced exactly as
// Sanitize does.
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
