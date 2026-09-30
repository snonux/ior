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
	// zero-width and default-ignorable runes, see isInvisibleFormat), a ZWJ
	// outside an emoji sequence and every byte of invalid UTF-8. '?' is used
	// rather than U+FFFD or a Control Pictures glyph such as U+241B, because
	// those are East-Asian-ambiguous or font-dependent and could render two
	// cells wide, breaking column alignment.
	ControlPlaceholder = '?'
	// WhitespacePlaceholder replaces TAB, LF, VT, FF and CR, so multi-line
	// values (argv with embedded newlines, file names containing tabs)
	// flatten onto one row and stay readable instead of turning into '?'.
	WhitespacePlaceholder = ' '
)

// zeroWidthJoiner (U+200D) is kept only where it glues an emoji sequence.
const zeroWidthJoiner = '\u200d'

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
// "invoiceexe.pdf" (Trojan-Source style bidi spoofing), and zero-width or
// blank-rendering runes can hide text, smuggle data or make two different
// paths look identical. Replacing them with a visible one-cell placeholder
// both exposes the trick and keeps the measured width equal to the rendered
// width. U+200D ZWJ is kept only where it glues two emoji together (see
// joinsEmoji). Printable non-ASCII text (CJK, emoji incl. ZWJ
// sequences, U+FE0E/U+FE0F and skin-tone modifiers, combining marks) is
// kept unchanged.
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
		ph, size := placeholderAt(s, i)
		if ph != 0 {
			b.WriteByte(ph)
		} else {
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
		ph, size := placeholderAt(s, i)
		if ph != 0 {
			return i
		}
		i += size
	}
	return -1
}

// placeholderAt decodes the rune at byte offset i of s and returns the
// placeholder byte Sanitize writes for it (0 when the rune is kept) and the
// rune's encoded size. It is shared by Sanitize and firstUnsafe so the fast
// check and the rewrite can never disagree. The runes around i are looked
// up (in the original s) only for a ZWJ, so the common path pays nothing for
// that context.
func placeholderAt(s string, i int) (byte, int) {
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		return ControlPlaceholder, size
	case isWhitespaceControl(r):
		return WhitespacePlaceholder, size
	case unicode.IsControl(r) || isInvisibleFormat(r):
		return ControlPlaceholder, size
	case r == zeroWidthJoiner && !joinsEmoji(s, i, size):
		return ControlPlaceholder, size
	}
	return 0, size
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

// isInvisibleFormat reports whether r is a zero-width, blank-rendering or
// direction-changing rune that can spoof, hide or smuggle traced text. It is
// defined by class rather than by list, so new code points in these classes
// are covered when Go updates its Unicode tables:
//
//   - unicode.Cf (format): bidi controls (U+061C, U+200E/F, U+202A..202E,
//     U+2066..2069), U+00AD, U+200B, U+2060..2064 and U+206A..206F, U+FEFF,
//     U+FFF9..FFFB, prepended concatenation marks (U+0600..0605, ...) that
//     would merge with the next cell and break width exactness, and the
//     U+E0000..E007F tag block (also used by subdivision flags such as
//     England's, which therefore degrade to a black flag plus '?' cells);
//   - unicode.Variation_Selector: VS1..VS14 and the U+E0100..E01EF
//     supplement, a known channel for invisible data smuggling;
//   - unicode.Other_Default_Ignorable_Code_Point: U+034F, U+115F/1160,
//     U+17B4/17B5, U+3164, U+FFA0 (Hangul fillers render as blank cells);
//   - U+2028/U+2029 line and paragraph separators (terminals may break the
//     row on them).
//
// Exceptions: U+200C ZWNJ (needed by Persian and Indic text), U+FE0E/U+FE0F
// (text/emoji presentation, measured correctly by the width helpers) and
// U+200D ZWJ, which placeholderAt keeps or replaces depending on context.
//
// The class lookups are binary searches, so the ranges that contain none of
// these runes (Latin, Greek, Cyrillic, Hebrew, symbols, kana, CJK, Hangul
// syllables, emoji) are rejected first with plain comparisons; TestInvisibleFormatPrecheck
// verifies against the Unicode tables that those gaps really are empty.
func isInvisibleFormat(r rune) bool {
	if r < 0xAD || (r > 0xAD && r < 0x34F) || (r > 0x34F && r < 0x600) ||
		(r > 0x206F && r < 0x3164) || (r > 0x3164 && r < 0xFE00) ||
		(r >= 0x1F000 && r < 0xE0000) {
		return false
	}
	switch r {
	case 0x200C, zeroWidthJoiner, 0xFE0E, 0xFE0F:
		return false
	case 0x2028, 0x2029:
		return true
	}
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
}

// joinsEmoji reports whether the ZWJ at s[i:i+size] sits inside an emoji
// ZWJ sequence: the rune before it is an emoji glue base and the rune after
// it is an emoji (a glue base other than U+FE0F, which cannot start the next
// element). Any other ZWJ ("pass\u200Dwd", a trailing "\U0001F600\u200D",
// a ZWJ before a letter) joins nothing visible and could hide text or make
// two strings look identical, so placeholderAt replaces it. ZWJ also shapes
// some Indic and Arabic conjuncts; those render with a '?' instead, which is
// acceptable for traced paths and comm names.
func joinsEmoji(s string, i, size int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	return isEmojiGlueBase(prev) && next != 0xFE0F && isEmojiGlueBase(next)
}

// isEmojiGlueBase reports whether r may stand next to a ZWJ inside an emoji
// sequence (family, profession, rainbow flag, ...): an Extended_Pictographic
// rune, a skin-tone modifier (U+1F3FB..1F3FF) or U+FE0F. Go's unicode
// package has no Extended_Pictographic table, so the emoji blocks are
// approximated by range.
func isEmojiGlueBase(r rune) bool {
	switch {
	case r == 0xFE0F, r == 0xA9, r == 0xAE, r == 0x203C, r == 0x2049,
		r == 0x2122, r == 0x2139, r == 0x24C2, r == 0x3030, r == 0x303D,
		r == 0x3297, r == 0x3299:
		return true
	case r >= 0x2194 && r <= 0x21FF, r >= 0x2300 && r <= 0x23FF,
		r >= 0x25A0 && r <= 0x27BF, r >= 0x2934 && r <= 0x2935,
		r >= 0x2B00 && r <= 0x2BFF, r >= 0x1F000 && r <= 0x1FFFF:
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
