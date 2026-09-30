// Package textsafe classifies the runes of traced, attacker-controlled text
// (paths, comm names, other users' argv, flamegraph frames) by whether a
// terminal could misinterpret them, and escapes the unsafe ones for
// line-oriented terminal output.
//
// A local unprivileged user can name a file
// "\x1b]8;;http://evil\x07click\x1b]8;;\x07" to plant a spoofed OSC 8 link,
// hide text with SGR "\x1b[8m", or reorder a name with a bidi override.
// Whatever ior prints to a root operator's terminal must therefore go through
// one of two consumers of the classification below:
//
//   - internal/tui/common.Sanitize replaces unsafe runes with a one-cell
//     placeholder, because the TUI needs exact column widths;
//   - Escape (this package) rewrites them in a visible Go-style escape
//     notation for the -plain CSV rows and `ior collapsed` output.
//
// Keeping the classification in this single non-TUI package means the two
// renderings can never disagree about what is dangerous.
package textsafe

import (
	"unicode"
	"unicode/utf8"
)

// Class is the terminal-safety class of one rune (or invalid byte).
type Class uint8

const (
	// Safe runes are printed unchanged: printable ASCII, printable non-ASCII
	// text (CJK, emoji incl. ZWJ sequences, U+FE0E/U+FE0F, skin tones,
	// combining marks) and ZWNJ.
	Safe Class = iota
	// Whitespace runes are the control runes that only move the cursor:
	// TAB, LF, VT, FF and CR. The TUI flattens them to a space; Escape
	// escapes them like any other control so a newline in a file name
	// cannot forge an extra output row.
	Whitespace
	// Unsafe covers every other control rune (C0 incl. ESC and BEL, DEL,
	// C1 U+0080..U+009F), the invisible format runes (IsInvisibleFormat),
	// a ZWJ outside an emoji sequence and each byte of invalid UTF-8 (a raw
	// 0x9b byte is the C1 CSI introducer on 8-bit terminals).
	Unsafe
)

// zeroWidthJoiner (U+200D) is Safe only where it glues an emoji sequence.
const zeroWidthJoiner = '\u200d'

// ClassAt decodes the rune at byte offset i of s and returns its class and
// its encoded size (1 for an invalid byte). The runes around i are looked up
// only for a ZWJ, so the common path pays nothing for that context.
func ClassAt(s string, i int) (Class, int) {
	c := s[i]
	if c >= 0x20 && c < 0x7f {
		return Safe, 1
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	switch {
	case r == utf8.RuneError && size == 1:
		return Unsafe, size
	case isWhitespaceControl(r):
		return Whitespace, size
	case unicode.IsControl(r) || IsInvisibleFormat(r):
		return Unsafe, size
	case r == zeroWidthJoiner && !joinsEmoji(s, i, size):
		return Unsafe, size
	}
	return Safe, size
}

// FirstUnsafe returns the byte offset of the first rune in s that is not
// Safe, or -1 when every rune is Safe. keepLF additionally treats '\n' as
// safe, for renderers that keep line breaks. Printable ASCII bytes are
// skipped without UTF-8 decoding, so the check for a clean string is cheap
// and never allocates; callers use it as their fast path.
func FirstUnsafe(s string, keepLF bool) int {
	for i := 0; i < len(s); {
		c := s[i]
		if (c >= 0x20 && c < 0x7f) || (keepLF && c == '\n') {
			i++
			continue
		}
		if c < 0x80 {
			return i // C0 control or DEL
		}
		class, size := ClassAt(s, i)
		if class != Safe {
			return i
		}
		i += size
	}
	return -1
}

// isWhitespaceControl reports whether r is a control rune that only moves
// the cursor (TAB, LF, VT, FF, CR).
func isWhitespaceControl(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

// IsInvisibleFormat reports whether r is a zero-width, blank-rendering or
// direction-changing rune that can spoof, hide or smuggle traced text. A
// file named "invoice\u202efdp.exe" would otherwise render as
// "invoiceexe.pdf" (Trojan-Source style bidi spoofing). It is defined by
// class rather than by list, so new code points in these classes are covered
// when Go updates its Unicode tables:
//
//   - unicode.Cf (format): bidi controls (U+061C, U+200E/F, U+202A..202E,
//     U+2066..2069), U+00AD, U+200B, U+2060..2064 and U+206A..206F, U+FEFF,
//     U+FFF9..FFFB, prepended concatenation marks (U+0600..0605, ...) that
//     would merge with the next cell and break width exactness, and the
//     U+E0000..E007F tag block (also used by subdivision flags such as
//     England's, which therefore degrade);
//   - unicode.Variation_Selector: VS1..VS14 and the U+E0100..E01EF
//     supplement, a known channel for invisible data smuggling;
//   - unicode.Other_Default_Ignorable_Code_Point: U+034F, U+115F/1160,
//     U+17B4/17B5, U+3164, U+FFA0 (Hangul fillers render as blank cells);
//   - U+2028/U+2029 line and paragraph separators (terminals may break the
//     row on them).
//
// Exceptions: U+200C ZWNJ (needed by Persian and Indic text), U+FE0E/U+FE0F
// (text/emoji presentation, measured correctly by the TUI width helpers) and
// U+200D ZWJ, which ClassAt keeps or rejects depending on context.
//
// The class lookups are binary searches, so the ranges that contain none of
// these runes (Latin, Greek, Cyrillic, Hebrew, symbols, kana, CJK, Hangul
// syllables, emoji) are rejected first with plain comparisons;
// TestInvisibleFormatMatchesClasses verifies against the Unicode tables that
// those gaps really are empty.
func IsInvisibleFormat(r rune) bool {
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
// element). Any other ZWJ ("pass\u200dwd", a trailing "\U0001F600\u200d",
// a ZWJ before a letter) joins nothing visible and could hide text or make
// two strings look identical, so ClassAt reports it Unsafe. ZWJ also shapes
// some Indic and Arabic conjuncts; those lose the joiner, which is acceptable
// for traced paths and comm names.
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
