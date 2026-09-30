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

// emojitable.go is generated from the Unicode emoji data file; see gen_emoji.go
// and the Unicode refresh notes in AGENTS.md. The path is the one Fedora and
// Debian (unicode-ucd / unicode-data) install; pass another file with -in.
//
//go:generate go run gen_emoji.go -in /usr/share/unicode/ucd/emoji/emoji-data.txt

// Class is the terminal-safety class of one rune (or invalid byte).
type Class uint8

const (
	// Safe runes are printed unchanged: printable ASCII, printable non-ASCII
	// text (CJK, emoji incl. ZWJ sequences, skin tones, combining marks) and
	// the joiners/selectors that have a visible job in their context: a
	// ZWJ inside an emoji sequence, U+FE0E/U+FE0F directly after an emoji
	// or keycap base, and a ZWNJ between two letters of a script that uses
	// it (see joinsEmoji, selectsPresentation, separatesJoiningLetters).
	Safe Class = iota
	// Whitespace runes are the control runes that only move the cursor:
	// TAB, LF, VT, FF and CR. The TUI flattens them to a space; Escape
	// escapes them like any other control so a newline in a file name
	// cannot forge an extra output row.
	Whitespace
	// Unsafe covers every other control rune (C0 incl. ESC and BEL, DEL,
	// C1 U+0080..U+009F), the invisible format runes (IsInvisibleFormat),
	// a ZWJ, ZWNJ or variation selector U+FE0E/U+FE0F outside the context
	// where it is visible and each byte of invalid UTF-8 (a raw
	// 0x9b byte is the C1 CSI introducer on 8-bit terminals).
	Unsafe
)

// The context-dependent format runes. Each is Safe only where it changes how
// a neighbouring rune renders; anywhere else it is invisible and lets a
// traced name "pass<rune>wd" look identical to "passwd".
const (
	// zeroWidthJoiner (U+200D) is Safe only where it glues an emoji sequence.
	zeroWidthJoiner = '\u200d'
	// zeroWidthNonJoiner (U+200C) is Safe only between two letters of a
	// script that uses it (Persian, Indic, ...).
	zeroWidthNonJoiner = '\u200c'
	// textPresentation (VS15) and emojiPresentation (VS16) are Safe only
	// directly after an emoji base or a keycap base followed by U+20E3.
	textPresentation  = '\ufe0e'
	emojiPresentation = '\ufe0f'
	// combiningKeycap (U+20E3) closes a keycap sequence "1\ufe0f\u20e3".
	combiningKeycap = '\u20e3'
)

// ClassAt decodes the rune at byte offset i of s and returns its class and
// its encoded size (1 for an invalid byte). The runes around i are looked up
// only for a ZWJ, ZWNJ or variation selector, so the common path pays
// nothing for that context. The decision is stable: every rune a rule accepts
// as context (emoji base, keycap base, letter or mark) is itself Safe, and
// letters or marks that ClassAt would replace (the Mongolian free variation
// selectors, Khmer U+17B4/17B5, ...) are never accepted as context, so
// classifying an already escaped string, or the output of Sanitize, again
// yields the same result; the idempotence tests cover the tricky neighbours.
//
// Trade-offs the context rules accept, because a name that an operator
// cannot tell apart from another name is worse than a lost joiner:
//
//   - ZWNJ is replaced in scripts that are not in zwnjScripts (Tibetan, Lao,
//     Thai, Balinese, Javanese, N'Ko, Adlam, Mandaic), between an Arabic
//     letter and a digit or Latin letter, and next to any other script;
//   - ZWJ is replaced outside emoji sequences, which costs the conjunct
//     shaping it does in some Indic and Arabic text;
//   - the standardized variation selectors VS1..VS14, the ideographic
//     variation selectors U+E0100..E01EF (IVS) and the Mongolian free
//     variation selectors U+180B..180D/180F are replaced, so some Japanese
//     and Mongolian names lose the glyph variant they select. They are a
//     known channel for invisible data smuggling and change no visible text
//     unless a font supports the variant;
//   - a bare digit, '#' or '*' followed by VS15/VS16 without the U+20E3 that
//     makes a keycap loses its selector (only a keycap base vouches for it),
//     which is accepted: the selector is invisible, so keeping it would again
//     let a name look identical to another one.
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
	case r == zeroWidthNonJoiner && !separatesJoiningLetters(s, i, size):
		return Unsafe, size
	case (r == textPresentation || r == emojiPresentation) && !selectsPresentation(s, i, size):
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
// (text/emoji presentation) and U+200D ZWJ. They are invisible on their own,
// so ClassAt keeps or rejects each of them depending on its neighbours
// instead of IsInvisibleFormat deciding by rune alone.
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
	case zeroWidthNonJoiner, zeroWidthJoiner, textPresentation, emojiPresentation:
		return false
	case 0x2028, 0x2029:
		return true
	}
	return unicode.In(r, unicode.Cf, unicode.Variation_Selector,
		unicode.Other_Default_Ignorable_Code_Point)
}

// joinsEmoji reports whether the ZWJ at s[i:i+size] sits inside an emoji
// ZWJ sequence: the text before it ends in an emoji base (optionally with its
// U+FE0F, as in the rainbow flag) and the rune after it is an emoji base. Any
// other ZWJ ("pass\u200dwd", "a\ufe0f\u200d\U0001F600", a trailing
// "\U0001F600\u200d", a ZWJ before a letter) joins nothing visible and could
// hide text or make two strings look identical, so ClassAt reports it
// Unsafe. ZWJ also shapes some Indic and Arabic conjuncts; those lose the
// joiner, which is acceptable for traced paths and comm names.
func joinsEmoji(s string, i, size int) bool {
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	return endsInEmoji(s[:i]) && isEmojiBase(next)
}

// endsInEmoji reports whether s ends in an emoji base, optionally followed by
// one U+FE0F. A U+FE0F after anything else does not count: it is itself
// Unsafe, and must not vouch for a ZWJ behind it.
func endsInEmoji(s string) bool {
	last, size := utf8.DecodeLastRuneInString(s)
	if last == emojiPresentation {
		last, _ = utf8.DecodeLastRuneInString(s[:len(s)-size])
	}
	return isEmojiBase(last)
}

// selectsPresentation reports whether the variation selector U+FE0E/U+FE0F at
// s[i:i+size] follows something it can change the presentation of: an emoji
// base, or a keycap base ([0-9#*]) that the selector links to a following
// U+20E3 ("1\ufe0f\u20e3"). After any other rune (a letter, another selector,
// a ZWJ) it renders nothing, yet terminals and width tables treat it as a
// zero-width or even extra cell, so "pass\ufe0fwd" would look like "passwd".
func selectsPresentation(s string, i, size int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	if isEmojiBase(prev) {
		return true
	}
	if !isKeycapBase(prev) {
		return false
	}
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	return next == combiningKeycap
}

// isKeycapBase reports whether r can start a keycap sequence.
func isKeycapBase(r rune) bool {
	return (r >= '0' && r <= '9') || r == '#' || r == '*'
}

// zwnjScripts lists the scripts whose orthography uses U+200C to break a
// cursive join (Arabic-script Persian, Urdu, Pashto, ...) or an Indic conjunct
// (after a virama), so that a ZWNJ between their letters is meaningful text.
// Scripts outside the list (Tibetan, Lao, Thai, ...) lose their ZWNJ, see
// the trade-offs in ClassAt. TestZWNJKeptBetweenScriptLetters pins every
// entry, so dropping one is noticed.
var zwnjScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Mongolian,
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada,
	unicode.Malayalam, unicode.Sinhala, unicode.Myanmar, unicode.Khmer,
}

// separatesJoiningLetters reports whether the ZWNJ at s[i:i+size] sits between
// two letters or marks of the same script from zwnjScripts. Everywhere else
// (Latin "pass\u200cwd", at the start or end of a name, next to a space or an
// emoji, between two different scripts) it draws nothing, so ClassAt reports
// it Unsafe. A local user could still plant a ZWNJ inside an Arabic-script
// name, but there it is legitimate text and identical-looking spellings of
// the same word are what the script itself allows.
func separatesJoiningLetters(s string, i, size int) bool {
	prev, _ := utf8.DecodeLastRuneInString(s[:i])
	next, _ := utf8.DecodeRuneInString(s[i+size:])
	if !isJoiningContext(prev) || !isJoiningContext(next) {
		return false
	}
	for _, script := range zwnjScripts {
		if unicode.Is(script, prev) {
			return unicode.Is(script, next)
		}
	}
	return false
}

// isJoiningContext reports whether r may stand next to a ZWNJ as the letter
// or combining mark it separates (an Indic virama is a mark). A mark that
// ClassAt itself replaces, such as the Mongolian free variation selectors or
// Khmer U+17B4/17B5, is excluded: it disappears from the text on the first
// pass, so accepting it would keep a ZWNJ that the second pass (over the
// escaped or sanitised text) rejects.
func isJoiningContext(r rune) bool {
	return (unicode.IsLetter(r) || unicode.IsMark(r)) && !IsInvisibleFormat(r)
}

// isEmojiBase reports whether r may stand next to a ZWJ or take a variation
// selector: a rune that is Extended_Pictographic, Emoji_Modifier_Base or an
// Emoji_Modifier (skin tone), see emojiBases. U+FE0F is deliberately not
// one, so a selector after a letter cannot pose as an emoji. Regional
// indicators are not either: flags never contain a ZWJ. Two Extended_Pictographic
// runes around a ZWJ are kept even where no emoji ZWJ sequence is defined for
// them, because Unicode text segmentation (UAX #29, rule GB11) also treats
// that as one grapheme cluster; the set is what keeps ordinary symbols such as
// arrows and geometric shapes out.
func isEmojiBase(r rune) bool {
	return unicode.Is(emojiBases, r)
}
