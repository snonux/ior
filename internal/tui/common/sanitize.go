package common

import (
	"strings"

	"ior/internal/textsafe"
)

// Placeholders used by Sanitize. Both are single-cell printable ASCII, so a
// sanitised string's display width is exactly one cell per replaced rune or
// byte and the width helpers in truncate.go keep their ASCII fast path.
const (
	// ControlPlaceholder replaces non-whitespace control runes (ESC, BEL,
	// DEL, C1 U+0080..U+009F, ...), invisible format runes (bidi controls,
	// zero-width and default-ignorable runes, see
	// textsafe.IsInvisibleFormat), a ZWJ, ZWNJ or variation selector
	// outside the context where it is visible and every byte of invalid UTF-8. '?' is used
	// rather than U+FFFD or a Control Pictures glyph such as U+241B, because
	// those are East-Asian-ambiguous or font-dependent and could render two
	// cells wide, breaking column alignment.
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
// Invisible format runes (textsafe.IsInvisibleFormat) become
// ControlPlaceholder as well: a file named "invoice\u202Efdp.exe" would
// otherwise render as "invoiceexe.pdf" (Trojan-Source style bidi spoofing),
// and zero-width or blank-rendering runes can hide text, smuggle data or
// make two different paths look identical. Replacing them with a visible
// one-cell placeholder both exposes the trick and keeps the measured width
// equal to the rendered width. Three invisible runes are context-dependent
// and kept only where they do something visible: U+200D ZWJ where it glues
// two emoji together, U+FE0E/U+FE0F directly after an emoji (or after a
// keycap base that is followed by U+20E3) and U+200C ZWNJ between two letters
// of an Arabic, Indic or similar script (textsafe.ClassAt has the rules).
// "pass\u200cwd" and "pass\ufe0fwd" therefore render as "pass?wd", not as
// "passwd". Printable non-ASCII text (CJK, emoji incl. ZWJ sequences,
// skin-tone modifiers, combining marks) is kept unchanged.
//
// Sanitize runs per cell per frame, so a clean string is returned as is
// without allocating; printable ASCII is checked byte-wise without decoding.
//
// Which runes count as unsafe is decided by the shared internal/textsafe
// package; the non-TUI outputs (-plain CSV, `ior collapsed`) escape the same
// runes with textsafe.Escape instead of replacing them.
//
// Sanitize is for terminal rendering only: exports (CSV/Parquet) must keep
// the raw values.
func Sanitize(s string) string {
	i := textsafe.FirstUnsafe(s, false)
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

// placeholderAt returns the placeholder byte Sanitize writes for the rune
// at byte offset i of s (0 when the rune is kept) and the rune's encoded
// size. The decision itself is textsafe.ClassAt, shared with the -plain CSV
// and `ior collapsed` escaper, so the TUI and the non-TUI outputs can never
// disagree about which runes are dangerous; this function only maps the
// class to the TUI's one-cell placeholder.
func placeholderAt(s string, i int) (byte, int) {
	class, size := textsafe.ClassAt(s, i)
	switch class {
	case textsafe.Whitespace:
		return WhitespacePlaceholder, size
	case textsafe.Unsafe:
		return ControlPlaceholder, size
	}
	return 0, size
}

// SanitizeLines is Sanitize for multi-line text such as error screens: line
// feeds are kept so the text keeps its intended layout, every other control
// rune, invisible format rune and invalid byte is replaced exactly as
// Sanitize does.
func SanitizeLines(s string) string {
	if textsafe.FirstUnsafe(s, true) < 0 {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = Sanitize(line)
	}
	return strings.Join(lines, "\n")
}
