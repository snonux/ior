package textsafe

import (
	"io"
	"strings"
	"unicode/utf8"

	xterm "github.com/charmbracelet/x/term"
)

// hexDigits renders escape sequences in lower case, matching strconv.Quote.
const hexDigits = "0123456789abcdef"

// Escape makes traced text safe to print on a terminal line while keeping
// what was replaced visible and identifiable. Every rune that is not Safe
// (see ClassAt) is rewritten in Go string-literal notation:
//
//   - C0 controls, DEL and each byte of invalid UTF-8 become \xHH
//     (ESC -> \x1b, BEL -> \x07, LF -> \x0a, raw byte 0x9b -> \x9b);
//   - other unsafe runes become \uXXXX or \UXXXXXXXX (C1 CSI -> \u009b,
//     RLO -> \u202e, stray ZWJ -> \u200d, tag rune -> \U000e0041).
//
// The notation names the exact original code point or byte, so an operator
// can tell what a file name really contains. It is not a full quoting scheme:
// a literal backslash is not doubled, so a name that already contains the
// four characters `\x1b` prints the same as one containing ESC. That keeps
// clean names byte-identical (and Escape idempotent); consumers that need
// the exact bytes read ior's piped (non-terminal) output, which is never
// escaped.
//
// Escaping only adds backslashes, letters and hex digits, none of which is a
// CSV delimiter, quote or line break, so CSV-quoting an escaped field
// afterwards still yields a valid row (and an escaped LF or CR no longer
// forces quoting at all).
//
// A clean string is returned as is without allocating, so the hot -plain
// output path pays only a byte scan per field.
func Escape(s string) string {
	i := FirstUnsafe(s, false)
	if i < 0 {
		return s
	}
	var b strings.Builder
	// Most payloads are short; escaping grows each unsafe rune to 4..10
	// bytes, so reserve a little headroom beyond the input length.
	b.Grow(len(s) + 16)
	b.WriteString(s[:i])
	for i < len(s) {
		class, size := ClassAt(s, i)
		if class == Safe {
			b.WriteString(s[i : i+size])
		} else {
			writeEscaped(&b, s[i:i+size])
		}
		i += size
	}
	return b.String()
}

// writeEscaped appends the escape notation for one unsafe rune (or one
// invalid byte) enc to b.
func writeEscaped(b *strings.Builder, enc string) {
	if len(enc) == 1 {
		// ASCII control, DEL or a lone invalid byte.
		writeHex(b, `\x`, uint32(enc[0]), 2)
		return
	}
	r, _ := utf8.DecodeRuneInString(enc)
	if r <= 0xFFFF {
		writeHex(b, `\u`, uint32(r), 4)
		return
	}
	writeHex(b, `\U`, uint32(r), 8)
}

// writeHex appends prefix followed by v as exactly digits lower-case hex
// digits.
func writeHex(b *strings.Builder, prefix string, v uint32, digits int) {
	b.WriteString(prefix)
	for shift := 4 * (digits - 1); shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(v>>uint(shift))&0xF])
	}
}

// IsTerminal reports whether w is a file descriptor attached to a terminal.
// Writers without a file descriptor (buffers, pipes wrapped in bufio, test
// recorders) are treated as non-terminals, which selects the raw,
// machine-readable output. Callers decide once per run, before writing.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(interface{ Fd() uintptr })
	return ok && xterm.IsTerminal(f.Fd())
}

// ForWriter returns Escape when w is a terminal and nil otherwise. A nil
// escaper means "write traced text raw": piped or redirected output feeds
// CSV readers and flamegraph.pl, which must see the exact original bytes.
func ForWriter(w io.Writer) func(string) string {
	if IsTerminal(w) {
		return Escape
	}
	return nil
}
