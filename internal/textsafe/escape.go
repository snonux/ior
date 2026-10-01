package textsafe

import (
	"fmt"
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
//     RLO -> \u202e, stray ZWJ -> \u200d, tag rune -> \U000e0041, no-break
//     space -> \u00a0, Braille blank -> \u2800).
//
// The notation names the exact original code point or byte, so an operator
// can tell what a file name really contains. It is not a full quoting scheme:
// a literal backslash is not doubled, so a name that already contains the
// four characters `\x1b` prints the same as one containing ESC. That keeps
// clean names byte-identical (and Escape idempotent); consumers that need
// the exact bytes read ior's piped (non-terminal) output, which is not
// escaped under the default -escape=auto (except that `ior collapsed`
// always encodes line breaks inside a frame, which are structural in its
// line-based format).
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

// EscapeMode selects when traced text is escaped for output: the value of
// the -escape flag shared by -plain and `ior collapsed`. It implements
// flag.Value, so an invalid value is rejected while the flags are parsed.
type EscapeMode string

const (
	// EscapeAuto escapes only when the writer is a terminal (the default).
	EscapeAuto EscapeMode = "auto"
	// EscapeAlways escapes regardless of the writer. Auto cannot see a
	// terminal behind a pipe, so `ior -plain | less -R`, `| grep` or
	// `| tee` still show raw bytes unless the operator asks for this.
	EscapeAlways EscapeMode = "always"
	// EscapeNever writes the exact traced bytes even to a terminal.
	EscapeNever EscapeMode = "never"
)

// ParseEscapeMode validates s as an EscapeMode.
func ParseEscapeMode(s string) (EscapeMode, error) {
	switch m := EscapeMode(s); m {
	case EscapeAuto, EscapeAlways, EscapeNever:
		return m, nil
	}
	return "", fmt.Errorf("invalid escape mode %q (valid: auto, always, never)", s)
}

// String returns the mode name. The zero value deliberately stays "" (the
// Escaper still treats it as auto): package flag decides whether to print
// "(default X)" by comparing the default's String() with the String() of the
// type's zero value, so a zero value that read "auto" made the default "auto"
// look like a zero default and hid "(default auto)" from -help.
func (m EscapeMode) String() string {
	return string(m)
}

// Set parses and stores a flag value (flag.Value).
func (m *EscapeMode) Set(s string) error {
	parsed, err := ParseEscapeMode(s)
	if err != nil {
		return err
	}
	*m = parsed
	return nil
}

// Escaper returns the escape function to apply to traced text written to w:
// Escape when the mode is always, or when it is auto (or unset) and w is a
// terminal; nil otherwise. A nil escaper means "write traced text raw", the
// right choice for CSV readers and flamegraph.pl, which must see the exact
// original bytes. Callers decide once per run, before writing.
func (m EscapeMode) Escaper(w io.Writer) func(string) string {
	switch m {
	case EscapeAlways:
		return Escape
	case EscapeNever:
		return nil
	}
	if IsTerminal(w) {
		return Escape
	}
	return nil
}
