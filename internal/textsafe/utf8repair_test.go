package textsafe

import (
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/types"
)

// checkRepair runs one repair function over a table case and checks the
// properties every repair must have besides the expected value: the result is
// valid UTF-8, and repairing it again changes nothing (so a value read back
// from a data file and written again is stored identically).
func checkRepair(t *testing.T, name string, fn func(string) string, in, want string) {
	t.Helper()
	got := fn(in)
	if got != want {
		t.Fatalf("%s(len %d %q) = %q, want %q", name, len(in), tail(in), tail(got), tail(want))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("%s(len %d) = %q is not valid UTF-8", name, len(in), tail(got))
	}
	if again := fn(got); again != got {
		t.Fatalf("%s is not idempotent: second pass gave %q, first %q", name, tail(again), tail(got))
	}
}

// tail returns the last few bytes of s for compact failure messages, since
// the capture-limit cases are 255 bytes long.
func tail(s string) string {
	if len(s) > 12 {
		return "..." + s[len(s)-12:]
	}
	return s
}

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ascii", "/tmp/file", "/tmp/file"},
		{"valid multibyte kept", "/tmp/äö/日本語/😀", "/tmp/äö/日本語/😀"},
		{"valid controls kept", "a\tb\nc\x00\x1b", "a\tb\nc\x00\x1b"},
		{"literal backslash-x text kept", `a\xffb`, `a\xffb`},
		{"lone high byte", "f\xff\xfeinv", `f\xff\xfeinv`},
		// SanitizeUTF8 alone never trims: a cut rune is escaped. The trim is
		// SanitizeComm's/SanitizePath's job.
		{"truncated rune", "abc\xc3", `abc\xc3`},
		{"only an invalid byte", "\xff", `\xff`},
		{"stray continuation", "\x80x", `\x80x`},
		{"overlong encoding", "\xc0\xaf", `\xc0\xaf`},
		{"utf-16 surrogate", "\xed\xa0\x80", `\xed\xa0\x80`},
		{"above U+10FFFF", "\xf4\x90\x80\x80", `\xf4\x90\x80\x80`},
		{"valid runes around invalid byte", "ä\xffö", `ä\xffö`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRepair(t, "SanitizeUTF8", SanitizeUTF8, tt.in, tt.want)
		})
	}
}

// TestSanitizeUTF8DoesNotAllocateForValidText pins the fast path: almost
// every traced string is valid, so the hot recording path must not pay for
// the rare invalid one.
func TestSanitizeUTF8DoesNotAllocateForValidText(t *testing.T) {
	const s = "/var/log/ünïcode/access.log"
	if allocs := testing.AllocsPerRun(100, func() { _ = SanitizeUTF8(s) }); allocs != 0 {
		t.Fatalf("SanitizeUTF8 allocated %v times for valid text, want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = SanitizePath(s) }); allocs != 0 {
		t.Fatalf("SanitizePath allocated %v times for valid text, want 0", allocs)
	}
}

// TestSanitizeUTF8UsesEscapeNotation pins that the \xHH form is exactly what
// Escape produces for every possible invalid byte, so the data-file repair
// and the -plain/collapsed notation cannot drift apart.
func TestSanitizeUTF8UsesEscapeNotation(t *testing.T) {
	for b := 0x80; b <= 0xff; b++ {
		in := string([]byte{byte(b)})
		if utf8.ValidString(in) {
			continue
		}
		if got, want := SanitizeUTF8(in), Escape(in); got != want {
			t.Fatalf("byte 0x%02x: SanitizeUTF8 = %q, Escape = %q", b, got, want)
		}
	}
}

func TestSanitizeComm(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ascii", "kworker/0:1", "kworker/0:1"},
		{"valid multibyte kept", "日本語", "日本語"},
		// The kernel's 15-byte cut of ten "ä": seven complete runes plus the
		// lead byte of the eighth, which is dropped, not escaped.
		{"kernel cut mid-rune", "äääääää\xc3", "äääääää"},
		{"cut three-byte rune at the limit", "abc日本語本\xe8\xaa", "abc日本語本"},
		// prctl(PR_SET_NAME) accepts arbitrary bytes: a mid-string invalid
		// byte is real data and is escaped.
		{"mid-string invalid byte", "a\xffb", `a\xffb`},
		{"cut and invalid byte together", "a\xffä\xc3", `a\xffä`},
		{"trailing invalid non-lead byte escaped", "ab\xff", `ab\xff`},
		{"only a partial rune", "\xc3", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkRepair(t, "SanitizeComm", SanitizeComm, tt.in, tt.want)
		})
	}
}

// capturedPath builds a path of exactly n bytes ending in tail: "/" plus
// filler of the two-byte rune ä, padded with ASCII 'x' so the total is n.
func capturedPath(n int, tail string) string {
	base := "/" + strings.Repeat("ä", (n-1-len(tail))/2)
	for len(base)+len(tail) < n {
		base += "x"
	}
	return base + tail
}

func TestSanitizePath(t *testing.T) {
	const limit = types.MAX_FILENAME_LENGTH - 1
	if maxCapturedPath != limit {
		t.Fatalf("maxCapturedPath = %d, want MAX_FILENAME_LENGTH-1 = %d", maxCapturedPath, limit)
	}
	// Exactly the BPF capture limit, cut inside "ä": the partial rune is
	// the kernel-side cut and is dropped, like comm's.
	full := capturedPath(limit-1, "") + "\xc3"
	cut3 := capturedPath(limit, "\xe6\x97")     // 3-byte rune cut after 2 bytes
	cut4 := capturedPath(limit, "\xf0\x9f\x98") // 4-byte rune cut after 3 bytes
	whole3 := capturedPath(limit, "日")          // complete 3-byte rune ending at the limit
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"valid", "/tmp/ü", "/tmp/ü"},
		{"ascii path at the limit", capturedPath(limit, "x"), capturedPath(limit, "x")},
		{"limit-length path cut mid-rune", full, full[:len(full)-1]},
		{"limit-length path cut inside a three-byte rune", cut3, cut3[:len(cut3)-2]},
		{"limit-length path cut inside a four-byte rune", cut4, cut4[:len(cut4)-3]},
		{"limit-length path ending in a complete two-byte rune", capturedPath(limit, "ä"), capturedPath(limit, "ä")},
		{"limit-length path ending in a complete three-byte rune", whole3, whole3},
		{"limit-length path with mid-string invalid byte keeps the escape", "\xff" + full[1:len(full)-1] + "\xe6", `\xff` + full[1:len(full)-1]},
		// 0xff can start no sequence, so it is not a cut and is escaped even
		// at the limit.
		{"limit-length path ending in an invalid non-lead byte", capturedPath(limit, "\xff"), capturedPath(limit, "\xff")[:limit-1] + `\xff`},
		// Shorter or longer than the limit nothing was cut, so an invalid
		// trailing byte is corrupt data (a real name) and is escaped, not
		// trimmed.
		{"one byte short of the limit", capturedPath(limit-1, "\xc3"), capturedPath(limit-1, "\xc3")[:limit-2] + `\xc3`},
		{"one byte over the limit", capturedPath(limit+1, "\xc3"), capturedPath(limit+1, "\xc3")[:limit] + `\xc3`},
		{"short path ending in a lone lead byte is escaped", "/tmp/x\xe6", `/tmp/x\xe6`},
		{"short path mid-string invalid byte", "f\xff\xfeinv", `f\xff\xfeinv`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.in != "" && strings.Contains(tt.name, "limit-length") && len(tt.in) != limit {
				t.Fatalf("test input length = %d, want %d", len(tt.in), limit)
			}
			checkRepair(t, "SanitizePath", SanitizePath, tt.in, tt.want)
		})
	}
}

// TestSanitizePathTrimsTruncatedGetcwdPath covers the getcwd form: a path
// longer than the captured field is reported as the captured prefix plus
// types.TruncatedPathSuffix, so the byte-wise cut sits in front of the suffix.
func TestSanitizePathTrimsTruncatedGetcwdPath(t *testing.T) {
	prefix := capturedPath(maxCapturedPath-1, "") + "\xc3"
	in := prefix + types.TruncatedPathSuffix
	checkRepair(t, "SanitizePath", SanitizePath, in, prefix[:len(prefix)-1]+types.TruncatedPathSuffix)

	// The getcwd length with a complete rune in front of the suffix is
	// already valid and kept.
	valid := capturedPath(maxCapturedPath, "ä") + types.TruncatedPathSuffix
	checkRepair(t, "SanitizePath", SanitizePath, valid, valid)

	// A "..." suffix on a path of any other length is ordinary text.
	checkRepair(t, "SanitizePath", SanitizePath, "/tmp/\xc3...", `/tmp/\xc3...`)

	// The getcwd length without the "..." suffix is not the getcwd form, so
	// its trailing partial rune is real data and escaped.
	noDots := capturedPath(maxCapturedPath+len(types.TruncatedPathSuffix), "\xc3")
	checkRepair(t, "SanitizePath", SanitizePath, noDots, noDots[:len(noDots)-1]+`\xc3`)

	// Longer than the getcwd form (255+3 bytes) is not a captured prefix any
	// more (e.g. a real name that merely ends in dots), so nothing is trimmed:
	// the partial rune is escaped like any other invalid byte.
	long := capturedPath(types.MAX_FILENAME_LENGTH+10, "") + "\xc3" + types.TruncatedPathSuffix
	checkRepair(t, "SanitizePath", SanitizePath, long, long[:len(long)-4]+`\xc3`+types.TruncatedPathSuffix)
}

// TestTruncatedPathSuffixLiteral pins the value the docs and AGENTS.md
// promise for an over-long getcwd path.
func TestTruncatedPathSuffixLiteral(t *testing.T) {
	if types.TruncatedPathSuffix != "..." {
		t.Fatalf("types.TruncatedPathSuffix = %q, want %q", types.TruncatedPathSuffix, "...")
	}
}
