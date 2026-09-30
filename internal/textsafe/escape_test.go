package textsafe

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// osc8Payload is a file name that plants a spoofed OSC 8 hyperlink in a
// terminal that prints it raw.
const osc8Payload = "\x1b]8;;http://evil\aclick\x1b]8;;\a"

// TestEscape checks the notation for every unsafe class and that safe text
// (ASCII, CJK, emoji ZWJ sequences, ZWNJ, backslashes) is kept verbatim.
func TestEscape(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"OSC 8 link", osc8Payload, `\x1b]8;;http://evil\x07click\x1b]8;;\x07`},
		{"SGR hidden", "a\x1b[8mhidden\x1b[0m", `a\x1b[8mhidden\x1b[0m`},
		{"C1 CSI rune", "x\u009b31my", `x\u009b31my`},
		{"raw 0x9b byte", "x\x9b31my", `x\x9b31my`},
		{"DEL", "a\x7fb", `a\x7fb`},
		{"whitespace controls", "a\tb\nc\rd", `a\x09b\x0ac\x0dd`},
		{"invalid UTF-8", "ok\xff\xfe", `ok\xff\xfe`},
		{"RLO spoof", "invoice\u202efdp.exe", `invoice\u202efdp.exe`},
		{"stray ZWJ", "pass\u200dwd", `pass\u200dwd`},
		{"tag rune", "a\U000E0041b", `a\U000e0041b`},
		{"line separator", "a\u2028b", `a\u2028b`},
		{"emoji ZWJ sequence kept", "\U0001F468\u200d\U0001F469", "\U0001F468\u200d\U0001F469"},
		{"ZWNJ kept", "\u0645\u200c\u06cc", "\u0645\u200c\u06cc"},
		{"CJK kept", "日本語/ファイル-é", "日本語/ファイル-é"},
		{"backslash kept", `C:\dir\x`, `C:\dir\x`},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Escape(tt.in)
			if got != tt.want {
				t.Fatalf("Escape(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if FirstUnsafe(got, false) >= 0 {
				t.Fatalf("Escape(%q) = %q still contains an unsafe rune", tt.in, got)
			}
			if again := Escape(got); again != got {
				t.Fatalf("Escape is not idempotent: %q -> %q", got, again)
			}
		})
	}
}

// TestEscapeCleanStringsDoNotAllocate guards the zero-allocation fast path
// the per-event -plain output relies on.
func TestEscapeCleanStringsDoNotAllocate(t *testing.T) {
	for _, s := range []string{"/var/lib/some/file.txt", "日本語/ファイル", "\U0001F468\u200d\U0001F469"} {
		allocs := testing.AllocsPerRun(100, func() { _ = Escape(s) })
		if allocs != 0 {
			t.Fatalf("Escape(%q) allocated %.1f times, want 0", s, allocs)
		}
	}
}

// TestForWriterNonTerminal checks that writers without a terminal behind
// them (buffers, pipes, regular files) keep traced text raw.
func TestForWriterNonTerminal(t *testing.T) {
	if ForWriter(&bytes.Buffer{}) != nil {
		t.Fatal("ForWriter(bytes.Buffer) returned an escaper, want nil (raw)")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if IsTerminal(w) {
		t.Fatal("IsTerminal(pipe) = true, want false")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	if ForWriter(f) != nil {
		t.Fatal("ForWriter(regular file) returned an escaper, want nil (raw)")
	}
}

// TestForWriterTerminal opens a pseudo-terminal master, which answers the
// terminal ioctl like a real tty, and checks that it selects Escape.
func TestForWriterTerminal(t *testing.T) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	escape := ForWriter(ptmx)
	if escape == nil {
		t.Fatal("ForWriter(pty) = nil, want the Escape function")
	}
	if got := escape(osc8Payload); strings.ContainsRune(got, '\x1b') {
		t.Fatalf("escaper for a pty left ESC in %q", got)
	}
}

// BenchmarkEscapeCleanASCII measures the per-field cost on the -plain hot
// path for a typical clean path.
func BenchmarkEscapeCleanASCII(b *testing.B) {
	s := "/var/lib/postgresql/16/main/base/16384/2619_fsm"
	for b.Loop() {
		_ = Escape(s)
	}
}
