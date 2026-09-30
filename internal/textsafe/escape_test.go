package textsafe

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// osc8Payload is a file name that plants a spoofed OSC 8 hyperlink in a
// terminal that prints it raw.
const osc8Payload = "\x1b]8;;http://evil\aclick\x1b]8;;\a"

// TestEscape checks the notation for every unsafe class and that safe text
// (ASCII, CJK, emoji ZWJ sequences, contextual ZWNJ and variation selectors, backslashes) is kept verbatim.
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
		{"ZWNJ between Persian letters kept", "\u0645\u200c\u06cc", "\u0645\u200c\u06cc"},
		{"stray ZWNJ", "pass\u200cwd", `pass\u200cwd`},
		{"stray VS16", "pass\ufe0fwd", `pass\ufe0fwd`},
		{"stray VS15", "pass\ufe0ewd", `pass\ufe0ewd`},
		{"VS16 after emoji kept", "\u2764\ufe0f", "\u2764\ufe0f"},
		{"keycap kept", "1\ufe0f\u20e3", "1\ufe0f\u20e3"},
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

// openPTY opens a pseudo-terminal master, which answers the terminal ioctl
// like a real tty, skipping the test on hosts without /dev/ptmx.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal available: %v", err)
	}
	t.Cleanup(func() { _ = ptmx.Close() })
	return ptmx
}

// TestIsTerminal checks buffers, pipes and regular files are non-terminals
// and a pty is a terminal.
func TestIsTerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = f.Close() }()
	for name, out := range map[string]io.Writer{"buffer": &bytes.Buffer{}, "pipe": w, "file": f} {
		if IsTerminal(out) {
			t.Errorf("IsTerminal(%s) = true, want false", name)
		}
	}
	if !IsTerminal(openPTY(t)) {
		t.Fatal("IsTerminal(pty) = false, want true")
	}
}

// TestEscapeModeEscaper checks every mode against a non-terminal and a
// terminal writer: auto (and the unset zero value) follows the terminal,
// always escapes even into a pipe, never stays raw even on a terminal.
func TestEscapeModeEscaper(t *testing.T) {
	pty := openPTY(t)
	tests := []struct {
		mode        EscapeMode
		pipeEscapes bool
		ttyEscapes  bool
	}{
		{EscapeAuto, false, true},
		{"", false, true},
		{EscapeAlways, true, true},
		{EscapeNever, false, false},
	}
	for _, tt := range tests {
		for _, c := range []struct {
			name string
			w    io.Writer
			want bool
		}{{"pipe", &bytes.Buffer{}, tt.pipeEscapes}, {"tty", pty, tt.ttyEscapes}} {
			escape := tt.mode.Escaper(c.w)
			if (escape != nil) != c.want {
				t.Fatalf("EscapeMode(%q).Escaper(%s) escapes = %v, want %v", tt.mode, c.name, escape != nil, c.want)
			}
			if escape != nil && strings.ContainsRune(escape(osc8Payload), '\x1b') {
				t.Fatalf("EscapeMode(%q) escaper left ESC in the payload", tt.mode)
			}
		}
	}
}

// TestParseEscapeMode checks the valid names, the flag.Value round trip and
// that invalid values (wrong case, empty, unknown) are rejected.
func TestParseEscapeMode(t *testing.T) {
	for _, name := range []string{"auto", "always", "never"} {
		var m EscapeMode
		if err := m.Set(name); err != nil || m.String() != name {
			t.Fatalf("Set(%q) = %v, String() = %q", name, err, m.String())
		}
	}
	for _, bad := range []string{"", "Always", "yes", "tty"} {
		if _, err := ParseEscapeMode(bad); err == nil {
			t.Errorf("ParseEscapeMode(%q) succeeded, want error", bad)
		}
		m := EscapeAlways
		if err := m.Set(bad); err == nil || m != EscapeAlways {
			t.Errorf("Set(%q) = %v and changed the mode to %q, want error and no change", bad, err, m)
		}
	}
	// The zero value must stay "" (not "auto"): package flag compares the
	// default's String() with the zero value's String() to decide whether to
	// print "(default ...)", so "auto" here hides the default from -help.
	if got := EscapeMode("").String(); got != "" {
		t.Fatalf("zero EscapeMode String() = %q, want empty", got)
	}
	if got := EscapeAuto.String(); got != "auto" {
		t.Fatalf("EscapeAuto String() = %q, want auto", got)
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
