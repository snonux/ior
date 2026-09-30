package common

import (
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2"
)

// Attacker-controlled payloads used by the sanitiser tests: a spoofed OSC 8
// hyperlink, SGR hidden text, a raw C1 CSI byte (0x9b), a C1 CSI rune
// (U+009B), DEL and cursor-moving whitespace.
const (
	osc8Payload   = "\x1b]8;;http://evil\aclick\x1b]8;;\a"
	sgrHidden     = "a\x1b[8mhidden\x1b[0m"
	rawCSI        = "x\x9b31my"
	c1CSIRune     = "x\u009b31my"
	delPayload    = "a\x7fb"
	argvNewlines  = "sh -c\necho hi\r\n\tdone"
	unterminated  = "abc\x1b["
	invalidUTF8   = "ok\xff\xfe"
	cleanNonASCII = "日本語/ファイル-é"
	// rloSpoof renders as "invoiceexe.pdf" without sanitising: U+202E
	// (RLO) reverses the rest of the line (Trojan-Source style).
	rloSpoof = "invoice\u202efdp.exe"
	// cleanEmoji holds sequences whose glue runes must survive: a ZWJ family,
	// a skin-tone modifier, text/emoji variation selectors and a regional-
	// indicator flag.
	cleanEmoji = "\U0001F468\u200D\U0001F469\u200D\U0001F467 \U0001F44D\U0001F3FD \u2764\uFE0F \u2603\uFE0E \U0001F1E9\U0001F1EA"
)

// invisibleFormatCases lists one payload per neutralised rune class and the
// expected sanitised output.
var invisibleFormatCases = []struct{ name, in, want string }{
	{"RLO spoof", rloSpoof, "invoice?fdp.exe"},
	{"bidi embeddings LRE..RLO", "a\u202a\u202b\u202c\u202d\u202eb", "a?????b"},
	{"bidi isolates LRI..PDI", "a\u2066\u2067\u2068\u2069b", "a????b"},
	{"LRM RLM ALM", "a\u200e\u200f\u061cb", "a???b"},
	{"line and paragraph separators", "a\u2028b\u2029c", "a?b?c"},
	{"zero-width space", "pass\u200bwd", "pass?wd"},
	{"BOM", "\ufeffname", "?name"},
	{"soft hyphen", "ab\u00adc", "ab?c"},
	{"interlinear annotations", "a\ufff9b\ufffac\ufffbd", "a?b?c?d"},
	{"tag chars first and last", "a\U000E0000\U000E0041\U000E007Fb", "a???b"},
	{"mixed with controls", "\x1b\u202e\n", "?? "},
	{"clean emoji kept", cleanEmoji, cleanEmoji},
	{"ZWNJ kept", "\u0645\u200c\u06cc", "\u0645\u200c\u06cc"},
	{"boundary neighbours kept", "\u00ac\u00ae\u2027\u202f\u2065\u206a\ufff8\ufffc", "\u00ac\u00ae\u2027\u202f\u2065\u206a\ufff8\ufffc"},
}

// assertTerminalSafe fails when s contains any byte or rune a terminal could
// interpret as control: C0, DEL, C1 runes or invalid UTF-8.
func assertTerminalSafe(t *testing.T, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%q is not valid UTF-8", s)
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			t.Fatalf("%q still contains control rune %U", s, r)
		}
	}
}

// TestSanitizeReplacesControls checks each payload maps to the documented
// placeholders: whitespace controls to ' ', everything else (including each
// byte of invalid UTF-8) to '?'.
func TestSanitizeReplacesControls(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"osc8", osc8Payload, "?]8;;http://evil?click?]8;;?"},
		{"sgr hidden", sgrHidden, "a?[8mhidden?[0m"},
		{"raw 0x9b", rawCSI, "x?31my"},
		{"C1 CSI rune", c1CSIRune, "x?31my"},
		{"DEL", delPayload, "a?b"},
		{"argv newlines", argvNewlines, "sh -c echo hi   done"},
		{"unterminated CSI", unterminated, "abc?["},
		{"invalid UTF-8", invalidUTF8, "ok??"},
		{"vertical tab and form feed", "a\vb\fc", "a b c"},
		{"NUL and BEL", "a\x00b\x07", "a?b?"},
		{"clean non-ASCII kept", cleanNonASCII, cleanNonASCII},
		{"literal U+FFFD kept", "a�b", "a�b"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.in)
			if got != tt.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
			assertTerminalSafe(t, got)
			if again := Sanitize(got); again != got {
				t.Fatalf("Sanitize is not idempotent: %q -> %q", got, again)
			}
		})
	}
}

// TestSanitizeReplacesInvisibleFormat checks bidi controls, separators and
// zero-width format runes become the visible '?', while emoji glue (ZWJ,
// variation selectors, skin tones), regional-indicator flags and ZWNJ, as
// well as the code points right next to each replaced range, are kept.
func TestSanitizeReplacesInvisibleFormat(t *testing.T) {
	for _, tt := range invisibleFormatCases {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.in)
			if got != tt.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := Sanitize(got); again != got {
				t.Fatalf("Sanitize is not idempotent: %q -> %q", got, again)
			}
			for _, r := range got {
				if isInvisibleFormat(r) {
					t.Fatalf("%q still contains format rune %U", got, r)
				}
			}
		})
	}
}

// TestSanitizeLinesReplacesInvisibleFormat checks the multi-line variant
// applies the same format-rune rule on both its fast and slow path.
func TestSanitizeLinesReplacesInvisibleFormat(t *testing.T) {
	if got, want := SanitizeLines("a\u202eb\nc\u200bd"), "a?b\nc?d"; got != want {
		t.Fatalf("SanitizeLines = %q, want %q", got, want)
	}
}

// TestSanitizeFormatWidthIsExact checks a replaced format rune (0 cells
// before) is measured as the one cell it now renders as, so FitRight keeps
// columns exact, and that emoji sequences stay one grapheme wide.
func TestSanitizeFormatWidthIsExact(t *testing.T) {
	for _, tt := range invisibleFormatCases {
		s := Sanitize(tt.in)
		for _, width := range []int{1, 2, 4, 7, 12, 40} {
			if got := DisplayWidth(FitRight(s, width, ASCIIEllipsis)); got != width {
				t.Fatalf("%s: FitRight(%q, %d) width = %d", tt.name, s, width, got)
			}
		}
	}
	if got, want := DisplayWidth(Sanitize(rloSpoof)), len("invoice?fdp.exe"); got != want {
		t.Fatalf("RLO spoof width = %d, want %d", got, want)
	}
	// Family (2) + space + thumbs-up (2) + space + heart (2) + space +
	// snowman text-style (1) + space + flag (2).
	if got, want := DisplayWidth(Sanitize(cleanEmoji)), 13; got != want {
		t.Fatalf("emoji width = %d, want %d", got, want)
	}
}

// TestSanitizeWidthIsExact checks every replaced rune or byte costs exactly
// one cell, so a sanitised cell fitted by FitRight is exactly width wide.
func TestSanitizeWidthIsExact(t *testing.T) {
	for _, in := range []string{osc8Payload, sgrHidden, rawCSI, c1CSIRune, delPayload, argvNewlines, unterminated, invalidUTF8} {
		s := Sanitize(in)
		if got, want := DisplayWidth(s), utf8.RuneCountInString(s); got != want {
			t.Fatalf("DisplayWidth(%q) = %d, want %d (one cell per rune)", s, got, want)
		}
		for _, width := range []int{1, 3, 5, 12, 40} {
			if got := DisplayWidth(FitRight(s, width, ASCIIEllipsis)); got != width {
				t.Fatalf("FitRight(%q, %d) width = %d", s, width, got)
			}
		}
	}
}

// TestSanitizeLinesKeepsLineFeeds checks multi-line text keeps its layout
// while every other control is replaced.
func TestSanitizeLinesKeepsLineFeeds(t *testing.T) {
	got := SanitizeLines("line1\x1b[8m\nline2\t\x9b")
	if want := "line1?[8m\nline2 ?"; got != want {
		t.Fatalf("SanitizeLines = %q, want %q", got, want)
	}
	if clean := "a\nb"; SanitizeLines(clean) != clean {
		t.Fatalf("SanitizeLines changed clean text")
	}
}

// TestSanitizeCleanStringsDoNotAllocate checks the fast path: clean ASCII and
// clean non-ASCII strings are returned as is, with zero allocations, because
// Sanitize runs for every table cell on every frame.
func TestSanitizeCleanStringsDoNotAllocate(t *testing.T) {
	ascii := "/usr/lib/x86_64-linux-gnu/libc.so.6"
	for _, in := range []string{ascii, cleanNonASCII, cleanEmoji, ""} {
		var out string
		allocs := testing.AllocsPerRun(100, func() { out = Sanitize(in) })
		if allocs != 0 {
			t.Fatalf("Sanitize(%q) allocated %.1f times, want 0", in, allocs)
		}
		if out != in {
			t.Fatalf("Sanitize(%q) = %q, want unchanged", in, out)
		}
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = SanitizeLines("a\nb") }); allocs != 0 {
		t.Fatalf("SanitizeLines clean path allocated %.1f times, want 0", allocs)
	}
}

// TestRenderTableRowSanitizesCells checks the shared table row renderer used
// by every dashboard table: no escape byte survives and each cell keeps its
// exact width.
func TestRenderTableRowSanitizesCells(t *testing.T) {
	cols := []TableColumn{{Title: "A", Width: 10}, {Title: "B", Width: 20}}
	row := RenderTableRow(cols, []string{sgrHidden, osc8Payload}, false, -1, lipgloss.Style{})
	assertTerminalSafe(t, row)
	if strings.Contains(row, "\x1b") {
		t.Fatalf("row %q contains ESC", row)
	}
	if got, want := DisplayWidth(row), 10+1+20; got != want {
		t.Fatalf("row width = %d, want %d: %q", got, want, row)
	}
}

func BenchmarkSanitizeCleanASCII(b *testing.B) {
	s := "/usr/lib/x86_64-linux-gnu/libc.so.6"
	b.ReportAllocs()
	for b.Loop() {
		_ = Sanitize(s)
	}
}

// BenchmarkSanitizeCleanNonASCII measures the fast path for clean non-ASCII
// text, where every rune now also passes the isInvisibleFormat check.
func BenchmarkSanitizeCleanNonASCII(b *testing.B) {
	s := cleanNonASCII + cleanEmoji
	b.ReportAllocs()
	for b.Loop() {
		_ = Sanitize(s)
	}
}

// BenchmarkSanitizeBidiSpoof measures the slow path for a spoofed name.
func BenchmarkSanitizeBidiSpoof(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = Sanitize(rloSpoof)
	}
}
