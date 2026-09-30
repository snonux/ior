package common

import (
	"strings"
	"testing"
	"unicode/utf8"

	"charm.land/lipgloss/v2"

	"ior/internal/textsafe"
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
	// a skin-tone modifier, text/emoji variation selectors, a regional-
	// indicator flag, a ZWJ after U+FE0F (rainbow flag) and a ZWJ after a
	// skin tone (man technologist, medium skin).
	cleanEmoji = "\U0001F468\u200D\U0001F469\u200D\U0001F467 \U0001F44D\U0001F3FD \u2764\uFE0F \u2603\uFE0E \U0001F1E9\U0001F1EA" +
		" \U0001F3F3\uFE0F\u200D\U0001F308 \U0001F468\U0001F3FD\u200D\U0001F4BB"
	// englandFlag is black flag + tag letters "gbeng" + cancel tag. Tag runes
	// are replaced (see textsafe.IsInvisibleFormat), so it degrades to 1 flag + 6 '?'.
	englandFlag = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"
)

// boundaryNeighbours holds visible code points right next to replaced
// ranges: U+00AC/00AE around the soft hyphen, U+0606 after U+0600..0605,
// U+2027/2030 around U+2028..202E, U+205E before U+2060, U+2070 after
// U+206F and U+FFFC after U+FFF0..FFFB.
const boundaryNeighbours = "\u00ac\u00ae\u0606\u2027\u2030\u205e\u2070\ufffc"

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
	{"word joiner and invisible operators", "a\u2060\u2061\u2062\u2063\u2064b", "a?????b"},
	{"deprecated format U+206A..206F", "a\u206a\u206fb", "a??b"},
	{"Mongolian vowel separator", "a\u180eb", "a?b"},
	{"musical and hieroglyph format", "a\U0001D173\U0001D17A\U00013430\U0001343Fb", "a????b"},
	{"shorthand format", "a\U0001BCA0\U0001BCA3b", "a??b"},
	{"CGJ and Khmer inherent vowels", "a\u034f\u17b4\u17b5b", "a???b"},
	{"VS1 and VS14", "a\ufe00\ufe0db", "a??b"},
	{"variation selector supplement smuggling", "a\U000E0100\U000E01EFb", "a??b"},
	{"Hangul fillers", "a\u115f\u1160\u3164\uffa0b", "a????b"},
	{"prepended concatenation marks", "a\u0600b\u06ddc\u070fd\u0890e\u08e2f\U000110BDg\U000110CDh", "a?b?c?d?e?f?g?h"},
	{"ZWJ between letters", "pass\u200dwd", "pass?wd"},
	{"ZWJ at start", "\u200d\U0001F525", "?\U0001F525"},
	{"ZWJ after replaced rune", "\U0001F525\ufe00\u200d\U0001F525", "\U0001F525??\U0001F525"},
	{"ZWJ after invalid byte", "\xff\u200dx", "??x"},
	{"trailing ZWJ after emoji", "\U0001F600\u200d", "\U0001F600?"},
	{"ZWJ between emoji and letter", "\U0001F600\u200dx", "\U0001F600?x"},
	{"ZWJ before VS16", "\U0001F600\u200d\ufe0f", "\U0001F600?\ufe0f"},
	{"ZWJ before invalid byte", "\U0001F600\u200d\xff", "\U0001F600??"},
	{"fire heart kept", "\u2764\ufe0f\u200d\U0001F525", "\u2764\ufe0f\u200d\U0001F525"},
	{"England flag degrades", englandFlag, "\U0001F3F4??????"},
	{"mixed with controls", "\x1b\u202e\n", "?? "},
	{"clean emoji kept", cleanEmoji, cleanEmoji},
	{"ZWNJ kept", "\u0645\u200c\u06cc", "\u0645\u200c\u06cc"},
	{"boundary neighbours kept", boundaryNeighbours, boundaryNeighbours},
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

// TestSanitizeReplacesInvisibleFormat checks bidi controls, separators,
// format, default-ignorable and variation-selector runes and a ZWJ outside an
// emoji sequence become the visible '?', while emoji glue (ZWJ between two
// emoji, VS15/VS16, skin tones), regional-indicator flags and ZWNJ, as well
// as the visible code points next to each replaced range, are kept.
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
				if textsafe.IsInvisibleFormat(r) {
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
	// snowman text-style (1) + space + flag (2) + space + rainbow flag (2) +
	// space + technologist (2).
	if got, want := DisplayWidth(Sanitize(cleanEmoji)), 19; got != want {
		t.Fatalf("emoji width = %d, want %d", got, want)
	}
	// A prepended concatenation mark would merge with the next cell; as '?'
	// it is one cell of its own.
	if got := DisplayWidth(Sanitize("a\u0600b")); got != 3 {
		t.Fatalf("a<U+0600>b width = %d, want 3", got)
	}
	// Black flag (2) + six '?' cells.
	if got := DisplayWidth(Sanitize(englandFlag)); got != 8 {
		t.Fatalf("England flag width = %d, want 8", got)
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
// text, where every rune now also passes the textsafe.IsInvisibleFormat check.
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
