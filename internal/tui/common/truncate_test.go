package common

import (
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

// truncateCase is one row of the shared truncation table tests. The inputs
// deliberately mix ASCII, two-cell CJK/emoji runes and combining marks, the
// cases byte slicing (invalid UTF-8) and rune counting (misaligned width) got
// wrong.
type truncateCase struct {
	name   string
	in     string
	width  int
	marker string
	want   string
}

// assertTruncated checks the exact result, that it is valid UTF-8, and that
// it never exceeds the requested display width.
func assertTruncated(t *testing.T, fn string, tc truncateCase, got string) {
	t.Helper()
	if got != tc.want {
		t.Fatalf("%s(%q, %d, %q) = %q, want %q", fn, tc.in, tc.width, tc.marker, got, tc.want)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("%s(%q, %d) produced invalid UTF-8 %q", fn, tc.in, tc.width, got)
	}
	if w := DisplayWidth(got); w > max(tc.width, 0) {
		t.Fatalf("%s(%q, %d) is %d cells wide", fn, tc.in, tc.width, w)
	}
}

func TestTruncateRight(t *testing.T) {
	tests := []truncateCase{
		{"fits", "abc", 3, ASCIIEllipsis, "abc"},
		{"ascii cut", "abcdef", 5, ASCIIEllipsis, "ab..."},
		{"unicode ellipsis", "abcdef", 4, Ellipsis, "abc…"},
		{"cjk cut on boundary", "日本語ab", 5, ASCIIEllipsis, "日..."},
		// 4 cells minus 3 for "..." leaves 1, too narrow for 日: the
		// result is just the marker, one cell short, never half a rune.
		{"cjk cut inside wide rune", "日本語ab", 4, ASCIIEllipsis, "..."},
		{"cjk fits exactly", "日本", 4, Ellipsis, "日本"},
		{"emoji", "👍🏽👍🏽x", 4, Ellipsis, "👍🏽…"},
		{"combining marks stay attached", "éééé", 3, Ellipsis, "éé…"},
		{"marker as wide as width hard-cuts", "abcdef", 3, ASCIIEllipsis, "abc"},
		{"marker wider than width hard-cuts", "abcdef", 2, ASCIIEllipsis, "ab"},
		{"width one ascii", "abc", 1, Ellipsis, "a"},
		{"width one wide falls back to marker", "日本", 1, Ellipsis, "…"},
		{"width one wide marker too wide", "日本", 1, ASCIIEllipsis, ""},
		{"empty marker", "日本語", 3, "", "日"},
		{"zero width", "abc", 0, Ellipsis, ""},
		{"negative width", "abc", -2, Ellipsis, ""},
		{"empty input", "", 3, Ellipsis, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertTruncated(t, "TruncateRight", tc, TruncateRight(tc.in, tc.width, tc.marker))
		})
	}
}

func TestTruncateLeft(t *testing.T) {
	tests := []truncateCase{
		{"fits", "/a/b", 4, ASCIIEllipsis, "/a/b"},
		{"ascii cut keeps end", "/very/long/path.txt", 10, ASCIIEllipsis, "...ath.txt"},
		{"cjk keeps whole runes", "/データ/日本語.txt", 10, ASCIIEllipsis, "...語.txt"},
		{"cjk cut on boundary", "日本語ab", 7, ASCIIEllipsis, "...語ab"},
		// 6 cells: "..." + 3 cells; 語 would straddle the cut, so it is
		// dropped entirely and the result is one cell short.
		{"cjk straddling rune dropped", "日本語ab", 6, ASCIIEllipsis, "...ab"},
		{"marker too wide hard-cuts", "abcdef", 3, ASCIIEllipsis, "def"},
		{"width one wide falls back to marker", "日本", 1, Ellipsis, "…"},
		{"zero width", "abc", 0, ASCIIEllipsis, ""},
		{"negative width", "abc", -1, ASCIIEllipsis, ""},
		{"empty input", "", 5, ASCIIEllipsis, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertTruncated(t, "TruncateLeft", tc, TruncateLeft(tc.in, tc.width, tc.marker))
		})
	}
}

func TestTruncateMiddle(t *testing.T) {
	tests := []truncateCase{
		{"fits", "/a/b.txt", 8, ASCIIEllipsis, "/a/b.txt"},
		{"ascii", "/aaaa/bbbb/cccc.txt", 11, ASCIIEllipsis, "/aaa....txt"},
		// The probe from the bug report: byte slicing produced invalid
		// UTF-8 here. 20 cells = 8 head + 3 + 9 tail budget; the tail keeps
		// 8 cells because the next rune (イ) would straddle the cut.
		{"cjk path from bug report", "/data/日本語のファイル名.txt", 20, ASCIIEllipsis, "/data/日...ル名.txt"},
		// Head budget 3 cells stops before the wide 日 at 2 cells, so the
		// spare cell goes to the tail.
		{"cjk head short gives cell to tail", "日本語日本語", 9, ASCIIEllipsis, "日...本語"},
		{"separator fills width hard-cuts right", "abcdef", 3, ASCIIEllipsis, "abc"},
		{"width one", "abc", 1, ASCIIEllipsis, "a"},
		{"zero width", "abc", 0, ASCIIEllipsis, ""},
		{"negative width", "abc", -5, ASCIIEllipsis, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertTruncated(t, "TruncateMiddle", tc, TruncateMiddle(tc.in, tc.width, tc.marker))
		})
	}
}

// TestFitRightExactWidth checks that FitRight always yields exactly width
// cells, including when a wide rune forces the cut one cell short.
func TestFitRightExactWidth(t *testing.T) {
	tests := []truncateCase{
		{"pad ascii", "ab", 4, Ellipsis, "ab  "},
		{"pad cjk by cells not runes", "日本", 6, Ellipsis, "日本  "},
		{"cut then pad", "日本語", 4, Ellipsis, "日… "},
		{"combining mark pads by cells", "é", 3, Ellipsis, "é  "},
		{"zero width", "abc", 0, Ellipsis, ""},
		{"negative width", "abc", -1, Ellipsis, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FitRight(tc.in, tc.width, tc.marker)
			assertTruncated(t, "FitRight", tc, got)
			if tc.width > 0 && DisplayWidth(got) != tc.width {
				t.Fatalf("FitRight(%q, %d) is %d cells, want exactly %d", tc.in, tc.width, DisplayWidth(got), tc.width)
			}
		})
	}
}

func TestPadRightNeverTruncates(t *testing.T) {
	if got := PadRight("日本語", 2); got != "日本語" {
		t.Fatalf("PadRight wider input = %q, want unchanged", got)
	}
	if got := PadRight("x", -1); got != "x" {
		t.Fatalf("PadRight negative width = %q, want unchanged", got)
	}
	if got := PadRight("日", 3); got != "日 " {
		t.Fatalf("PadRight cjk = %q, want one pad cell", got)
	}
}

// TestRenderTableCellCJKAlignment is the table-alignment regression: cells
// used to be padded by rune count, so a CJK value came out wider than its
// column and shifted every column to its right.
func TestRenderTableCellCJKAlignment(t *testing.T) {
	for _, value := range []string{"abc", "日本", "日本語のファイル名", "👍🏽ok", "é́"} {
		got := renderTableCell(value, 8)
		if !utf8.ValidString(got) {
			t.Fatalf("renderTableCell(%q) produced invalid UTF-8 %q", value, got)
		}
		if w := DisplayWidth(got); w != 8 {
			t.Fatalf("renderTableCell(%q, 8) = %q is %d cells, want 8", value, got, w)
		}
	}
	if got := renderTableCell("日本語のファイル名", 8); got != "日本... " {
		t.Fatalf("renderTableCell cut = %q, want %q", got, "日本... ")
	}
}

// TestASCIIFastPathMatchesGraphemePath checks the printable-ASCII fast path
// (byte slicing, width == len) returns exactly what the general ansi-based
// grapheme path returns, for every width 1..len(s)-1 (the widths that force
// a cut, the only ones reaching the internal helpers). The exported helpers'
// early returns for widths -1, 0, len(s) and len(s)+1 are checked separately.
func TestASCIIFastPathMatchesGraphemePath(t *testing.T) {
	inputs := []string{"", "a", "ab", "/very/long/path/with/segments/and/filename.log", "  spaced  out  ", "~!@#$%^&*()_+{}|:<>?"}
	markers := []string{"", ASCIIEllipsis, Ellipsis, ".."}
	for _, s := range inputs {
		if _, ascii := measure(s); !ascii {
			t.Fatalf("measure(%q) did not take the ASCII fast path", s)
		}
		total := len(s)
		checkASCIIEarlyReturns(t, s)
		for width := 1; width < total; width++ {
			for _, m := range markers {
				pairs := [][2]string{
					{truncateRight(s, true, width, m), truncateRight(s, false, width, m)},
					{truncateLeft(s, total, true, width, m), truncateLeft(s, total, false, width, m)},
					{truncateMiddle(s, total, true, width, m), truncateMiddle(s, total, false, width, m)},
				}
				for i, p := range pairs {
					if p[0] != p[1] {
						t.Fatalf("helper %d on %q width %d marker %q: fast %q != general %q", i, s, width, m, p[0], p[1])
					}
				}
			}
		}
	}
	if _, ascii := measure("tab\there"); ascii {
		t.Fatal("control bytes must not take the ASCII fast path")
	}
	if w, ascii := measure(Ellipsis); w != 1 || ascii {
		t.Fatalf("measure(Ellipsis) = %d, %v; want 1, false", w, ascii)
	}
}

// checkASCIIEarlyReturns checks the exported helpers at the widths that never
// reach the cutting code: -1 and 0 yield "", len(s) and len(s)+1 yield s.
func checkASCIIEarlyReturns(t *testing.T, s string) {
	t.Helper()
	for _, width := range []int{-1, 0, len(s), len(s) + 1} {
		want := s
		if width <= 0 {
			want = ""
		}
		for name, got := range map[string]string{
			"Right":  TruncateRight(s, width, ASCIIEllipsis),
			"Left":   TruncateLeft(s, width, ASCIIEllipsis),
			"Middle": TruncateMiddle(s, width, ASCIIEllipsis),
		} {
			if got != want {
				t.Fatalf("Truncate%s(%q, %d) = %q, want %q", name, s, width, got, want)
			}
		}
	}
}

// propertyAlphabet mixes one-cell ASCII, two-cell CJK and emoji (including a
// skin-tone modifier sequence), zero-width combining marks, which attach to
// the preceding grapheme, and the clusters ansi.Truncate counts differently
// from ansi.StringWidth (task vp2): keycaps and an ASCII base with U+FE0F.
var propertyAlphabet = []string{"a", "Z", "/", ".", " ", "日", "本", "語", "ル", "👍", "👍🏽", "́", "̈", "é",
	"1\ufe0f\u20e3", "#\ufe0f\u20e3", "*\u20e3", "a\ufe0f"}

// randomMixed builds a random string of up to 12 alphabet entries.
func randomMixed(rng *rand.Rand) string {
	var b strings.Builder
	for n := rng.IntN(13); n > 0; n-- {
		b.WriteString(propertyAlphabet[rng.IntN(len(propertyAlphabet))])
	}
	return b.String()
}

// TestTruncatePropertiesRandomMixedWidth is a fixed-seed property test over
// random mixed-width strings: every helper must return valid UTF-8 no wider
// than asked, FitRight/PadRight must hit the exact width, and the kept part
// must be a real prefix (Right), suffix (Left) or both (Middle) of the input.
func TestTruncatePropertiesRandomMixedWidth(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 2026))
	for range 3000 {
		s := randomMixed(rng)
		width := rng.IntN(16) - 1
		marker := []string{"", Ellipsis, ASCIIEllipsis}[rng.IntN(3)]
		checkProperties(t, s, width, marker)
	}
}

// checkProperties asserts the truncation invariants for one input.
func checkProperties(t *testing.T, s string, width int, marker string) {
	t.Helper()
	right := TruncateRight(s, width, marker)
	left := TruncateLeft(s, width, marker)
	middle := TruncateMiddle(s, width, marker)
	for name, got := range map[string]string{"Right": right, "Left": left, "Middle": middle} {
		if !utf8.ValidString(got) || DisplayWidth(got) > max(width, 0) {
			t.Fatalf("Truncate%s(%q, %d, %q) = %q: invalid UTF-8 or too wide", name, s, width, marker, got)
		}
	}
	if !strings.HasPrefix(s, strings.TrimSuffix(right, marker)) && right != marker {
		t.Fatalf("TruncateRight(%q, %d, %q) = %q is not a prefix", s, width, marker, right)
	}
	if !strings.HasSuffix(s, strings.TrimPrefix(left, marker)) && left != marker {
		t.Fatalf("TruncateLeft(%q, %d, %q) = %q is not a suffix", s, width, marker, left)
	}
	if marker != "" && middle != s && strings.Contains(middle, marker) && !keepsBothEnds(s, middle, marker) {
		t.Fatalf("TruncateMiddle(%q, %d, %q) = %q does not keep both ends", s, width, marker, middle)
	}
	if width > 0 {
		if got := FitRight(s, width, marker); DisplayWidth(got) != width {
			t.Fatalf("FitRight(%q, %d) = %q is %d cells", s, width, got, DisplayWidth(got))
		}
		if got := PadRight(right, width); DisplayWidth(got) != width {
			t.Fatalf("PadRight(%q, %d) = %q is %d cells", right, width, got, DisplayWidth(got))
		}
	}
}

// keepsBothEnds reports whether middle is head+marker+tail for some split
// where head is a prefix and tail a suffix of s. Every marker occurrence is
// tried because the kept text may itself contain the marker characters.
func keepsBothEnds(s, middle, marker string) bool {
	for i := 0; i+len(marker) <= len(middle); i++ {
		if middle[i:i+len(marker)] == marker &&
			strings.HasPrefix(s, middle[:i]) && strings.HasSuffix(s, middle[i+len(marker):]) {
			return true
		}
	}
	return false
}

// Benchmarks for the event-stream hot path: a typical ASCII path that fits,
// one that is middle-cut, and a CJK path taking the general grapheme path.
func BenchmarkTruncateMiddleASCIIFits(b *testing.B) {
	for b.Loop() {
		_ = TruncateMiddle("/var/log/app.log", 48, ASCIIEllipsis)
	}
}

func BenchmarkTruncateMiddleASCIICut(b *testing.B) {
	for b.Loop() {
		_ = TruncateMiddle("/very/long/path/with/segments/and/filename.log", 24, ASCIIEllipsis)
	}
}

func BenchmarkFitRightASCII(b *testing.B) {
	for b.Loop() {
		_ = FitRight("12345", 8, ASCIIEllipsis)
	}
}

func BenchmarkTruncateMiddleCJK(b *testing.B) {
	for b.Loop() {
		_ = TruncateMiddle("/data/日本語のファイル名.txt", 20, ASCIIEllipsis)
	}
}
