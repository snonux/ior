package common

import (
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
