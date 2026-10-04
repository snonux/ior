package dashboard

import (
	"testing"
	"unicode/utf8"

	common "ior/internal/tui/common"
)

// TestDashboardTruncatorsKeepUTF8AndWidth is the regression for byte-based
// truncation: slicing "/data/日本語…" at a byte offset split a multi-byte rune
// and rendered invalid glyphs; rune-based cuts let wide runes overflow the
// column. Every helper must now return valid UTF-8 within its cell budget.
func TestDashboardTruncatorsKeepUTF8AndWidth(t *testing.T) {
	const path = "/data/日本語のファイル名.txt"
	tests := []struct {
		name  string
		fn    func(string, int) string
		in    string
		width int
		want  string
	}{
		{"truncatePathMiddle", truncatePathMiddle, path, 20, "/data/日...ル名.txt"},
		{"truncatePathMiddle tiny", truncatePathMiddle, path, 3, "/da"},
		{"trimPathTail", trimPathTail, path, 13, "...イル名.txt"},
		{"trimPathTail tiny", trimPathTail, "日本語", 2, "語"},
		{"truncateText", truncateText, "プロセス名前です", 9, "プロセ..."},
		{"truncateText trims space before marker", truncateText, "ab 日本語", 7, "ab..."},
		{"truncateText tiny", truncateText, "日本語", 3, "日"},
		{"truncateText zero", truncateText, "日本語", 0, ""},
		{"truncatePlain", truncatePlain, "filter: 日本語", 12, "filter: 日…"},
		{"truncatePlain negative", truncatePlain, "日本語", -1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.fn(tc.in, tc.width)
			if got != tc.want {
				t.Fatalf("%s(%q, %d) = %q, want %q", tc.name, tc.in, tc.width, got, tc.want)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("%s produced invalid UTF-8 %q", tc.name, got)
			}
			if w := common.DisplayWidth(got); w > max(tc.width, 0) {
				t.Fatalf("%s(%q, %d) is %d cells wide", tc.name, tc.in, tc.width, w)
			}
		})
	}
}

// TestRenderTabBarPlainExactWidth checks the plain tab bar is padded by
// display cells, not runes, so it always spans exactly width cells.
func TestRenderTabBarPlainExactWidth(t *testing.T) {
	for _, width := range []int{1, 5, 20, 200} {
		if got := common.DisplayWidth(renderTabBarPlain(TabOverview, width)); got != width {
			t.Fatalf("renderTabBarPlain width %d rendered %d cells", width, got)
		}
	}
}

// TestPadOrTrimExactDisplayWidth is the regression for the bubble/treemap/
// icicle header and status lines: padOrTrim cut by display width but padded
// by rune count, so "sel: 日本語のファイル" at width 20 came out 27 cells.
func TestPadOrTrimExactDisplayWidth(t *testing.T) {
	tests := []struct {
		in    string
		width int
		want  string
	}{
		{"sel: 日本語のファイル", 20, "sel: 日本語のファイ…"},
		{"sel: 日本", 12, "sel: 日本   "},
		{"sel: none", 12, "sel: none   "},
		{"日本", 1, "…"},
	}
	for _, tc := range tests {
		got := padOrTrim(tc.in, tc.width)
		if got != tc.want || common.DisplayWidth(got) != tc.width || !utf8.ValidString(got) {
			t.Fatalf("padOrTrim(%q, %d) = %q (%d cells), want %q", tc.in, tc.width, got, common.DisplayWidth(got), tc.want)
		}
	}
	// A non-positive width means unconstrained: the value is kept as is.
	if got := padOrTrim("日本語", 0); got != "日本語" {
		t.Fatalf("padOrTrim(width 0) = %q, want unchanged", got)
	}
}
