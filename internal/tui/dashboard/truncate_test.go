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
