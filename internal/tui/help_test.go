package tui

import (
	"testing"

	common "ior/internal/tui/common"
)

// TestTruncateHelpLineDisplayWidth checks help lines are cut by display cells:
// the old rune-based cut let a line of wide runes overflow the help box.
func TestTruncateHelpLineDisplayWidth(t *testing.T) {
	tests := []struct {
		in    string
		width int
		want  string
	}{
		{"short", 10, "short"},
		{"ヘルプの説明文", 7, "ヘルプ…"},
		{"abc", 1, "a"},
		{"日本", 1, "…"},
		{"abc", 0, ""},
		{"abc", -1, ""},
	}
	for _, tc := range tests {
		got := truncateHelpLine(tc.in, tc.width)
		if got != tc.want {
			t.Fatalf("truncateHelpLine(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
		if w := common.DisplayWidth(got); w > max(tc.width, 0) {
			t.Fatalf("truncateHelpLine(%q, %d) is %d cells wide", tc.in, tc.width, w)
		}
	}
}
