package textsafe

import (
	"testing"
	"unicode"
)

// TestInvisibleFormatMatchesClasses checks IsInvisibleFormat against the
// Unicode tables for every code point: its cheap range pre-check must not
// hide any member of Cf, Variation_Selector or
// Other_Default_Ignorable_Code_Point, and only the documented exceptions
// (ZWNJ, ZWJ, VS15, VS16) and the separators may differ from the classes.
func TestInvisibleFormatMatchesClasses(t *testing.T) {
	exceptions := map[rune]bool{0x200C: true, 0x200D: true, 0xFE0E: true, 0xFE0F: true}
	extra := map[rune]bool{0x2028: true, 0x2029: true}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		inClass := unicode.In(r, unicode.Cf, unicode.Variation_Selector, unicode.Other_Default_Ignorable_Code_Point)
		want := (inClass && !exceptions[r]) || extra[r]
		if got := IsInvisibleFormat(r); got != want {
			t.Fatalf("IsInvisibleFormat(%U) = %v, want %v", r, got, want)
		}
	}
}

// TestClassAt covers each class, including the context-dependent ZWJ and
// the size reported for invalid bytes and multi-byte runes.
func TestClassAt(t *testing.T) {
	tests := []struct {
		name      string
		s         string
		i         int
		wantClass Class
		wantSize  int
	}{
		{"printable ASCII", "a", 0, Safe, 1},
		{"ESC", "\x1b", 0, Unsafe, 1},
		{"BEL", "\a", 0, Unsafe, 1},
		{"DEL", "\x7f", 0, Unsafe, 1},
		{"TAB", "\t", 0, Whitespace, 1},
		{"LF", "\n", 0, Whitespace, 1},
		{"CR", "\r", 0, Whitespace, 1},
		{"C1 CSI rune", "\u009b", 0, Unsafe, 2},
		{"raw 0x9b byte", "\x9b", 0, Unsafe, 1},
		{"truncated rune", "\xe2\x80", 0, Unsafe, 1},
		{"RLO", "\u202e", 0, Unsafe, 3},
		{"tag rune", "\U000E0041", 0, Unsafe, 4},
		{"CJK", "日", 0, Safe, 3},
		{"ZWNJ", "\u200c", 0, Safe, 3},
		{"ZWJ in emoji sequence", "\U0001F468\u200d\U0001F469", 4, Safe, 3},
		{"ZWJ between letters", "a\u200db", 1, Unsafe, 3},
		{"literal U+FFFD is text", "\ufffd", 0, Safe, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class, size := ClassAt(tt.s, tt.i)
			if class != tt.wantClass || size != tt.wantSize {
				t.Fatalf("ClassAt(%q, %d) = (%d, %d), want (%d, %d)", tt.s, tt.i, class, size, tt.wantClass, tt.wantSize)
			}
		})
	}
}

// TestFirstUnsafe checks the fast-path scan, including keepLF.
func TestFirstUnsafe(t *testing.T) {
	tests := []struct {
		s      string
		keepLF bool
		want   int
	}{
		{"", false, -1},
		{"/tmp/clean file.txt", false, -1},
		{"日本語/ファイル", false, -1},
		{"ab\x1b[8m", false, 2},
		{"a\nb", false, 1},
		{"a\nb", true, -1},
		{"a\nb\x07", true, 3},
		{"x\u202e", false, 1},
		{"ok\xff", false, 2},
	}
	for _, tt := range tests {
		if got := FirstUnsafe(tt.s, tt.keepLF); got != tt.want {
			t.Errorf("FirstUnsafe(%q, %v) = %d, want %d", tt.s, tt.keepLF, got, tt.want)
		}
	}
}
