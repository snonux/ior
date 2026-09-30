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

// TestClassAt covers each class, including the context-dependent ZWJ, ZWNJ
// and variation selectors and the size reported for invalid bytes and multi-byte runes.
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
		{"ZWNJ alone", "\u200c", 0, Unsafe, 3},
		{"ZWNJ between Persian letters", "\u0645\u200c\u06cc", 2, Safe, 3},
		{"ZWNJ between Latin letters", "a\u200cb", 1, Unsafe, 3},
		{"VS16 alone", "\ufe0f", 0, Unsafe, 3},
		{"VS16 after letter", "a\ufe0f", 1, Unsafe, 3},
		{"VS16 after heart", "\u2764\ufe0f", 3, Safe, 3},
		{"VS15 after letter", "a\ufe0e", 1, Unsafe, 3},
		{"VS16 in keycap", "1\ufe0f\u20e3", 1, Safe, 3},
		{"VS16 after digit without keycap", "1\ufe0f", 1, Unsafe, 3},
		{"ZWJ after letter plus VS16", "a\ufe0f\u200d\U0001F600", 4, Unsafe, 3},
		{"ZWJ after heart plus VS16", "\u2764\ufe0f\u200d\U0001F525", 6, Safe, 3},
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

// TestContextualRunesDoNotLookLikePlainText is the lookalike regression
// (task 1q2): inserting an invisible joiner or selector between ASCII
// letters must never survive, whichever of the three context-dependent
// runes is used, so "pass<rune>wd" cannot pose as "passwd".
func TestContextualRunesDoNotLookLikePlainText(t *testing.T) {
	for _, r := range []rune{zeroWidthJoiner, zeroWidthNonJoiner, textPresentation, emojiPresentation} {
		s := "pass" + string(r) + "wd"
		if i := FirstUnsafe(s, false); i != 4 {
			t.Errorf("FirstUnsafe(%q) = %d, want 4 (the %U)", s, i, r)
		}
		want := `pass\u` + map[rune]string{
			zeroWidthJoiner: "200d", zeroWidthNonJoiner: "200c",
			textPresentation: "fe0e", emojiPresentation: "fe0f",
		}[r] + "wd"
		if got := Escape(s); got != want {
			t.Errorf("Escape(%q) = %q, want %q", s, got, want)
		}
	}
}

// TestContextRulesAreStableUnderEscape checks the rune that vouches for a
// contextual rune (emoji base, keycap base, letter) is itself never
// rewritten, so escaping a string once decides everything and a second pass
// changes nothing, including for text where several contextual runes touch.
func TestContextRulesAreStableUnderEscape(t *testing.T) {
	for _, s := range []string{
		"\u2764\ufe0f\u200d\U0001F525", "a\ufe0f\u200d\u2764\ufe0f", "1\ufe0f\u20e3\ufe0e",
		"\u0645\u200c\u200c\u06cc", "\u0915\u094d\u200c\u200c\u0937", "\ufe0f\ufe0f\u200c\u200d",
	} {
		once := Escape(s)
		if twice := Escape(once); twice != once {
			t.Errorf("Escape(%q) = %q, but escaping again gives %q", s, once, twice)
		}
	}
}
