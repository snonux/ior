package textsafe

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
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
// and variation selectors, and the size reported for invalid bytes and
// multi-byte runes.
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
		{"ASCII space", " ", 0, Safe, 1},
		{"no-break space", "\u00a0", 0, Unsafe, 2},
		{"ideographic space", "\u3000", 0, Unsafe, 3},
		{"Braille blank", "\u2800", 0, Unsafe, 3},
		{"Khitan filler", "\U00016FE4", 0, Unsafe, 4},
		{"Braille dots are text", "\u2801", 0, Safe, 3},
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

// trickyRunes are the runes whose classification depends on, or can change,
// the context of a neighbour: the joiners and selectors themselves, format
// marks that ClassAt replaces although they are letters' neighbours in their
// script (Mongolian FVS, Khmer inherent vowels, an IVS), keycap and emoji
// bases, a skin tone, letters of each script in zwnjScripts (with their
// viramas), ASCII and a control rune.
var trickyRunes = []rune{
	zeroWidthJoiner, zeroWidthNonJoiner, textPresentation, emojiPresentation,
	0x180B, 0x180F, 0x17B4, 0x17B5, 0xE0100, 0xFE00, combiningKeycap,
	'a', '1', '\x1b', 0x2764, 0x1F600, 0x1F3FD, 0x1F1E9,
	0x0645, 0x0710, 0x1820, 0x0915, 0x094D, 0x0995, 0x0B95, 0x1000, 0x1780,
	0x00A0, 0x3000, 0x2800, 0x16FE4,
}

// forEachCombination calls fn with every string of 1 to maxLen runes drawn
// from runes.
func forEachCombination(runes []rune, maxLen int, fn func(s string)) {
	var build func(prefix []rune)
	build = func(prefix []rune) {
		if len(prefix) > 0 {
			fn(string(prefix))
		}
		if len(prefix) == maxLen {
			return
		}
		for _, r := range runes {
			build(append(prefix, r))
		}
	}
	build(make([]rune, 0, maxLen))
}

// TestContextRulesAreStableUnderEscape checks that the rune that vouches for
// a contextual rune (emoji base, keycap base, letter) is itself never
// rewritten, so escaping a string once decides everything and a second pass
// changes nothing. The named inputs are earlier counterexamples: a ZWNJ
// whose left neighbour is a Mongolian or Khmer mark that is replaced.
// The generated corpus covers every combination of up to four tricky runes.
func TestContextRulesAreStableUnderEscape(t *testing.T) {
	for _, s := range []string{
		"\u2764\ufe0f\u200d\U0001F525", "a\ufe0f\u200d\u2764\ufe0f", "1\ufe0f\u20e3\ufe0e",
		"\u0645\u200c\u200c\u06cc", "\u0915\u094d\u200c\u200c\u0937", "\ufe0f\ufe0f\u200c\u200d",
		"\u1820\u180b\u200c\u1820", "\u1780\u17b4\u200c\u1781", "\u1780\u17b5\u200c\u1781",
	} {
		once := Escape(s)
		if twice := Escape(once); twice != once {
			t.Errorf("Escape(%q) = %q, but escaping again gives %q", s, once, twice)
		}
	}
	forEachCombination(trickyRunes, 4, func(s string) {
		once := Escape(s)
		if twice := Escape(once); twice != once {
			t.Fatalf("Escape(%q) = %q, but escaping again gives %q", s, once, twice)
		}
		if i := FirstUnsafe(once, false); i >= 0 {
			t.Fatalf("Escape(%q) = %q still has an unsafe rune at %d", s, once, i)
		}
	})
}

// TestZWNJIgnoresReplacedMarks is the regression for the false idempotence
// claim: a Mongolian FVS or Khmer U+17B4 is replaced, so it cannot vouch for
// the ZWNJ next to it, in either direction.
func TestZWNJIgnoresReplacedMarks(t *testing.T) {
	for _, s := range []string{
		"\u1820\u180b\u200c\u1820", "\u1820\u200c\u180b\u1820",
		"\u1780\u17b4\u200c\u1781", "\u1780\u200c\u17b5\u1781",
	} {
		i := strings.Index(s, "\u200c")
		if class, _ := ClassAt(s, i); class != Unsafe {
			t.Errorf("ClassAt(%q, %d) = %d, want Unsafe", s, i, class)
		}
	}
}

// zwnjCase is one ZWNJ context: the rune before and after it.
type zwnjCase struct {
	name       string
	prev, next rune
}

// TestZWNJKeptBetweenScriptLetters pins each entry of zwnjScripts: a ZWNJ
// between two letters (or a virama and a letter) of the same script is kept.
// Removing a script from the list makes exactly its cases fail.
func TestZWNJKeptBetweenScriptLetters(t *testing.T) {
	for _, tt := range []zwnjCase{
		{"Arabic", 0x0645, 0x06CC},
		{"Syriac", 0x0710, 0x0712},
		{"Mongolian", 0x1820, 0x1821},
		{"Devanagari virama", 0x094D, 0x0937},
		{"Devanagari letters", 0x0915, 0x0937},
		{"Bengali virama", 0x09CD, 0x09B7},
		{"Gurmukhi", 0x0A15, 0x0A16},
		{"Gujarati", 0x0A95, 0x0A96},
		{"Oriya", 0x0B15, 0x0B16},
		{"Tamil virama", 0x0BCD, 0x0BB7},
		{"Telugu", 0x0C15, 0x0C16},
		{"Kannada", 0x0C95, 0x0C96},
		{"Malayalam", 0x0D15, 0x0D16},
		{"Sinhala", 0x0D9A, 0x0D9B},
		{"Myanmar", 0x1000, 0x1001},
		{"Khmer", 0x1780, 0x1781},
	} {
		s := string(tt.prev) + "\u200c" + string(tt.next)
		if class, _ := ClassAt(s, utf8.RuneLen(tt.prev)); class != Safe {
			t.Errorf("%s: ClassAt(%q) = %d, want Safe", tt.name, s, class)
		}
	}
}

// TestZWNJReplacedOutsideScriptLetters covers the negatives: mixed scripts,
// a script's letter next to a digit, Latin letter or name boundary, scripts
// that are deliberately not in zwnjScripts, and a same-script rune that is
// neither letter nor mark (a digit), which the isJoiningContext guard must
// reject even though the script table contains it.
func TestZWNJReplacedOutsideScriptLetters(t *testing.T) {
	for _, tt := range []zwnjCase{
		{"Arabic and Syriac", 0x0645, 0x0712},
		{"Devanagari and Bengali", 0x0915, 0x09B7},
		{"Mongolian and Khmer", 0x1820, 0x1781},
		{"Latin and Arabic", 'a', 0x0645},
		{"Arabic and Latin", 0x0645, 'a'},
		{"Arabic letter and ASCII digit", 0x0645, '1'},
		{"Arabic letter and emoji", 0x0645, 0x1F600},
		{"Arabic letter and space", 0x0645, ' '},
		{"Thai", 0x0E01, 0x0E02},
		{"Lao", 0x0E81, 0x0E82},
		{"Tibetan", 0x0F40, 0x0F41},
		{"Devanagari digit before letter", 0x0966, 0x0915},
		{"Devanagari letter before digit", 0x0915, 0x0966},
		{"Bengali digits", 0x09E6, 0x09E7},
		{"Myanmar digit before letter", 0x1040, 0x1000},
		{"Khmer sign before letter", 0x17D4, 0x1780},
		{"Syriac punctuation before letter", 0x0700, 0x0710},
		{"Mongolian punctuation before letter", 0x1800, 0x1820},
		{"Arabic prepended mark before letter", 0x0600, 0x0645},
		{"Tamil digit before letter", 0x0BE6, 0x0B95},
	} {
		s := string(tt.prev) + "\u200c" + string(tt.next)
		if class, _ := ClassAt(s, utf8.RuneLen(tt.prev)); class != Unsafe {
			t.Errorf("%s: ClassAt(%q) = %d, want Unsafe", tt.name, s, class)
		}
	}
	for _, s := range []string{"\u200c\u0645", "\u0645\u200c"} {
		if class, _ := ClassAt(s, strings.Index(s, "\u200c")); class != Unsafe {
			t.Errorf("ClassAt(%q) at name boundary = %d, want Unsafe", s, class)
		}
	}
}
