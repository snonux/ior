package textsafe

import (
	"fmt"
	"testing"
	"unicode"
)

// namedBlanks are the lookalikes the review of task 1q2 reported plus the
// other Zs members, spelled out so that a regression names the rune.
var namedBlanks = []struct {
	name string
	r    rune
}{
	{"BRAILLE PATTERN BLANK", 0x2800},
	{"NO-BREAK SPACE", 0x00A0},
	{"IDEOGRAPHIC SPACE", 0x3000},
	{"OGHAM SPACE MARK", 0x1680},
	{"EN QUAD", 0x2000},
	{"EM SPACE", 0x2003},
	{"THIN SPACE", 0x2009},
	{"HAIR SPACE", 0x200A},
	{"NARROW NO-BREAK SPACE", 0x202F},
	{"MEDIUM MATHEMATICAL SPACE", 0x205F},
	{"IDEOGRAPHIC HALF FILL SPACE", 0x303F},
	{"OBJECT REPLACEMENT CHARACTER", 0xFFFC},
	{"EGYPTIAN HIEROGLYPH FULL BLANK", 0x13441},
	{"EGYPTIAN HIEROGLYPH HALF BLANK", 0x13442},
	{"KHITAN SMALL SCRIPT FILLER", 0x16FE4},
	{"MUSICAL SYMBOL NULL NOTEHEAD", 0x1D159},
}

// TestBlankLookalikeMatchesTables checks IsBlankLookalike against the Unicode
// space class for every code point: it is exactly Zs minus the ASCII space
// plus the pinned blankSymbols, so a space added to Zs by a Go update is
// covered without touching the list.
func TestBlankLookalikeMatchesTables(t *testing.T) {
	pinned := map[rune]bool{}
	for _, r := range blankSymbols {
		pinned[r] = true
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		want := (unicode.Is(unicode.Zs, r) && r != ' ') || pinned[r]
		if got := IsBlankLookalike(r); got != want {
			t.Fatalf("IsBlankLookalike(%U) = %v, want %v", r, got, want)
		}
	}
}

// slowBlankLookalike is the definition of IsBlankLookalike without any early
// return: the Zs class minus the ASCII space plus the pinned list.
func slowBlankLookalike(r rune) bool {
	if unicode.Is(unicode.Zs, r) && r != ' ' {
		return true
	}
	for _, blank := range blankSymbols {
		if r == blank {
			return true
		}
	}
	return false
}

// TestBlankLookalikeBounds derives the bounds of the early returns in
// IsBlankLookalike from the sets themselves and checks every code point
// against the slow reference: U+00A0 must be the only match below
// firstWideZs, firstWideZs must be the smallest match above it, and lastZs
// must be the largest Zs rune, so the cheap comparisons cannot skip a match
// when Go updates its tables. Nothing below U+00A0 may match either (the
// ASCII fast path of ClassAt relies on that).
func TestBlankLookalikeBounds(t *testing.T) {
	smallestAbove, largestZs := rune(-1), rune(-1)
	for r := rune(0); r <= unicode.MaxRune; r++ {
		slow := slowBlankLookalike(r)
		if got := IsBlankLookalike(r); got != slow {
			t.Fatalf("IsBlankLookalike(%U) = %v, reference says %v", r, got, slow)
		}
		if slow && r > noBreakSpace && smallestAbove < 0 {
			smallestAbove = r
		}
		if unicode.Is(unicode.Zs, r) && r != ' ' {
			largestZs = r
		}
		if slow && r < noBreakSpace {
			t.Errorf("%U below U+00A0 is a blank lookalike", r)
		}
	}
	if smallestAbove != firstWideZs {
		t.Errorf("smallest blank lookalike above U+00A0 is %U, firstWideZs = %U", smallestAbove, rune(firstWideZs))
	}
	if largestZs != lastZs {
		t.Errorf("largest Zs rune is %U, lastZs = %U", largestZs, rune(lastZs))
	}
	if !unicode.Is(unicode.Zs, noBreakSpace) {
		t.Errorf("noBreakSpace %U is not Zs", rune(noBreakSpace))
	}
}

// BenchmarkIsBlankLookalike compares the runes of the common scripts; the
// Latin-1, Cyrillic and CJK cases are the ones the early returns serve.
func BenchmarkIsBlankLookalike(b *testing.B) {
	for _, c := range []struct {
		name string
		r    rune
	}{{"Latin1", 'é'}, {"Cyrillic", 'д'}, {"CJK", '日'}, {"emoji", 0x1F600}, {"NBSP", 0xA0}} {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				_ = IsBlankLookalike(c.r)
			}
		})
	}
}

// TestBlankSymbolsArePinned guards the hand-kept list: each entry must still
// be outside every class that already catches it (a duplicate would hide a
// stale entry) and the set of letters, marks, numbers, punctuation and
// symbols that count as blank must be exactly this list, so a Go table update
// that moves a rune is noticed here instead of silently changing the output.
func TestBlankSymbolsArePinned(t *testing.T) {
	for _, r := range blankSymbols {
		if unicode.Is(unicode.Zs, r) || unicode.IsControl(r) || IsInvisibleFormat(r) {
			t.Errorf("blankSymbols entry %U is already covered by another class; drop it", r)
		}
	}
	got := map[rune]bool{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsBlankLookalike(r) && unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S) {
			got[r] = true
		}
	}
	if len(got) != len(blankSymbols) {
		t.Errorf("blank lookalikes among L/M/N/P/S = %d runes, want exactly the %d pinned ones: %v", len(got), len(blankSymbols), got)
	}
	for _, r := range blankSymbols {
		if !got[r] {
			t.Errorf("pinned blank symbol %U is not in L/M/N/P/S any more", r)
		}
	}
}

// TestBlankLookalikesAreEscaped covers every blank lookalike for every code
// point (not only the named ones): alone, between ASCII letters (the
// "pass<rune>wd" spoof), as the whole name and next to an emoji, ClassAt says
// Unsafe, Escape writes the exact code point in escape notation, and a second
// Escape changes nothing.
func TestBlankLookalikesAreEscaped(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !IsBlankLookalike(r) {
			continue
		}
		esc := fmt.Sprintf(`\u%04x`, r)
		if r > 0xFFFF {
			esc = fmt.Sprintf(`\U%08x`, r)
		}
		for _, c := range []struct{ in, want string }{
			{string(r), esc},
			{"pass" + string(r) + "wd", "pass" + esc + "wd"},
			{"etc" + string(r) + "passwd", "etc" + esc + "passwd"},
			{"\U0001F600" + string(r) + "\U0001F600", "\U0001F600" + esc + "\U0001F600"},
		} {
			if i := FirstUnsafe(c.in, false); i < 0 {
				t.Fatalf("FirstUnsafe(%q) = -1, want an unsafe rune", c.in)
			}
			got := Escape(c.in)
			if got != c.want {
				t.Fatalf("Escape(%q) = %q, want %q", c.in, got, c.want)
			}
			if again := Escape(got); again != got {
				t.Fatalf("Escape(%q) = %q, escaping again gives %q", c.in, got, again)
			}
		}
	}
}

// TestNamedBlanksAreUnsafe pins the runes the review named, so the test above
// cannot pass vacuously if the predicate were emptied.
func TestNamedBlanksAreUnsafe(t *testing.T) {
	for _, nb := range namedBlanks {
		s := "pass" + string(nb.r) + "wd"
		if class, _ := ClassAt(s, 4); class != Unsafe {
			t.Errorf("%s (%U): ClassAt = %d, want Unsafe", nb.name, nb.r, class)
		}
		if got := Escape(s); got == s {
			t.Errorf("%s (%U): Escape left %q unchanged", nb.name, nb.r, s)
		}
	}
}

// TestBenignTextIsNotMistakenForBlank is the negative side: ordinary text must
// stay byte-identical, in particular the ASCII space, CJK without ideographic
// spaces, emoji (ZWJ sequences, flags, keycaps, skin tones), combining marks
// with a base, Persian ZWNJ, and symbols next to the blank ones (Braille
// dots, the replacement character U+FFFD, other musical symbols).
func TestBenignTextIsNotMistakenForBlank(t *testing.T) {
	for _, s := range []string{
		"etc passwd", " leading and trailing ", "日本語のファイル.txt", "한국어 파일",
		"café", "é", "\U0001F468\u200d\U0001F469\u200d\U0001F467", "\U0001F1E9\U0001F1EA",
		"1\ufe0f⃣", "❤\ufe0f", "\U0001F44D\U0001F3FD", "م\u200cی",
		"⠁⡀⣿", "\ufffd", "\U0001D15A\U0001D158", "\U00016FE3", "␣", "·",
	} {
		if i := FirstUnsafe(s, false); i >= 0 {
			t.Errorf("FirstUnsafe(%q) = %d, want -1", s, i)
		}
		if got := Escape(s); got != s {
			t.Errorf("Escape(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestLettersNumbersSymbolsStaySafe sweeps every code point that is a letter,
// number, punctuation or symbol and not one of the documented invisible or
// blank runes: each is Safe on its own. It catches an over-broad blank
// predicate (for instance a whole Unicode block) that the named examples miss.
func TestLettersNumbersSymbolsStaySafe(t *testing.T) {
	for r := rune(0x20); r <= unicode.MaxRune; r++ {
		if !unicode.In(r, unicode.L, unicode.N, unicode.P, unicode.S) ||
			IsInvisibleFormat(r) || IsBlankLookalike(r) || unicode.IsControl(r) {
			continue
		}
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates are not encodable
		}
		if class, _ := ClassAt(string(r), 0); class != Safe {
			t.Fatalf("ClassAt(%U) = %d, want Safe", r, class)
		}
	}
}

// TestBlankLookalikesAreNotContext checks that no blank lookalike can vouch
// for a contextual rune (emoji base, joining letter), which would make the
// decision differ between the first and the second pass over escaped text.
func TestBlankLookalikesAreNotContext(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if IsBlankLookalike(r) && (isEmojiBase(r) || isJoiningContext(r) || isKeycapBase(r)) {
			t.Errorf("blank lookalike %U is accepted as context", r)
		}
	}
}
