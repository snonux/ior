package common

import (
	"slices"
	"testing"
)

// TestWrapAtWhitespace pins what WrapAtSpaces breaks at: any Unicode white
// space (strings.Fields), a tab and a no-break space included, each run
// written as one plain space; and that a wide rune wider than a one-cell
// line opens its word without the empty line ansi.Hardwrap puts before it,
// its line then cut empty by FitWrapped rather than left two cells wide.
// (Moved from the export package with the function, task rz2.)
func TestWrapAtWhitespace(t *testing.T) {
	cases := []struct {
		text  string
		width int
		want  []string
	}{
		{"a b\tc", 3, []string{"a b", "c"}},
		{"a  \t b", 80, []string{"a b"}},
		{"日本 a", 1, []string{"日", "本", "a"}},
		{"😀x", 1, []string{"😀", "x"}},
		{"ior-stream-1.csv x", 16, []string{"ior-stream-1.csv", "x"}},
	}
	for _, c := range cases {
		if got := WrapAtSpaces(c.text, c.width); !slices.Equal(got, c.want) {
			t.Fatalf("WrapAtSpaces(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
	}
	if got, want := FitWrapped("日 a", 1), []string{"", "a"}; !slices.Equal(got, want) {
		t.Fatalf("FitWrapped at width 1 = %q, want %q", got, want)
	}
}

// TestWrapKeepsALeadingIndent pins the indent rule the trace filter's
// "         ^dir/* = ..." note relies on (task rz2): the leading spaces stay
// on the first line while its first word fits after them, the continuation
// lines are not indented, and an indent with no room for the first word is
// dropped rather than put on a line of its own.
func TestWrapKeepsALeadingIndent(t *testing.T) {
	cases := []struct {
		text  string
		width int
		want  []string
	}{
		{"   ab cd", 8, []string{"   ab cd"}},
		{"   ab cd", 7, []string{"   ab", "cd"}},
		{"   ab cd", 5, []string{"   ab", "cd"}},
		{"   ab cd", 4, []string{"ab", "cd"}},
		{"   abcdef", 3, []string{"abc", "def"}},
		{"   ", 5, []string{""}},
	}
	for _, c := range cases {
		if got := WrapAtSpaces(c.text, c.width); !slices.Equal(got, c.want) {
			t.Fatalf("WrapAtSpaces(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
	}
}

// TestFitWrappedStaysWithinTheWidth checks every line FitWrapped returns is
// at most the width, wide runes, emoji and keycaps included, from one cell.
func TestFitWrappedStaysWithinTheWidth(t *testing.T) {
	texts := []string{
		"Error: open /tmp/日本語/ファイル.parquet: permission denied",
		"😀😀😀 emoji 👩‍👩‍👧 family 1️⃣ keycap",
		"         ^dir/* = files directly in dir (case-sensitive, no subdirs)",
	}
	for _, text := range texts {
		for width := 1; width <= 40; width++ {
			for _, line := range FitWrapped(text, width) {
				if got := DisplayWidth(line); got > width {
					t.Fatalf("FitWrapped(%q, %d): line %q is %d cells", text, width, line, got)
				}
			}
		}
	}
}
