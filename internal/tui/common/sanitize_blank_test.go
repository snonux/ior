package common

import "testing"

// blankLookalikeCases are the space and blank-glyph lookalikes of task ms2:
// each must become the visible '?', so a traced name cannot pose as another
// one in the operator's TUI, while an ordinary space and neighbouring text
// (CJK, Braille dots, emoji) stay as they are.
var blankLookalikeCases = []struct{ name, in, want string }{
	{"Braille blank in name", "pass⠀wd", "pass?wd"},
	{"no-break space in path", "etc passwd", "etc?passwd"},
	{"ideographic space in CJK name", "日本　語", "日本?語"},
	{"en quad", "a b", "a?b"},
	{"em space", "a b", "a?b"},
	{"hair space", "a b", "a?b"},
	{"narrow no-break space", "a b", "a?b"},
	{"medium mathematical space", "a b", "a?b"},
	{"Ogham space mark", "a b", "a?b"},
	{"object replacement", "a￼b", "a?b"},
	{"Khitan filler", "a\U00016FE4b", "a?b"},
	{"musical null notehead", "a\U0001D159b", "a?b"},
	{"ASCII space kept", "etc passwd", "etc passwd"},
	{"Braille dots kept", "⠁⣿", "⠁⣿"},
	{"CJK and emoji kept", "日本語 \U0001F600", "日本語 \U0001F600"},
	{"replacement character kept", "a�b", "a�b"},
}

// TestSanitizeReplacesBlankLookalikes checks the replacement, idempotence and
// that a replaced two-cell ideographic space is measured as the one cell '?'
// it now renders as, so column fitting stays exact.
func TestSanitizeReplacesBlankLookalikes(t *testing.T) {
	for _, tt := range blankLookalikeCases {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.in)
			if got != tt.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
			}
			if again := Sanitize(got); again != got {
				t.Fatalf("Sanitize is not idempotent: %q -> %q", got, again)
			}
			for _, width := range []int{1, 3, 8, 20} {
				if w := DisplayWidth(FitRight(got, width, ASCIIEllipsis)); w != width {
					t.Fatalf("FitRight(%q, %d) width = %d", got, width, w)
				}
			}
		})
	}
}
