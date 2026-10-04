package common

import "testing"

// blankLookalikeCases are the space and blank-glyph lookalikes of task ms2:
// each must become the visible '?', so a traced name cannot pose as another
// one in the operator's TUI, while an ordinary space and neighbouring text
// (CJK, Braille dots, emoji) stay as they are.
var blankLookalikeCases = []struct{ name, in, want string }{
	{"Braille blank in name", "pass\u2800wd", "pass?wd"},
	{"no-break space in path", "etc\u00a0passwd", "etc?passwd"},
	{"ideographic space in CJK name", "日本\u3000語", "日本?語"},
	{"en quad", "a\u2000b", "a?b"},
	{"em space", "a\u2003b", "a?b"},
	{"hair space", "a\u200ab", "a?b"},
	{"narrow no-break space", "a\u202fb", "a?b"},
	{"medium mathematical space", "a\u205fb", "a?b"},
	{"Ogham space mark", "a\u1680b", "a?b"},
	{"object replacement", "a\ufffcb", "a?b"},
	{"Khitan filler", "a\U00016FE4b", "a?b"},
	{"musical null notehead", "a\U0001D159b", "a?b"},
	{"ideographic half fill space", "a\u303fb", "a?b"},
	{"hieroglyph full blank", "a\U00013441b", "a?b"},
	{"hieroglyph half blank", "a\U00013442b", "a?b"},
	{"ASCII space kept", "etc passwd", "etc passwd"},
	{"Braille dots kept", "⠁⣿", "⠁⣿"},
	{"CJK and emoji kept", "日本語 \U0001F600", "日本語 \U0001F600"},
	{"replacement character kept", "a\ufffdb", "a\ufffdb"},
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

// Scripts for the clean-text Sanitize benchmarks. Each string is plain text
// without a single rune that Sanitize replaces, so the benchmark measures the
// per-rune cost of the "is it safe?" scan for that script: Latin-1 letters
// sit at U+00C0..U+00FF, Cyrillic at U+0400..U+04FF and CJK at U+4E00..U+9FFF,
// which are the ranges the IsBlankLookalike early returns skip or scan.
const (
	benchLatin1   = "Größe_übersicht_café_à_la_crème_ñoño_ångström.txt"
	benchCyrillic = "Документы/Отчёт_за_год_2024.pdf"
	benchCJK      = "文档/日本語のファイル/中文报告_最终版.txt"
)

func benchmarkSanitize(b *testing.B, s string) {
	if Sanitize(s) != s {
		b.Fatalf("benchmark input %q is not clean", s)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = Sanitize(s)
	}
}

func BenchmarkSanitizeLatin1(b *testing.B)   { benchmarkSanitize(b, benchLatin1) }
func BenchmarkSanitizeCyrillic(b *testing.B) { benchmarkSanitize(b, benchCyrillic) }
func BenchmarkSanitizeCJK(b *testing.B)      { benchmarkSanitize(b, benchCJK) }
