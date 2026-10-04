package internal

import (
	"math/rand/v2"
	"strings"
	"testing"
	"unicode/utf8"
)

// shortenPropertyPieces are the fragments random warnings are built from: the
// characters shortenWarning treats specially ("\r", "\n", blanks), multibyte
// runes (2-, 3- and 4-byte, so cuts land inside them), the PROG LOAD LOG
// banners and every marker form splitMoreLinesMarker parses, including the
// ones it must reject.
var shortenPropertyPieces = []string{
	"a", "b", " ", "\t", "\r", "\n", "\r\n", "é", "€", "😀", "\x80",
	"prog 'x': ", progLoadLogBegin, progLoadLogEnd,
	moreLinesPrefix, moreLinesSuffix, moreLineSuffix, "1", "2", "0", "...",
	" ... (1 more line)", " ... (3 more lines)", " ... (1 more lines)",
	strings.Repeat("v", 70),
}

// randomWarning joins up to 24 random pieces, deterministically from rng.
func randomWarning(rng *rand.Rand) string {
	var b strings.Builder
	for range rng.IntN(25) {
		b.WriteString(shortenPropertyPieces[rng.IntN(len(shortenPropertyPieces))])
	}
	return b.String()
}

// TestShortenWarningProperties checks, over seeded random warnings and limits
// 0..40 plus the production bound, every promise shortenWarning makes: the
// row fits the limit, is a single line, stays valid UTF-8 for valid input and
// is a fixed point (shortening it again with the same bound changes nothing).
// The last one used to fail below 3 bytes, where a cut has no ellipsis and
// could end in the "\r" a second pass trims: "a\rb" at limit 2 gave "a\r",
// then "a".
func TestShortenWarningProperties(t *testing.T) {
	rng := rand.New(rand.NewPCG(2, 7))
	limits := []int{maxRoutedWarningBytes}
	for limit := 0; limit <= 40; limit++ {
		limits = append(limits, limit)
	}
	inputs := []string{"\r-- END PROG LOAD LOG --", "a\rb", "\r", "a\r\r\nb"}
	for range 3000 {
		inputs = append(inputs, randomWarning(rng))
	}
	for _, in := range inputs {
		for _, limit := range limits {
			checkShortenWarningProperties(t, in, limit)
		}
	}
}

// checkShortenWarningProperties asserts the shortenWarning properties for one
// input and limit; see TestShortenWarningProperties.
func checkShortenWarningProperties(t *testing.T, in string, limit int) {
	t.Helper()
	once := shortenWarning(in, limit)
	switch {
	case len(once) > max(limit, 0):
		t.Errorf("shortenWarning(%q, %d) = %q: %d bytes", in, limit, once, len(once))
	case strings.Contains(once, "\n"):
		t.Errorf("shortenWarning(%q, %d) = %q: more than one line", in, limit, once)
	case utf8.ValidString(in) && !utf8.ValidString(once):
		t.Errorf("shortenWarning(%q, %d) = %q: invalid UTF-8", in, limit, once)
	}
	if twice := shortenWarning(once, limit); twice != once {
		t.Errorf("shortenWarning(%q, %d) not idempotent:\n once  %q\n twice %q", in, limit, once, twice)
	}
}
