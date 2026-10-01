package textsafe

import "unicode"

// blankSymbols are the code points outside the space class that render as an
// empty cell or an empty glyph box in practice, so a traced name can use them
// as a stand-in for a space or as an invisible filler. None of them is a
// default-ignorable code point (those are IsInvisibleFormat's job) and none is
// in unicode.Zs; the Unicode tables carry no property for "renders blank",
// hence this short, pinned list:
//
//   - U+2800 BRAILLE PATTERN BLANK (So): a full-width blank cell in most fonts;
//   - U+303F IDEOGRAPHIC HALF FILL SPACE (So): the half-width sibling of
//     U+3000 IDEOGRAPHIC SPACE, an empty cell although it is a symbol and not
//     a space separator;
//   - U+FFFC OBJECT REPLACEMENT CHARACTER (So): a placeholder for an inline
//     object that terminals draw as nothing or as a box;
//   - U+13441 EGYPTIAN HIEROGLYPH FULL BLANK and U+13442 EGYPTIAN HIEROGLYPH
//     HALF BLANK (Lo): letters whose glyph is an empty (full or half) quadrat;
//   - U+16FE4 KHITAN SMALL SCRIPT FILLER (Mn): a zero-width filler mark;
//   - U+1D159 MUSICAL SYMBOL NULL NOTEHEAD (So): a notehead without a glyph.
//
// Deliberately NOT listed: the zero-width joiner-like marks U+2D7F TIFINAGH
// CONSONANT JOINER, U+1107F BRAHMI NUMBER JOINER, U+113D0 TULU-TIGALARI
// CONJOINER, U+11A47 ZANABAZAR SQUARE SUBJOINER, U+11A99 SOYOMBO SUBJOINER and
// U+11F42 KAWI CONJOINER (all Mn). They render nothing by themselves, but
// like a virama they exist to change how the neighbouring letters are shaped
// (a conjunct, a stacked consonant), so they are part of legitimate text in
// those scripts, and replacing them would break such names, the same trade
// that ZWJ/ZWNJ get in ClassAt, but without a per-script context rule to
// keep the visible uses. They are therefore a known, accepted residual gap
// (a joiner glued to Latin text is invisible). U+16FE4 differs: it is a filler
// whose only job is to occupy a position, it shapes nothing and has no
// legitimate use in running text, so escaping it costs nothing.
//
// The Go unicode tables are Unicode 15.0, so code points that later Unicode
// versions add to Cf, Zs or the lists above (for example U+113D0, which is
// unassigned for Go) pass as Safe until Go updates its tables;
// TestBlankSymbolsArePinned and TestBlankLookalikeMatchesTables then pick the
// new version up.
//
// TestBlankSymbolsArePinned fails when one of them stops being outside Zs/Cf,
// so the list cannot silently go stale when Go updates its Unicode tables.
var blankSymbols = [...]rune{0x2800, 0x303F, 0xFFFC, 0x13441, 0x13442, 0x16FE4, 0x1D159}

// Bounds of the cheap early returns in IsBlankLookalike, derived from the
// sets it matches (TestBlankLookalikeBounds sweeps every code point against
// them): U+00A0 is the only match below U+1680 (U+1680 OGHAM SPACE MARK is
// the next Zs rune after it) and U+3000 IDEOGRAPHIC SPACE is the last Zs rune,
// so above it only the pinned blankSymbols can match.
const (
	noBreakSpace = 0x00A0
	firstWideZs  = 0x1680
	lastZs       = 0x3000
)

// IsBlankLookalike reports whether r renders as an empty or space-width cell
// although it is not the ASCII space: a file named "etc\u00a0passwd" or
// "pass\u2800wd" would otherwise look identical to "etc passwd" or "passwd"
// in a root operator's terminal. It is defined by Unicode class where one
// exists, so new code points are covered when Go updates its tables:
//
//   - every unicode.Zs rune except U+0020: U+00A0 no-break space, U+1680 Ogham
//     space mark, U+2000..U+200A (en/em/thin/hair ... spaces), U+202F narrow
//     no-break space, U+205F medium mathematical space and U+3000 ideographic
//     space (the other space-like runes, U+0085, U+2028 and U+2029, are
//     already controls or caught by IsInvisibleFormat);
//   - the blankSymbols above.
//
// Decision (task ms2): U+00A0 and U+3000 are replaced too, although they occur
// in legitimate European and CJK file names. An operator who sees "?" (TUI) or
// `\u3000` (-plain on a terminal) for them loses a little readability but can
// tell them from a real space, while keeping them would leave exactly the
// "same-looking, different name" hole this package exists to close. Raw
// output (-escape=never, or a pipe under -escape=auto) and the Parquet/CSV
// exports keep the original bytes.
//
// Cost: Sanitize asks this for every non-ASCII rune of a clean string, and
// unicode.Is(Zs) is a scan over a short table. The bounds above reject
// everything below U+1680 other than U+00A0 (so Latin-1 letters such as
// \u00e9, Greek, Cyrillic, Hebrew and Arabic cost two comparisons and no
// table lookup) and let the runes above U+3000 (CJK, Hangul, emoji) skip the
// Zs scan and only be compared with the pinned runes.
func IsBlankLookalike(r rune) bool {
	if r < firstWideZs {
		return r == noBreakSpace
	}
	for _, blank := range blankSymbols {
		if r == blank {
			return true
		}
	}
	return r <= lastZs && unicode.Is(unicode.Zs, r)
}
