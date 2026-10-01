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
//   - U+FFFC OBJECT REPLACEMENT CHARACTER (So): a placeholder for an inline
//     object that terminals draw as nothing or as a box;
//   - U+16FE4 KHITAN SMALL SCRIPT FILLER (Mn): a zero-width filler mark;
//   - U+1D159 MUSICAL SYMBOL NULL NOTEHEAD (So): a notehead without a glyph.
//
// TestBlankSymbolsArePinned fails when one of them stops being outside Zs/Cf,
// so the list cannot silently go stale when Go updates its Unicode tables.
var blankSymbols = [...]rune{0x2800, 0xFFFC, 0x16FE4, 0x1D159}

// IsBlankLookalike reports whether r renders as an empty or space-width cell
// although it is not the ASCII space: a file named "etc passwd" or
// "pass⠀wd" would otherwise look identical to "etc passwd" or "passwd"
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
// `　` (-plain on a terminal) for them loses a little readability but can
// tell them from a real space, while keeping them would leave exactly the
// "same-looking, different name" hole this package exists to close. Raw
// output (-escape=never, or a pipe under -escape=auto) and the Parquet/CSV
// exports keep the original bytes.
//
// Zs is a short table (a linear scan of seven ranges), and every rune below
// U+00A0 is rejected first, so the hot path for ASCII and Latin-1 text pays a
// single comparison.
func IsBlankLookalike(r rune) bool {
	if r < 0xA0 {
		return false
	}
	for _, blank := range blankSymbols {
		if r == blank {
			return true
		}
	}
	return unicode.Is(unicode.Zs, r)
}
