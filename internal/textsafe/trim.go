package textsafe

import "unicode/utf8"

// TrimPartialRune drops a trailing, incomplete-but-so-far-valid UTF-8
// sequence from s. Traced text is cut by bytes in several places (the kernel
// stores comm in a 16-byte buffer, 15 characters plus NUL; the BPF side
// captures a path in a MAX_FILENAME_LENGTH buffer), so a name such as
// "ääääääääää" ends in a lone lead byte 0xc3. That byte is not corrupt data
// but the cut-off half of a rune, so dropping it yields the longest valid
// prefix, which reads better than a "\xc3" escape. A trailing byte that is
// genuinely invalid (not the start of a longer valid sequence) is left alone
// for Escape or a strict-UTF-8 sanitizer to deal with.
//
// Callers must only apply it where a byte-wise cut is known to be possible
// (the value is exactly at the buffer limit); on other values a trailing lone
// lead byte is real data.
func TrimPartialRune(s string) string {
	// A UTF-8 sequence is at most 4 bytes, so its lead byte is among the
	// last utf8.UTFMax-1 bytes when it is cut short.
	for i := len(s) - 1; i >= 0 && i >= len(s)-(utf8.UTFMax-1); i-- {
		if !utf8.RuneStart(s[i]) {
			continue
		}
		if !utf8.FullRuneInString(s[i:]) {
			return s[:i]
		}
		return s
	}
	return s
}
