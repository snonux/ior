package globalfilter

import "unicode/utf8"

// The helpers in this file implement the allocation-free ASCII branch of
// matchString. They compare byte by byte with ASCII case folding, which for
// ASCII input is identical to comparing the strings.ToLower forms.

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// matchFoldASCII applies the case-insensitive anchor modes of matchString
// (substring, prefix, suffix) to an ASCII pattern (anchors already stripped)
// and an ASCII value, ignoring case. The exact mode (both anchors) never
// reaches it: exact matching is case-sensitive and matchString compares it
// directly.
func matchFoldASCII(pattern, value string, anchoredStart, anchoredEnd bool) bool {
	switch {
	case anchoredStart:
		return len(value) >= len(pattern) && equalFoldASCII(value[:len(pattern)], pattern)
	case anchoredEnd:
		return len(value) >= len(pattern) && equalFoldASCII(value[len(value)-len(pattern):], pattern)
	default:
		return containsFoldASCII(value, pattern)
	}
}

// lowerASCII returns the ASCII lower-case form of b.
func lowerASCII(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// equalFoldASCII reports whether the equal-length ASCII strings a and b are
// equal ignoring case.
func equalFoldASCII(a, b string) bool {
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

// containsFoldASCII reports whether the ASCII string s contains substr,
// ignoring case. Filter values are short (names, paths), so a direct scan is
// cheaper than building lowered copies for strings.Contains.
func containsFoldASCII(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}
