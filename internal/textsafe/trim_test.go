package textsafe

import "testing"

func TestTrimPartialRune(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"ascii", "kworker/0:1", "kworker/0:1"},
		{"complete two-byte rune", "ä", "ä"},
		{"complete three-byte rune", "a日", "a日"},
		{"kernel cut of 10 umlauts", "äääääää\xc3", "äääääää"},
		{"three-byte rune cut after one byte", "ab\xe6", "ab"},
		{"three-byte rune cut after two bytes", "ab\xe6\x97", "ab"},
		{"four-byte rune cut after three bytes", "a\xf0\x9f\x98", "a"},
		{"complete four-byte rune", "a😀", "a😀"},
		{"only a partial rune", "\xc3", ""},
		// Not the start of a longer valid sequence: left for the caller.
		{"trailing invalid byte", "ab\xff", "ab\xff"},
		{"stray continuation byte", "ab\x80", "ab\x80"},
		{"invalid sequence already full", "a\xe6\x28", "a\xe6\x28"},
		{"invalid byte before valid tail", "\xffab", "\xffab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TrimPartialRune(tt.in); got != tt.want {
				t.Fatalf("TrimPartialRune(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
