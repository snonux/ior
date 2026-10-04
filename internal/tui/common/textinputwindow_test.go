package common

import (
	"strings"
	"testing"

	"charm.land/bubbles/v2/textinput"
	"github.com/charmbracelet/x/ansi"
)

// TestFitTextInputKeepsTheCursorAndTypedText sweeps FitTextInput over input
// widths 1..14 and every cursor position of an ASCII and a CJK value,
// moving the cursor right then left as typing and editing do: the drawn
// line is at most width+1 cells (the cursor cell), the cursor is drawn, and
// on the way right (typing) the rune left of the cursor, the one just typed,
// is drawn when it and the cursor fit the line together. (On the way left
// the window moves only as far as the cursor, so the rune left of it may be
// scrolled off: WindowStart's minimal scrolling.)
func TestFitTextInputKeepsTheCursorAndTypedText(t *testing.T) {
	for _, value := range []string{"abcdefghijklmnopqrstuvwxyz", "日本語のファイル名前テスト"} {
		runes := []rune(value)
		for width := 1; width <= 14; width++ {
			ti := textinput.New()
			ti.Prompt = ""
			ti.SetStyles(textinput.DefaultStyles(true))
			ti.SetValue(value)
			ti.Focus()
			start := len(runes)
			positions := make([]int, 0, 2*len(runes)+2)
			for pos := 0; pos <= len(runes); pos++ {
				positions = append(positions, pos)
			}
			for pos := len(runes); pos >= 0; pos-- {
				positions = append(positions, pos)
			}
			for i, pos := range positions {
				ti.SetCursor(pos)
				start = FitTextInput(&ti, start, width)
				view := ti.View()
				plain := ansi.Strip(view)
				if got := ansi.StringWidth(plain); got > width+1 {
					t.Fatalf("%q width %d pos %d: line %q is %d cells", value, width, pos, plain, got)
				}
				if !strings.Contains(view, "\x1b[7") {
					t.Fatalf("%q width %d pos %d: no cursor drawn in %q", value, width, pos, view)
				}
				if pos == 0 || i > len(runes) {
					continue
				}
				typed := string(runes[pos-1])
				if 2*DisplayWidth(typed) <= width+1-1 && !strings.Contains(plain, typed) {
					t.Fatalf("%q width %d pos %d: typed rune %q not drawn in %q", value, width, pos, typed, plain)
				}
			}
		}
	}
}
