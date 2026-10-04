package export

import (
	"errors"
	"strings"
	"testing"
)

// TestViewSanitizesStatus verifies export status lines echoing a path or an
// error with escape sequences reach the terminal without them (task io2).
func TestViewSanitizesStatus(t *testing.T) {
	for _, msg := range []any{
		CompletedMsg{Path: "/tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a.csv"},
		FailedMsg{Err: errors.New("open /tmp/\x1b[8mhidden\x9b: denied")},
	} {
		m, _ := NewModel().Open().Update(msg)
		out := m.View(100, 30)
		for _, bad := range []string{"\x1b]8", "\x1b[8m", "\a", "\x9b"} {
			if strings.Contains(out, bad) {
				t.Fatalf("view for %T contains %q: %q", msg, bad, out)
			}
		}
	}
}
