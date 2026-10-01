package common

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// A message panel is shown when the terminal is small, so no line of it may
// be wider than the width it is given (a wider line soft-wraps into rows the
// caller has not budgeted); the boxed form is three rows, the bare form one.
// Negative control: a wide or unbounded width keeps the whole message.
func TestRenderMessagePanelFitsTheWidth(t *testing.T) {
	const msg = "Latency: terminal too narrow (need >= 26 columns)"
	for width := 1; width <= 60; width++ {
		out := RenderMessagePanel(msg, width)
		for _, line := range strings.Split(out, "\n") {
			if w := lipgloss.Width(line); w > width {
				t.Fatalf("width %d: line is %d cells: %q", width, w, line)
			}
		}
		wantRows := 3
		if width <= MessagePanelChrome {
			wantRows = 1
		}
		if got := lipgloss.Height(out); got != wantRows {
			t.Errorf("width %d: %d rows, want %d:\n%s", width, got, wantRows, out)
		}
	}
	for _, width := range []int{0, 100} {
		if out := RenderMessagePanel(msg, width); !strings.Contains(out, msg) {
			t.Errorf("width %d cut the message:\n%s", width, out)
		}
	}
}
