package tui

import (
	"strings"
	"testing"
)

// TestHelpOverlayExplainsTheWarningBadge pins the overlay line that says
// what the status line's "warnings: N (7:Stream)" badge points at (task
// ys2), with export on and off.
func TestHelpOverlayExplainsTheWarningBadge(t *testing.T) {
	for _, export := range []bool{true, false} {
		lines := dashboardTabHelpLines(export)
		if last := lines[len(lines)-1]; !strings.Contains(last, "warnings: N (7:Stream)") {
			t.Fatalf("export=%v: last help line %q does not explain the warning badge", export, last)
		}
	}
}
