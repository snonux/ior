package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
)

// TestErrorScreenWrapsLongWarningRowsToTheTerminalWidth: a failed trace setup
// puts its libbpf warning rows (hundreds of bytes each, e.g. the verifier's
// reason) into the error text. On a narrow terminal the view used to clip such
// a row at the screen edge, hiding the part the user needs; it must wrap.
func TestErrorScreenWrapsLongWarningRowsToTheTerminalWidth(t *testing.T) {
	const width = 60
	reason := "R1 invalid mem access 'scalar' | processed 2 insns (limit 1000000) max_states_per_insn 0 total_states 0"
	err := errors.New("failed to load BPF object: permission denied\nWarnings logged during setup:\n  - libbpf: prog 'ior_x': verifier: " + reason)

	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width = width
	m.height = 30
	m.setError(err, errorScreenFatal)

	view := ansi.Strip(m.View().Content)
	for _, line := range strings.Split(view, "\n") {
		if w := ansi.StringWidth(line); w > width {
			t.Fatalf("line of width %d exceeds the %d columns: %q", w, width, line)
		}
	}
	// Whitespace-insensitive: wrapping may break the text at any space.
	flat := strings.Join(strings.Fields(view), " ")
	for _, want := range []string{"R1 invalid mem access 'scalar'", "processed 2 insns", "total_states 0"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("wrapped error view lost %q:\n%s", want, view)
		}
	}
}
