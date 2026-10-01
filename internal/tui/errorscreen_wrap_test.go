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

// TestErrorScreenFitsTheTerminalHeight: 8 warning rows of ~520 bytes wrap into
// 50+ lines at 80 columns, and lipgloss.Place does not shorten tall content,
// so the end of the text and the quit hint used to fall off the screen. The
// body must be cut to the rows above the hint with a "(N more lines)" marker,
// down to terminals too short for anything but the hint.
func TestErrorScreenFitsTheTerminalHeight(t *testing.T) {
	var b strings.Builder
	b.WriteString("failed to load BPF object: permission denied\nWarnings logged during setup:")
	for i := 0; i < 8; i++ {
		b.WriteString("\n  - libbpf: prog 'ior_x': verifier: " + strings.Repeat("insn state ", 47))
	}
	err := errors.New(b.String())

	for _, height := range []int{40, 24, 10, 4, 3, 2, 1} {
		m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
		m.router.showDashboard()
		m.attaching = false
		m.width, m.height = 80, height
		m.setError(err, errorScreenFatal)

		view := ansi.Strip(m.View().Content)
		lines := strings.Split(view, "\n")
		if len(lines) > height {
			t.Fatalf("height %d: view has %d lines:\n%s", height, len(lines), view)
		}
		if !strings.Contains(view, "q / esc  quit") {
			t.Fatalf("height %d: quit hint fell off the screen:\n%s", height, view)
		}
		for _, line := range lines {
			if w := ansi.StringWidth(line); w > 80 {
				t.Fatalf("height %d: line of width %d: %q", height, w, line)
			}
		}
		if height >= 4 {
			// Room for at least one body row: the marker says text was cut.
			if !strings.Contains(view, "more lines)") {
				t.Fatalf("height %d: cut body has no marker:\n%s", height, view)
			}
		}
		if height >= 5 && !strings.HasPrefix(view, "failed to load BPF object") {
			t.Fatalf("height %d: the error's first line is not kept first:\n%s", height, view)
		}
	}
}

// TestErrorScreenShowsAShortErrorWhole is the negative twin: an error that
// fits is neither cut nor marked.
func TestErrorScreenShowsAShortErrorWhole(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width, m.height = 80, 6
	m.setError(errors.New("line one\nline two\nline three"), errorScreenFatal)

	view := ansi.Strip(m.View().Content)
	for _, want := range []string{"line one", "line two", "line three", "q / esc  quit"} {
		if !strings.Contains(view, want) {
			t.Fatalf("view lost %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "more lines") {
		t.Fatalf("an error that fits was marked as cut:\n%s", view)
	}
}

func TestFitErrorBody(t *testing.T) {
	body := "a\nb\nc\nd"
	if got := fitErrorBody(body, 4, 80); got != body {
		t.Errorf("fitting body changed: %q", got)
	}
	if got := ansi.Strip(fitErrorBody(body, 3, 80)); got != "a\nb\n... (2 more lines)" {
		t.Errorf("cut body = %q", got)
	}
	if got := ansi.Strip(fitErrorBody(body, 1, 80)); got != "... (4 more lines)" {
		t.Errorf("one-row body = %q", got)
	}
	if got := ansi.Strip(fitErrorBody(body, 1, 6)); got != "... (4" {
		t.Errorf("marker not truncated to the width: %q", got)
	}
	if got := fitErrorBody(body, 0, 80); got != "" {
		t.Errorf("no-room body = %q, want empty", got)
	}
}
