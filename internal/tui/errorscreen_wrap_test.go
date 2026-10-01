package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
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

// TestErrorScreenFitsNarrowTerminals: the key hint is 13 columns wide (21 for
// the recoverable "esc  back  •  q  quit") and used to be drawn uncut, so on
// a narrower terminal its line ran past the right edge; only the height was
// fitted. Every line must fit at every width from 1 to 24 columns, for both
// hints, at a tall and a short height, and the hint must still start with its
// first key. The body is checked too: lipgloss keeps a warning row's "  - "
// indent whole when wrapping, a 2-cell rune cannot fit one column, and a
// keycap is counted 1 cell by ansi's wrap but 2 by the terminal.
func TestErrorScreenFitsNarrowTerminals(t *testing.T) {
	err := errors.New("failed to load BPF object: permission denied\nWarnings logged during setup:\n  - libbpf: prog 'ior_x': verifier: R1 invalid mem access 'scalar'\n  - open /tmp/漢字" + keycap + keycap + keycap)
	kinds := []struct {
		kind  errorScreenKind
		first string
	}{{errorScreenFatal, "q"}, {errorScreenRecoverable, "e"}}
	for _, k := range kinds {
		for width := 1; width <= 24; width++ {
			for _, height := range []int{40, 3, 1} {
				m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
				m.router.showDashboard()
				m.attaching = false
				m.width, m.height = width, height
				m.setError(err, k.kind)

				view := ansi.Strip(m.View().Content)
				assertLinesFit(t, m.View().Content, width, height)
				lines := strings.Split(view, "\n")
				hint := strings.TrimSpace(lines[len(lines)-1])
				if height == 40 {
					// Placed at the top: the hint is the last non-blank line.
					for i := len(lines) - 1; i >= 0 && hint == ""; i-- {
						hint = strings.TrimSpace(lines[i])
					}
				}
				if !strings.HasPrefix(hint, k.first) {
					t.Fatalf("kind %v width %d height %d: hint line %q lost its first key:\n%s", k.kind, width, height, hint, view)
				}
			}
		}
	}
}

// TestWrapErrorTextWrapsRatherThanCuts: an over-wide line (an indent, a word
// longer than the terminal) is broken onto further lines, so no text is lost;
// only a grapheme wider than the terminal itself is dropped. Leading blanks
// that do not fit with the next word go with the break, as at any other word
// break.
func TestWrapErrorTextWrapsRatherThanCuts(t *testing.T) {
	cases := []struct {
		text  string
		width int
		want  string
	}{
		{"  - abc\nx", 2, "  \n-\nab\nc\nx"},
		{"foo bar baz quux", 7, "foo bar\nbaz\nquux"},
	}
	for _, c := range cases {
		if got := wrapErrorText(c.text, c.width); got != c.want {
			t.Errorf("wrapErrorText(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
	}
	if got := wrapErrorText("漢", 1); ansi.StringWidth(got) > 1 {
		t.Errorf("wrapErrorText(wide rune, 1) = %q, wider than 1", got)
	}
}

// TestWrapErrorTextKeepsGraphemesWhole: lipgloss's Width wrap (used before)
// broke "yyyye\u0301x" at 5 columns between the "e" and its combining accent,
// so the accent started the next line on its own. Every line must start and
// end on a grapheme boundary (but for the documented space+mark case), be at
// most width cells by ansi.StringWidth, and the text must survive the wrap.
// keycap is "1" + U+FE0F + U+20E3: one grapheme, 2 cells by ansi.StringWidth
// but 1 by ansi.Wordwrap, Hardwrap and Truncate.
const keycap = "1\ufe0f\u20e3"

func TestWrapErrorTextKeepsGraphemesWhole(t *testing.T) {
	cases := []struct {
		text  string
		width int
		want  string
	}{
		{"yyyye\u0301x", 5, "yyyye\u0301\nx"},
		{"ae\u0301\u0301b", 2, "ae\u0301\u0301\nb"},
		{"warn: cafe\u0301 cafe\u0301", 8, "warn:\ncafe\u0301\ncafe\u0301"},
		// Keycaps: ansi's wrap and Truncate count each as 1 cell, StringWidth
		// (lipgloss, the terminal) as 2; the lines are re-broken by the latter.
		{keycap + keycap + keycap, 4, keycap + keycap + "\n" + keycap},
		{"x" + keycap + "verylongword", 2, "x\n" + keycap + "\nve\nry\nlo\nng\nwo\nrd"},
		{"#\ufe0f\u20e3ab", 3, "#\ufe0f\u20e3a\nb"},
		// Too wide for the whole terminal: dropped, never shown 2 cells wide.
		{keycap, 1, ""},
		{"a" + keycap + "b", 1, "a\n\nb"},
		// The documented exception: a space+mark cluster at a word break loses
		// its space like any break, the zero-width mark leads the next line.
		{"x \u0301y", 2, "x\n\u0301y"},
		// That orphan mark before a keycap: ansi.Truncate cuts mark+keycap as
		// one cell, StringWidth measures 2, so TruncateRight at width 1 keeps
		// nothing; the mark fits and must not be dropped with the keycap.
		{"x \u0301" + keycap + "y", 1, "x\n\u0301\ny"},
		{"x \u0301" + keycap + "y", 2, "x\n\u0301" + keycap + "\ny"},
		{"x \u0301" + keycap + "y", 3, "x\n\u0301" + keycap + "y"},
		{"x \u0301" + keycap + "y", 4, "x \u0301" + keycap + "\ny"},
		{"\u0301\u0301" + keycap + "ab", 1, "\u0301\u0301\na\nb"},
	}
	for _, c := range cases {
		got := wrapErrorText(c.text, c.width)
		if got != c.want {
			t.Errorf("wrapErrorText(%q, %d) = %q, want %q", c.text, c.width, got, c.want)
		}
		for _, line := range strings.Split(got, "\n") {
			if w := ansi.StringWidth(line); w > c.width {
				t.Errorf("wrapErrorText(%q, %d): line %q is %d cells wide", c.text, c.width, line, w)
			}
		}
		// A zero-width mark always fits, so none may be lost.
		if in, out := strings.Count(c.text, "́"), strings.Count(got, "́"); in != out {
			t.Errorf("wrapErrorText(%q, %d) = %q kept %d of %d combining marks", c.text, c.width, got, out, in)
		}
	}
}

// TestErrorScreenKeepsCombiningMarksOnTheirLine: the same through the view,
// with the error style applied: no line of the screen starts with a
// combining mark.
func TestErrorScreenKeepsCombiningMarksOnTheirLine(t *testing.T) {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	m.attaching = false
	m.width, m.height = 5, 20
	m.setError(errors.New("yyyye\u0301x"), errorScreenFatal)

	for _, line := range strings.Split(ansi.Strip(m.View().Content), "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "\u0301") {
			t.Fatalf("a line starts with the combining accent: %q", line)
		}
	}
}

// TestErrorScreenFitsWithKeycapsAtEverySize sweeps the full view over widths
// 1..40 and heights 1..10 with keycap-laden text: ansi's wrap counts a keycap
// as 1 cell and lipgloss pads every line to the widest, so one miscounted line
// used to widen the whole screen past the terminal.
func TestErrorScreenFitsWithKeycapsAtEverySize(t *testing.T) {
	text := "warn " + strings.Repeat(keycap, 9) + " x" + keycap + "verylongword #\ufe0f\u20e3 漢字 " + keycap + " \u0301" + keycap
	for width := 1; width <= 40; width++ {
		for height := 1; height <= 10; height++ {
			m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
			m.router.showDashboard()
			m.attaching = false
			m.width, m.height = width, height
			m.setError(errors.New(text), errorScreenFatal)
			assertLinesFit(t, m.View().Content, width, height)
		}
	}
}

// assertLinesFit fails when the rendered view has more than height lines or a
// line wider than width, measured both with ansi.StringWidth (on the stripped
// line) and lipgloss.Width (on the styled one), the measures the terminal
// layout relies on.
func assertLinesFit(t *testing.T, view string, width, height int) {
	t.Helper()
	lines := strings.Split(view, "\n")
	if len(lines) > height {
		t.Fatalf("width %d height %d: %d lines:\n%s", width, height, len(lines), view)
	}
	for _, line := range lines {
		sw, lw := ansi.StringWidth(ansi.Strip(line)), lipgloss.Width(line)
		if sw > width || lw > width {
			t.Fatalf("width %d height %d: line of width %d (lipgloss %d): %q", width, height, sw, lw, ansi.Strip(line))
		}
	}
}
