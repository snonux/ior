package eventstream

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
)

// assertViewFits checks the height budget and that no line of a full stream
// view is wider than the terminal (a wider line wraps and scrolls the panel's
// top off-screen).
func assertViewFits(t *testing.T, label string, width, height int, out string) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) > height {
		t.Fatalf("%s width %d: %d lines exceed height %d\n%s", label, width, len(lines), height, out)
	}
	for _, line := range lines {
		if w := lipgloss.Width(line); w > width {
			t.Fatalf("%s width %d: line is %d cols wide: %q", label, width, w, line)
		}
	}
}

// newFooterTestModel returns a model with more events than fit on screen, a
// filter stack (the tallest panel layout) and a long status message mixing
// wide runes and control characters.
func newFooterTestModel(t *testing.T) Model {
	t.Helper()
	rb := NewRingBuffer()
	m := NewModel(rb)
	pushEvents(rb, 200)
	m.Refresh()
	m.filterStack = []string{strings.Repeat("comm~x", 30)}
	m.SetStatusMessage("Exported to /tmp/日本語\x1b[8m/" + strings.Repeat("very-long-dir/", 12) + "out.csv\nsecond line")
	return m
}

// Regression for task wo2: the paused footer "Row x/N | Sel x/N Col x/N |
// Enter push-filter | T fd-trace | Esc/F undo" is ~90 columns and the status
// message was unbounded; neither was fitted to the width, so both wrapped
// below ~90 columns and pushed the panel off-screen.
func TestStreamViewFitsAtAnyWidth(t *testing.T) {
	const height = 24
	m := newFooterTestModel(t)
	for width := 20; width <= 160; width++ {
		assertViewFits(t, "live", width, height, m.View(width, height))
	}
	if !pressLocal(t, &m, "space") || !m.paused || m.selectedIdx < 0 {
		t.Fatalf("space should pause with a selection")
	}
	// The exit hint must survive narrowing for as long as the selection
	// segment in front of it fits.
	sel := m.streamFooterSegments(0)[0]
	if !strings.HasPrefix(sel, "Sel ") {
		t.Fatalf("paused footer should lead with the selection, got %q", sel)
	}
	undoFrom := len(sel + footerSep + "Esc/F undo")
	for width := 20; width <= 160; width++ {
		out := m.View(width, height)
		assertViewFits(t, "paused", width, height, out)
		if !strings.Contains(out, "Sel ") {
			t.Fatalf("width %d: paused footer lost its Sel segment:\n%s", width, out)
		}
		if width >= undoFrom && !strings.Contains(out, "Esc/F undo") {
			t.Fatalf("width %d: paused footer lost the Esc/F undo hint:\n%s", width, out)
		}
		if strings.Contains(out, "\x1b[8m") {
			t.Fatalf("width %d: status message escape sequence was not sanitised", width)
		}
	}
	want := sel + " | Esc/F undo | Enter push-filter | T fd-trace | Row "
	if out := m.View(160, height); !strings.Contains(out, want) {
		t.Fatalf("wide paused footer should keep every segment in priority order %q:\n%s", want, out)
	}
	if out := m.View(undoFrom, height); !strings.Contains(out, "\n"+sel+" | Esc/F undo\n") {
		t.Fatalf("narrow paused footer should be the compact Sel + undo form:\n%s", out)
	}
}

// TestFDTraceViewFitsAtAnyWidth checks the fd-trace view's height budget and
// line widths, and that its "esc:back" exit hint survives every width.
func TestFDTraceViewFitsAtAnyWidth(t *testing.T) {
	const height = 24
	m := newFooterTestModel(t)
	m.fdTraceView.visible = true
	m.fdTraceView.events = m.filtered
	for width := 20; width <= 160; width++ {
		out := m.View(width, height)
		assertViewFits(t, "fd-trace", width, height, out)
		if !strings.Contains(out, "\nesc:back") {
			t.Fatalf("width %d: fd-trace footer lost the esc:back hint:\n%s", width, out)
		}
	}
	if out := m.View(160, height); !strings.HasSuffix(out, "\nesc:back | FD Trace Row 1/200 | j/k:scroll") {
		t.Fatalf("wide fd-trace footer should keep every segment:\n%s", out)
	}
}

func TestFitFooterSegments(t *testing.T) {
	segs := []string{"Row 1/10", "Sel 2/10 Col 3/10", "Enter push-filter"}
	tests := []struct {
		name     string
		segments []string
		width    int
		want     string
	}{
		{"all fit", segs, 100, "Row 1/10 | Sel 2/10 Col 3/10 | Enter push-filter"},
		{"exact fit", segs, 48, "Row 1/10 | Sel 2/10 Col 3/10 | Enter push-filter"},
		{"one short drops last segment", segs, 47, "Row 1/10 | Sel 2/10 Col 3/10"},
		{"only first segment", segs, 20, "Row 1/10"},
		{"first segment exactly", segs, 8, "Row 1/10"},
		{"first segment cut", segs, 7, "Row ..."},
		{"wide runes measured in cells", []string{"日本", "語"}, 6, "日本"},
		{"zero width", segs, 0, ""},
		{"negative width", segs, -5, ""},
		{"no segments", nil, 80, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fitFooterSegments(tt.segments, tt.width); got != tt.want {
				t.Fatalf("fitFooterSegments(%q, %d) = %q, want %q", tt.segments, tt.width, got, tt.want)
			}
		})
	}
}

func TestStatusMessageTruncatedToWidth(t *testing.T) {
	m := newFooterTestModel(t)
	out := m.View(40, 24)
	last := out[strings.LastIndex(out, "\n")+1:]
	if !strings.HasPrefix(last, "Exported to /tmp/日本語?[8m/") || !strings.HasSuffix(last, "...") {
		t.Fatalf("status line should be sanitised and cut with a tail, got %q", last)
	}
	if w := lipgloss.Width(last); w > 40 {
		t.Fatalf("status line is %d cols wide", w)
	}
}

// The stream view never outgrows the height it is handed from six rows up,
// whatever it has to show besides the table: the filter-stack line, the
// paused footer and a status message are each dropped before the view would
// be taller (the table keeps one event row), and come back with the rows.
func TestStreamViewFitsItsHeightWithEveryExtraLine(t *testing.T) {
	rb := NewRingBuffer()
	for i := range 50 {
		rb.Push(StreamEvent{Seq: uint64(i + 1), Syscall: "read", Comm: "proc", PID: 7, FD: UnknownFD})
	}
	m := NewModel(rb)
	m.Refresh()
	m.SetFilterStack([]string{"pid=7"})
	m.HandleKey(" ")
	if !m.Paused() {
		t.Fatal("space did not pause the stream")
	}
	m.SetStatusMessage("exported")
	for height := 6; height <= 30; height++ {
		out := m.View(100, height)
		if got := lipgloss.Height(out); got > height {
			t.Fatalf("height %d: view is %d rows:\n%s", height, got, out)
		}
		// Every extra line is back once the table no longer needs the row.
		if height >= 9 {
			for _, tok := range []string{"pid=7", "Sel ", "exported"} {
				if !strings.Contains(out, tok) {
					t.Fatalf("height %d: %q missing:\n%s", height, tok, out)
				}
			}
		}
	}
}

// A status message outranks the filter-stack line (task ls2): with one row
// to spare beside the panel and its single event row (a 7-row stream body,
// a 9-row terminal with the help bar off), "Export failed" takes it and the
// stack line, which the dashboard status line summarises, is dropped. With
// no message, or with a row more, the stack line is back.
func TestStatusMessageOutranksTheFilterStack(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 20)
	m := NewModel(rb)
	m.Refresh()
	m.SetFilterStack([]string{"pid=7"})
	m.HandleKey(" ")
	m.SetStatusMessage("Export failed: no such directory")
	out := m.View(100, 7)
	if got := lipgloss.Height(out); got > 7 {
		t.Fatalf("7 rows: view is %d rows:\n%s", got, out)
	}
	if !strings.Contains(out, "Export failed") || strings.Contains(out, "pid=7") {
		t.Fatalf("7 rows: want the message in place of the stack line:\n%s", out)
	}
	if out := m.View(100, 8); !strings.Contains(out, "Export failed") || !strings.Contains(out, "pid=7") {
		t.Fatalf("8 rows: want the message and the stack line:\n%s", out)
	}
	m.SetStatusMessage("")
	if out := m.View(100, 7); !strings.Contains(out, "pid=7") {
		t.Fatalf("7 rows, no message: want the stack line:\n%s", out)
	}
}

// The FD-trace overlay fits its height from six rows up too (task ls2): its
// panel keeps one event row, so at six rows it drops its footer line instead
// of drawing seven lines and losing the last to the dashboard's clip; from
// seven rows up the footer and its "esc:back" hint are back.
func TestFDTraceViewFitsItsHeight(t *testing.T) {
	m := newFooterTestModel(t)
	m.fdTraceView.visible = true
	m.fdTraceView.events = m.filtered
	for height := 6; height <= 30; height++ {
		out := m.View(100, height)
		if got := lipgloss.Height(out); got > height {
			t.Fatalf("height %d: fd-trace view is %d rows:\n%s", height, got, out)
		}
		if got, want := strings.Contains(out, "\nesc:back"), height >= 7; got != want {
			t.Fatalf("height %d: footer shown = %v, want %v:\n%s", height, got, want, out)
		}
	}
}

// With a single row free below the table, a status message takes it in
// place of the Row/Sel line: it is how "Export failed", "Invalid regex" and
// "No match" reach the user, while Row/Sel only repeats what the table's
// selection shows. A second free row brings Row/Sel back above it, and with
// no message the row is Row/Sel's (task ls2).
func TestStatusMessageTakesTheOnlySpareRow(t *testing.T) {
	m := NewModel(NewRingBuffer())
	m.width = 100
	const base = "table"
	m.SetStatusMessage("Export failed: no such directory")
	if got := m.appendStreamFooter(base, 0, 1); got != base+"\nExport failed: no such directory" {
		t.Fatalf("one spare row: %q, want the message alone", got)
	}
	if got := m.appendStreamFooter(base, 0, 2); got != base+"\nRow 0/0\nExport failed: no such directory" {
		t.Fatalf("two spare rows: %q, want Row/Sel above the message", got)
	}
	if got := m.appendStreamFooter(base, 0, 0); got != base {
		t.Fatalf("no spare row: %q, want the table alone", got)
	}
	m.SetStatusMessage("")
	if got := m.appendStreamFooter(base, 0, 1); got != base+"\nRow 0/0" {
		t.Fatalf("one spare row, no message: %q, want Row/Sel", got)
	}
}
