package eventstream

import (
	"fmt"
	"strings"
	"testing"

	"ior/internal/tui/common"

	"github.com/charmbracelet/x/ansi"
)

// Task b23: a warning row is one line cut at its end, so the tail of a long
// warning could not be read anywhere. Paused Enter on the row now opens a
// modal with the whole message. The tests drive the model with keys and read
// its view, the path the dashboard draws.

// warningTail is the end of bootClockWarning, which no row width shows.
const warningTail = "be folded with a later call."

// pausedOnWarning returns a paused model of a width x height view holding a
// syscall row and a warning row with message, the warning row selected.
func pausedOnWarning(t *testing.T, message string, width, height int) *Model {
	t.Helper()
	rb := NewRingBuffer()
	rb.Push(widthTestEvents("read")[0])
	rb.Push(NewWarningEvent(2, message))
	m := NewModel(rb)
	m.Refresh()
	m.View(width, height)
	if !pressLocal(t, &m, "space") || !m.paused {
		t.Fatalf("space did not pause the stream")
	}
	m.selectedIdx = 1
	return &m
}

// boxLines returns the text lines inside the modal's border, padding and
// blank lines dropped; the lines of a borderless view are returned trimmed.
func boxLines(view string) []string {
	var lines []string
	for _, line := range strings.Split(ansi.Strip(view), "\n") {
		line = strings.TrimSpace(strings.Trim(strings.TrimSpace(line), "│"))
		if line == "" || strings.ContainsAny(line, "╭╰") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// boxText joins the modal's lines the way a reader does, one space between.
func boxText(view string) string {
	return strings.Join(boxLines(view), " ")
}

// warningViewOpen reports whether the view is the warning modal.
func warningViewOpen(view string) bool {
	return strings.Contains(ansi.Strip(view), "Esc/Enter close")
}

// TestPausedEnterOnWarningRowShowsTheWholeMessage is the reproduction of the
// second point: the row cuts the warning, Enter shows all of it, wrapped
// inside the view, with the key that closes it.
func TestPausedEnterOnWarningRowShowsTheWholeMessage(t *testing.T) {
	for _, width := range []int{80, 120, 200} {
		m := pausedOnWarning(t, bootClockWarning, width, 24)
		if row := m.View(width, 24); strings.Contains(row, warningTail) || warningViewOpen(row) {
			t.Fatalf("width %d: the row already shows the whole warning:\n%s", width, row)
		}
		if !pressLocal(t, m, "enter") {
			t.Fatalf("width %d: enter on a warning row was not handled", width)
		}
		view := m.View(width, 24)
		assertViewFits(t, "warning", width, 24, view)
		lines := boxLines(view)
		if len(lines) < 4 || lines[0] != "Warning" || lines[len(lines)-1] != "Esc/Enter close" {
			t.Fatalf("width %d: modal is not title, message, hint:\n%s", width, view)
		}
		if got := strings.Join(lines[1:len(lines)-1], " "); got != bootClockWarning {
			t.Fatalf("width %d: modal message = %q, want the whole warning", width, got)
		}
		if strings.Contains(view, "Latency") || strings.Contains(view, "PAUSED") {
			t.Fatalf("width %d: the table is drawn with the modal:\n%s", width, view)
		}
	}
}

// TestWarningViewClosesWithItsKeys: the hint's Esc and Enter, and q (which
// the top-level model also delivers as esc), close the modal and nothing
// else: the stream stays paused on the same row and no filter is requested.
func TestWarningViewClosesWithItsKeys(t *testing.T) {
	for _, key := range []string{"esc", "enter", "q"} {
		m := pausedOnWarning(t, bootClockWarning, 100, 24)
		pressLocal(t, m, "enter")
		if !warningViewOpen(m.View(100, 24)) || !m.WarningModalVisible() {
			t.Fatalf("enter did not open the warning view")
		}
		if !pressLocal(t, m, key) {
			t.Fatalf("%q was not handled by the warning view", key)
		}
		view := ansi.Strip(m.View(100, 24))
		if warningViewOpen(view) || m.WarningModalVisible() || !strings.Contains(view, "PAUSED") || !strings.Contains(view, "Sel 2/2") {
			t.Fatalf("%q did not return to the paused table on the warning row:\n%s", key, view)
		}
		if !m.paused || m.selectedIdx != 1 || len(m.filterStack) != 0 {
			t.Fatalf("%q changed the stream: paused=%v selected=%d", key, m.paused, m.selectedIdx)
		}
	}
}

// TestWarningViewOwnsTheKeyboard: no other key leaves the modal, resumes the
// stream, opens another modal or reaches the dashboard behind it.
func TestWarningViewOwnsTheKeyboard(t *testing.T) {
	m := pausedOnWarning(t, bootClockWarning, 100, 24)
	pressLocal(t, m, "enter")
	for _, key := range []string{"space", " ", "tab", "shift+tab", "1", "7", "v", "r", "R", "f", "/", "?", "n", "x", "X", "E", "F", "T", "h", "l", "ctrl+x", "q!"} {
		if !pressLocal(t, m, key) {
			t.Fatalf("the warning view did not consume %q: it would reach the dashboard behind it", key)
		}
		if !warningViewOpen(m.View(100, 24)) {
			t.Fatalf("key %q closed the warning view", key)
		}
	}
	if !m.paused || m.SearchModalVisible() || m.ExportModalVisible() || m.FDTraceVisible() || m.statusMessage != "" {
		t.Fatalf("a key acted behind the warning view: paused=%v status=%q", m.paused, m.statusMessage)
	}
}

// hostileWarning is a message of three lines with an escape sequence, a tab
// and DEL, a wide rune, and a run of wide runes longer than any line.
var hostileWarning = "libbpf: \x1b[2Jmap\t'界'\nfailed\x7f\n" + strings.Repeat("界", 60) + " end\n"

// TestWarningViewSanitisesAndWrapsByCells: the message is foreign text. No
// control byte of it reaches the terminal, its line feeds still end lines,
// and the wide runes are wrapped by their two cells: 35 fill the 70-cell
// text area of an 80-column view, the rest continue with the next word.
func TestWarningViewSanitisesAndWrapsByCells(t *testing.T) {
	m := pausedOnWarning(t, hostileWarning, 80, 24)
	pressLocal(t, m, "enter")
	view := m.View(80, 24)
	assertViewFits(t, "hostile warning", 80, 24, view)
	for _, bad := range []string{"\x1b[2J", "\t", "\x7f", "\r"} {
		if strings.Contains(view, bad) {
			t.Fatalf("the warning view lets %q through:\n%q", bad, view)
		}
	}
	want := []string{
		"Warning",
		"libbpf: ?[2Jmap '界'",
		"failed?",
		strings.Repeat("界", 35),
		strings.Repeat("界", 25) + " end",
		"Esc/Enter close",
	}
	if got := boxLines(view); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("warning view lines:\n got %q\nwant %q", got, want)
	}
}

// scrollWindow reads the "lines a-b of n" part of a scrolled view's title.
func scrollWindow(t *testing.T, view string) (first, last, total int) {
	t.Helper()
	title := boxLines(view)[0]
	if _, err := fmt.Sscanf(title, "Warning, lines %d-%d of %d", &first, &last, &total); err != nil {
		t.Fatalf("title %q names no line window: %v", title, err)
	}
	return first, last, total
}

// TestWarningViewScrollsAMessageTallerThanTheView: ten rows hold the box's
// four rows of chrome and six lines of the warning, which needs about eleven
// at 50 columns. The title names the window, the hint the keys that move it,
// and the window stops at both ends, where the message's tail is readable.
func TestWarningViewScrollsAMessageTallerThanTheView(t *testing.T) {
	const width, height = 50, 10
	m := pausedOnWarning(t, bootClockWarning, width, height)
	pressLocal(t, m, "enter")
	view := m.View(width, height)
	assertViewFits(t, "tall warning", width, height, view)
	first, last, total := scrollWindow(t, view)
	if first != 1 || last != 6 || total < 9 {
		t.Fatalf("first window is lines %d-%d of %d, want 1-6 of nine or more", first, last, total)
	}
	text := boxText(view)
	if !strings.Contains(text, "Could not determine") || strings.Contains(text, warningTail) || !strings.HasSuffix(text, "Esc/Enter close • j/k scroll") {
		t.Fatalf("first window should start the message and name the scroll keys:\n%s", view)
	}
	for _, step := range []struct {
		key   string
		first int
	}{
		{"k", 1}, {"j", 2}, {"down", 3}, {"up", 2}, {"G", total - 5}, {"j", total - 5},
		{"pgdown", total - 5}, {"pgup", max(total-10, 1)}, {"g", 1}, {"pgdown", min(6, total-5)},
	} {
		pressLocal(t, m, step.key)
		if got, _, _ := scrollWindow(t, m.View(width, height)); got != step.first {
			t.Fatalf("after %q the window starts at line %d, want %d", step.key, got, step.first)
		}
	}
	pressLocal(t, m, "G")
	if text := boxText(m.View(width, height)); !strings.Contains(text, warningTail) {
		t.Fatalf("the last window does not show the message's tail:\n%s", text)
	}
}

// TestWarningViewScrolledWindowsCoverTheMessage: stepping the window line by
// line shows every wrapped line once, in order, so nothing of the message is
// unreachable.
func TestWarningViewScrolledWindowsCoverTheMessage(t *testing.T) {
	const width, height = 50, 10
	m := pausedOnWarning(t, bootClockWarning, width, height)
	pressLocal(t, m, "enter")
	lines := boxLines(m.View(width, height))
	seen := lines[1 : len(lines)-1]
	_, _, total := scrollWindow(t, m.View(width, height))
	for len(seen) < total {
		pressLocal(t, m, "j")
		lines = boxLines(m.View(width, height))
		seen = append(seen, lines[len(lines)-2])
	}
	if got := strings.Join(seen, " "); got != bootClockWarning {
		t.Fatalf("scrolled lines = %q, want the whole warning", got)
	}
}

// TestWarningViewFitsEveryViewSize: the modal never outgrows its view, and
// from the Stream tab's smallest body (six rows) up it keeps a message line
// and the key that closes it, in a box from 24 columns up.
func TestWarningViewFitsEveryViewSize(t *testing.T) {
	m := pausedOnWarning(t, hostileWarning+bootClockWarning, 100, 24)
	pressLocal(t, m, "enter")
	for width := 1; width <= 130; width++ {
		for height := 1; height <= 30; height++ {
			view := m.View(width, height)
			assertViewFits(t, "warning", width, height, view)
			if height < 6 || width < 24 {
				continue
			}
			lines := boxLines(view)
			if !strings.HasPrefix(lines[len(lines)-1], "Esc/Enter close") || len(lines) < 3 || !strings.Contains(ansi.Strip(view), "╭") {
				t.Fatalf("%dx%d: modal lost its box, message or hint:\n%s", width, height, view)
			}
		}
	}
}

// TestWarningViewSilencesTheUndrawnStatusMessage: on a six-row body the
// status message has no row and goes to the dashboard's badge slot; while
// the modal owns the view it is not drawn there either.
func TestWarningViewSilencesTheUndrawnStatusMessage(t *testing.T) {
	m := pausedOnWarning(t, bootClockWarning, 100, 6)
	m.SetStatusMessage("No match: \"zzz\"")
	if m.UndrawnStatusMessage() == "" {
		t.Fatalf("a six-row view should hand its status message to the dashboard")
	}
	pressLocal(t, m, "enter")
	if got := m.UndrawnStatusMessage(); got != "" || !warningViewOpen(m.View(100, 6)) {
		t.Fatalf("with the warning view open the undrawn message is %q", got)
	}
}

// pausedFooter returns the footer line (the one starting "Sel ") of a paused
// view.
func pausedFooter(t *testing.T, m *Model, width, height int) string {
	t.Helper()
	for _, line := range strings.Split(ansi.Strip(m.View(width, height)), "\n") {
		if strings.HasPrefix(line, "Sel ") {
			return line
		}
	}
	t.Fatalf("no Sel footer line in the paused view")
	return ""
}

// TestPausedFooterOnAWarningRowSaysWhatEnterDoes: the footer's hints follow
// the selected row. A warning row has no cells to filter by, no column to
// count and no descriptor to trace; Enter shows it. A syscall row keeps the
// hints it had.
func TestPausedFooterOnAWarningRowSaysWhatEnterDoes(t *testing.T) {
	m := pausedOnWarning(t, bootClockWarning, 120, 24)
	if got, want := pausedFooter(t, m, 120, 24), "Sel 2/2 | Esc/F undo | Enter show warning | Row 1/2"; got != want {
		t.Fatalf("footer on a warning row = %q, want %q", got, want)
	}
	m.selectedIdx = 0
	if got, want := pausedFooter(t, m, 120, 24), "Sel 1/2 Col 1/10 | Esc/F undo | Enter push-filter | T fd-trace | Row 1/2"; got != want {
		t.Fatalf("footer on a syscall row = %q, want %q", got, want)
	}
	for width := 20; width <= 120; width++ {
		m.selectedIdx = 1
		if w := common.DisplayWidth(pausedFooter(t, m, width, 24)); w > width {
			t.Fatalf("width %d: footer on a warning row is %d cells", width, w)
		}
	}
}
