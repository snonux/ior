package eventstream

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
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

// scrollWindow reads the "lines a-b of n" part of a scrolled view's title,
// which is the title's form from a text width of 24 to 26 cells up.
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
// and the key that closes it, in a box from 24 columns up. Wherever the box
// shows the message through a window, its title names the window and its
// hint the scroll keys, in the form its width holds (13 columns, seven text
// cells, is the narrowest box with room for "j/k Esc").
func TestWarningViewFitsEveryViewSize(t *testing.T) {
	m := pausedOnWarning(t, hostileWarning+bootClockWarning, 100, 24)
	pressLocal(t, m, "enter")
	for width := 1; width <= 130; width++ {
		for height := 1; height <= 30; height++ {
			view := m.View(width, height)
			assertViewFits(t, "warning", width, height, view)
			if height < 6 || width < 13 {
				continue
			}
			lines := boxLines(view)
			title, hint := lines[0], lines[len(lines)-1]
			if m.warningModal.frame(width, height).scrolls() && (!windowTitle.MatchString(title) || !strings.Contains(hint, "j/k")) {
				t.Fatalf("%dx%d: title %q and hint %q do not say that the text scrolls:\n%s", width, height, title, hint, view)
			}
			if width < 24 {
				continue
			}
			if !strings.Contains(hint, "Esc") || len(lines) < 3 || !strings.Contains(ansi.Strip(view), "╭") {
				t.Fatalf("%dx%d: modal lost its box, message or hint:\n%s", width, height, view)
			}
		}
	}
}

// windowTitle matches the window a scrolled view's title names, in any of
// its forms: "Warning, lines 1-6 of 11", "Warning 1-6/11", "1-6/11".
var windowTitle = regexp.MustCompile(`^(Warning, lines \d+-\d+ of \d+|(Warning )?\d+-\d+/\d+)$`)

// TestNarrowWarningViewStillSaysItScrolls: under about 34 columns the long
// title and the hint with "j/k scroll" do not fit, and both used to be
// dropped whole, so a scrolled message looked complete. The short forms keep
// the window and the keys; the last window ends the message.
func TestNarrowWarningViewStillSaysItScrolls(t *testing.T) {
	for _, tt := range []struct {
		width, height     int
		first, last, hint string
	}{
		{20, 6, "Warning 1-2/28", "27-28/28", "j/k • Esc"},
		{30, 8, "Warning, lines 1-4 of 16", "Warning 13-16/16", "j/k scroll • Esc close"},
		{34, 8, "Warning, lines 1-4 of 13", "Warning, lines 10-13 of 13", "Esc/Enter close • j/k scroll"},
	} {
		m := pausedOnWarning(t, bootClockWarning, tt.width, tt.height)
		pressLocal(t, m, "enter")
		view := m.View(tt.width, tt.height)
		assertViewFits(t, "narrow warning", tt.width, tt.height, view)
		lines := boxLines(view)
		if lines[0] != tt.first || lines[len(lines)-1] != tt.hint || !strings.Contains(view, "╭") {
			t.Fatalf("%dx%d: title %q hint %q, want %q and %q in a box:\n%s", tt.width, tt.height, lines[0], lines[len(lines)-1], tt.first, tt.hint, view)
		}
		pressLocal(t, m, "G")
		lines = boxLines(m.View(tt.width, tt.height))
		body := strings.Join(lines[1:len(lines)-1], " ")
		if lines[0] != tt.last || !strings.HasSuffix(bootClockWarning, body) {
			t.Fatalf("%dx%d: last window is %q with %q", tt.width, tt.height, lines[0], body)
		}
	}
}

// TestWarningHintFormsByWidth pins which form of each hint a text width
// gets: the scroll keys stay down to seven cells and lead from the second
// form on, and below the shortest form the way out is cut, not dropped.
func TestWarningHintFormsByWidth(t *testing.T) {
	for _, tt := range []struct {
		width           int
		scrolled, whole string
	}{
		{28, "Esc/Enter close • j/k scroll", "Esc/Enter close"},
		{27, "j/k scroll • Esc close", "Esc/Enter close"},
		{22, "j/k scroll • Esc close", "Esc/Enter close"},
		{21, "j/k • Esc close", "Esc/Enter close"},
		{15, "j/k • Esc close", "Esc/Enter close"},
		{14, "j/k • Esc", "Esc close"},
		{9, "j/k • Esc", "Esc close"},
		{8, "j/k Esc", "Esc"},
		{7, "j/k Esc", "Esc"},
		{6, "Esc", "Esc"},
		{3, "Esc", "Esc"},
		{2, "E…", "E…"},
		{1, "E", "E"},
	} {
		lines := []string{"a", "b"}
		if got := warningHint(warningFrame{textWidth: tt.width, lines: lines, rows: 1}); got != tt.scrolled {
			t.Fatalf("scrolled hint in %d cells = %q, want %q", tt.width, got, tt.scrolled)
		}
		if got := warningHint(warningFrame{textWidth: tt.width, lines: lines, rows: 2}); got != tt.whole {
			t.Fatalf("hint of a whole message in %d cells = %q, want %q", tt.width, got, tt.whole)
		}
	}
}

// TestWarningViewSurvivesAnEnlargedView: the offset is clamped for the view
// of the last key. Scrolled to the end of a small view and then drawn in a
// larger one, where the message has fewer lines and more of them show, the
// stored offset lies past the last window; View must clamp it, not slice out
// of range (a panic, which nothing else in the suite reached).
func TestWarningViewSurvivesAnEnlargedView(t *testing.T) {
	m := pausedOnWarning(t, bootClockWarning, 50, 10)
	pressLocal(t, m, "enter")
	pressLocal(t, m, "G")
	stored := m.warningModal.offset
	for _, size := range []struct{ width, height int }{{60, 10}, {60, 12}, {120, 30}, {50, 10}} {
		if f := m.warningModal.frame(size.width, size.height); size.width > 50 && stored <= f.maxOffset() {
			t.Fatalf("%dx%d: offset %d is not past the last window (%d)", size.width, size.height, stored, f.maxOffset())
		}
		view := m.View(size.width, size.height)
		assertViewFits(t, "enlarged warning", size.width, size.height, view)
		lines := boxLines(view)
		if got := lines[len(lines)-2]; !strings.HasSuffix(warningTail, got) && !strings.HasSuffix(got, warningTail) {
			t.Fatalf("%dx%d: the view does not end on the message's last line:\n%s", size.width, size.height, view)
		}
	}
	if lines := boxLines(m.View(120, 30)); lines[0] != "Warning" || strings.Join(lines[1:len(lines)-1], " ") != bootClockWarning {
		t.Fatalf("the large view should show the whole message:\n%q", lines)
	}
}

// TestWarningViewDropsLineFeedsAtTheMessageEnds: libbpf lines end in a line
// feed. Kept, it is a blank line that the window and its "of n" count; the
// title's total is the three lines of text. (boxLines drops blank lines, so
// only the total shows the difference.)
func TestWarningViewDropsLineFeedsAtTheMessageEnds(t *testing.T) {
	m := pausedOnWarning(t, "\n\none\ntwo\n\nthree\n\n", 50, 6)
	pressLocal(t, m, "enter")
	first, last, total := scrollWindow(t, m.View(50, 6))
	if first != 1 || last != 2 || total != 4 {
		t.Fatalf("window is lines %d-%d of %d, want 1-2 of 4 (one, two, a blank, three)", first, last, total)
	}
	if got := boxLines(m.View(50, 6)); got[1] != "one" || got[2] != "two" {
		t.Fatalf("first window = %q, want it to start at the first line of text", got)
	}
}

// TestRowKeysReachAWarningViewOverALiveTable: the live table's viewport
// leaves the row keys alone while the warning modal is open. The modal opens
// from the paused table only and no key resumes the stream behind it, so the
// test has to put it over a live table itself; it pins that the viewport's
// guard names the modal, rather than relying on that.
func TestRowKeysReachAWarningViewOverALiveTable(t *testing.T) {
	rb := NewRingBuffer()
	pushEvents(rb, 200)
	m := NewModel(rb)
	m.Refresh()
	m.View(50, 10)
	m.warningModal = m.warningModal.Open(NewWarningEvent(1, bootClockWarning))
	scrolled := m.scrollOffset
	for _, step := range []struct {
		key   rune
		first int
	}{{'j', 2}, {'j', 3}, {'k', 2}} {
		handled, _ := m.HandleTeaKey(tea.KeyPressMsg{Code: step.key, Text: string(step.key)})
		first, _, _ := scrollWindow(t, m.View(50, 10))
		if !handled || first != step.first || m.scrollOffset != scrolled {
			t.Fatalf("%q: handled=%v, window starts at line %d (want %d), table row %d (want %d)", step.key, handled, first, step.first, m.scrollOffset, scrolled)
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
	m.SetFilterStack([]string{"pid=7"})
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

// TestPausedFooterNamesUndoOnlyWithALayerToPop: Esc and F pop the latest
// layer of the shared filter stack. With an empty stack neither key is
// handled (requestGlobalFilterUndo), so the footer does not offer them, on
// either kind of row; the hint is there as soon as a layer is.
func TestPausedFooterNamesUndoOnlyWithALayerToPop(t *testing.T) {
	m := pausedOnWarning(t, bootClockWarning, 120, 24)
	for _, tt := range []struct {
		selected     int
		empty, layer string
	}{
		{1, "Sel 2/2 | Enter show warning | Row 1/2", "Sel 2/2 | Esc/F undo | Enter show warning | Row 1/2"},
		{0, "Sel 1/2 Col 1/10 | Enter push-filter | T fd-trace | Row 1/2", "Sel 1/2 Col 1/10 | Esc/F undo | Enter push-filter | T fd-trace | Row 1/2"},
	} {
		m.selectedIdx = tt.selected
		m.SetFilterStack(nil)
		for _, key := range []string{"esc", "F"} {
			if handled, cmd := m.HandleKey(key); handled || cmd != nil {
				t.Fatalf("row %d: %q was handled with an empty filter stack", tt.selected, key)
			}
		}
		if got := pausedFooter(t, m, 120, 24); got != tt.empty {
			t.Fatalf("row %d, empty stack: footer = %q, want %q", tt.selected, got, tt.empty)
		}
		m.SetFilterStack([]string{"pid=7"})
		if got := pausedFooter(t, m, 120, 24); got != tt.layer {
			t.Fatalf("row %d, one layer: footer = %q, want %q", tt.selected, got, tt.layer)
		}
		pressRequest[messages.GlobalFilterUndoRequestedMsg](t, m, "esc")
	}
}
