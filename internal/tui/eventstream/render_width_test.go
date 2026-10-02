package eventstream

import (
	"strings"
	"testing"
	"unicode"

	"ior/internal/tui/common"
	"ior/internal/types"

	"github.com/charmbracelet/x/ansi"
)

// Task 923: the Syscall column was a fixed 9 or 11 cells, so a 200-column
// terminal showed clock_nanosleep as "cloc...leep" next to a File column of
// over a hundred cells, and a warning row squeezed its message into that File
// column and elided the cause in the middle. The tests below render the real
// table and read the cells back by the header's column offsets.

// longSyscallNames are the names the task's reviewers saw cut in the middle.
var longSyscallNames = []string{
	"clock_nanosleep", "name_to_handle_at", "open_by_handle_at",
	"process_vm_writev", "restart_syscall",
}

// streamColumnTitles are the header titles in column order (streamCol*).
var streamColumnTitles = []string{
	"Gap", "Latency", "Comm", "PID", "TID", "Syscall", "FD", "Ret", "Bytes", "File",
}

// widthTestEvents returns one ordinary row per name. The other cells are
// short, so only the Syscall cell can need more room than its column has.
func widthTestEvents(names ...string) []StreamEvent {
	events := make([]StreamEvent, 0, len(names))
	for i, name := range names {
		events = append(events, StreamEvent{
			Seq: uint64(i + 1), Syscall: name, Comm: "sleeper", PID: 4100, TID: 4101,
			FD: 3, DurationNs: 1500, GapNs: 300, Bytes: 64, RetVal: 64, FileName: "/tmp/f",
		})
	}
	return events
}

// streamTextLines renders the stream table at a terminal width and returns
// the panel's text lines (status, filter, header, rows) without styling. The
// frame is checked first: no wrapped row and no line wider than the terminal.
func streamTextLines(t *testing.T, width int, events []StreamEvent) []string {
	t.Helper()
	out := RenderStreamTable(width, false, len(events), len(events), len(events), 10000, Filter{}, nil, events, -1, -1)
	// border top + status + filter + header + rows + border bottom
	assertPanelFits(t, width, out, 4+len(events)+1)
	lines := strings.Split(ansi.Strip(out), "\n")
	return lines[1 : len(lines)-1]
}

// panelText strips the panel's border rune and padding from one text line.
// Every cell text in these tests is ASCII, so the non-ASCII runes at the ends
// can only be the border.
func panelText(line string) string {
	return strings.TrimFunc(line, func(r rune) bool { return r == ' ' || r > unicode.MaxASCII })
}

// headerAndRows splits the text lines into the column header and the rows.
func headerAndRows(t *testing.T, lines []string) (string, []string) {
	t.Helper()
	for i, line := range lines {
		if strings.Contains(line, "Gap") && strings.Contains(line, "File") {
			return line, lines[i+1:]
		}
	}
	t.Fatalf("no column header in:\n%s", strings.Join(lines, "\n"))
	return "", nil
}

// cellAt returns the text of column col in line: the cells between that
// title's offset in the header and the next title's. It fails when the cell
// is not preceded by the separator, which is what a shifted row looks like.
func cellAt(t *testing.T, header, line string, col int) string {
	t.Helper()
	start := strings.Index(header, streamColumnTitles[col])
	if start < 1 || start > len(line) {
		t.Fatalf("title %q missing or row too short\nheader %q\nrow    %q", streamColumnTitles[col], header, line)
	}
	if line[start-1] != ' ' {
		t.Fatalf("column %q does not start at the header's offset %d\nheader %q\nrow    %q", streamColumnTitles[col], start, header, line)
	}
	end := len(line)
	if col+1 < len(streamColumnTitles) {
		end = min(strings.Index(header, streamColumnTitles[col+1]), len(line))
	}
	return panelText(line[start:end])
}

// assertRowAligned checks that every cell of an ordinary widthTestEvents row
// sits under its title: the short cells are read back whole.
func assertRowAligned(t *testing.T, header, row string) {
	t.Helper()
	want := map[int]string{
		streamColGap: "300ns", streamColLatency: "1.5us", streamColComm: "sleeper",
		streamColPID: "4100", streamColTID: "4101", streamColFD: "3", streamColRet: "64", streamColBytes: "64",
		streamColFile: "/tmp/f",
	}
	for col, cell := range want {
		if got := cellAt(t, header, row, col); got != cell {
			t.Fatalf("column %q = %q, want %q\nheader %q\nrow    %q", streamColumnTitles[col], got, cell, header, row)
		}
	}
}

// TestStreamTableShowsFullSyscallNamesWithRoom is the reproduction: at 200
// and at 120 columns every long name must be readable in full, with the row
// still one line, inside the terminal, and under the header's titles.
func TestStreamTableShowsFullSyscallNamesWithRoom(t *testing.T) {
	events := widthTestEvents(append([]string{"read"}, longSyscallNames...)...)
	for _, width := range []int{120, 200} {
		header, rows := headerAndRows(t, streamTextLines(t, width, events))
		if len(rows) != len(events) {
			t.Fatalf("width %d: %d rows, want %d", width, len(rows), len(events))
		}
		for i, row := range rows {
			if got := cellAt(t, header, row, streamColSyscall); got != events[i].Syscall {
				t.Fatalf("width %d: Syscall cell = %q, want the full name %q\n%s\n%s", width, got, events[i].Syscall, header, row)
			}
			assertRowAligned(t, header, row)
		}
	}
}

// generatedSyscallNames returns every name a traced row can carry: the names
// of the generated sys_enter tracepoints, which is what streamrow.New stores.
func generatedSyscallNames() []string {
	ids := types.EnterTraceIDs()
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, id.Name())
	}
	return names
}

// TestStreamTableFitsEveryGeneratedSyscallNameAt200 pins the bound of the
// column: on a wide terminal no name of the generated table is cut, and the
// column is no wider than the longest of them (the File column gets the rest).
func TestStreamTableFitsEveryGeneratedSyscallNameAt200(t *testing.T) {
	names := generatedSyscallNames()
	longest := 0
	for _, name := range names {
		longest = max(longest, len(name))
	}
	if longest < len("process_vm_writev") {
		t.Fatalf("generated table's longest name is %d cells: table not loaded?", longest)
	}
	header, rows := headerAndRows(t, streamTextLines(t, 200, widthTestEvents(names...)))
	for i, row := range rows {
		if got := cellAt(t, header, row, streamColSyscall); got != names[i] {
			t.Fatalf("Syscall cell = %q, want %q", got, names[i])
		}
	}
	cols := computeColumnLayout(panelTextWidth(panelContentWidth(200)))
	if cols.syscall != longest {
		t.Fatalf("Syscall column is %d wide at 200 columns, want the longest name's %d", cols.syscall, longest)
	}
}

// TestSyscallCommonWidthCoversNearlyAllNames keeps the first growth step
// honest: syscallCommonWidth is a literal, so a regenerated table that makes
// many names longer than it must fail here rather than quietly truncate them
// on mid-sized terminals.
func TestSyscallCommonWidthCoversNearlyAllNames(t *testing.T) {
	names := generatedSyscallNames()
	over := 0
	for _, name := range names {
		if len(name) > syscallCommonWidth {
			over++
		}
	}
	if over*100 > len(names)*3 {
		t.Fatalf("%d of %d generated names are wider than syscallCommonWidth (%d): raise it", over, len(names), syscallCommonWidth)
	}
	for _, name := range longSyscallNames {
		if len(name) > syscallCommonWidth {
			t.Fatalf("%q is wider than syscallCommonWidth (%d)", name, syscallCommonWidth)
		}
	}
}

// TestStreamTableAt80TruncatesSyscallWithoutOverflow: an 80-column terminal
// has no room for the long names. They are cut to the column (both ends
// kept), a short name stays whole, and the table neither wraps nor loses a
// column or its alignment.
func TestStreamTableAt80TruncatesSyscallWithoutOverflow(t *testing.T) {
	events := widthTestEvents(append([]string{"read"}, longSyscallNames...)...)
	header, rows := headerAndRows(t, streamTextLines(t, 80, events))
	if got := strings.Fields(panelText(header)); strings.Join(got, " ") != strings.Join(streamColumnTitles, " ") {
		t.Fatalf("header titles = %q, want %q", got, streamColumnTitles)
	}
	syscallWidth := computeColumnLayout(panelTextWidth(panelContentWidth(80))).syscall
	if got := cellAt(t, header, rows[0], streamColSyscall); got != "read" {
		t.Fatalf("short name cell = %q, want %q", got, "read")
	}
	for i, row := range rows[1:] {
		name := events[i+1].Syscall
		got := cellAt(t, header, row, streamColSyscall)
		head, tail, cut := strings.Cut(got, common.ASCIIEllipsis)
		if !cut || len(got) != syscallWidth || !strings.HasPrefix(name, head) || !strings.HasSuffix(name, tail) || head == "" || tail == "" {
			t.Fatalf("Syscall cell = %q, want %q cut to %d cells with both ends kept", got, name, syscallWidth)
		}
		assertRowAligned(t, header, row)
	}
}

// TestStreamHeaderDoesNotDependOnRows: the column widths are a function of
// the terminal width alone, so the table does not shift when a row with a
// longer name scrolls in or out of view.
func TestStreamHeaderDoesNotDependOnRows(t *testing.T) {
	for _, width := range []int{80, 120, 200} {
		short, _ := headerAndRows(t, streamTextLines(t, width, widthTestEvents("read")))
		long, _ := headerAndRows(t, streamTextLines(t, width, widthTestEvents(longSyscallNames...)))
		if short != long {
			t.Fatalf("width %d: header moved with the rows\nshort %q\nlong  %q", width, short, long)
		}
	}
}

// TestSyscallColumnGrowsMonotonically: widening the terminal never narrows
// the Syscall column (a name readable at one width stays readable at every
// larger one), and the column never grows past the longest generated name.
func TestSyscallColumnGrowsMonotonically(t *testing.T) {
	prev := 0
	for width := 1; width <= 300; width++ {
		cols := computeColumnLayout(width)
		if cols.syscall < prev {
			t.Fatalf("width %d: Syscall column shrank from %d to %d", width, prev, cols.syscall)
		}
		if cols.syscall > syscallFullWidth {
			t.Fatalf("width %d: Syscall column %d is wider than the longest name (%d)", width, cols.syscall, syscallFullWidth)
		}
		prev = cols.syscall
	}
	if prev != syscallFullWidth {
		t.Fatalf("Syscall column is %d at 300 columns, want %d", prev, syscallFullWidth)
	}
}

// bootClockWarning is the text of the warning the y13 review saw elided
// (internal/bootclock.go, unknownBootClockDomain), with a cause filled in.
const bootClockWarning = "Could not determine the boottime offset of ior's time namespace " +
	"(open /proc/self/timens_offsets: permission denied); assuming none. If ior runs " +
	"inside a time namespace with such an offset, close rows of descriptors opened " +
	"before the trace may be unnamed or misnamed, and interrupted calls may stay " +
	"unfolded or be folded with a later call."

// warningRowText renders a syscall row and a warning row at a terminal width
// and returns the warning's row text plus the width the panel has for text.
func warningRowText(t *testing.T, width int, message string) (string, int) {
	t.Helper()
	events := append(widthTestEvents("read"), NewWarningEvent(2, message))
	_, rows := headerAndRows(t, streamTextLines(t, width, events))
	return panelText(rows[1]), panelTextWidth(panelContentWidth(width))
}

// assertWarningCutAtEnd checks that got is the labelled message filling the
// whole row and cut only at its end: everything before the final "..." is an
// unbroken prefix of the message.
func assertWarningCutAtEnd(t *testing.T, got, message string, textWidth int) {
	t.Helper()
	full := "warning: " + message
	kept, cut := strings.CutSuffix(got, common.ASCIIEllipsis)
	if !cut || !strings.HasPrefix(full, kept) {
		t.Fatalf("warning row is not the message cut at its end:\n%q", got)
	}
	if len(got) != textWidth {
		t.Fatalf("warning row is %d cells, want the full row width %d:\n%q", len(got), textWidth, got)
	}
}

// TestWarningRowUsesFullRowAndKeepsCause is the y13 reproduction: at 220
// columns the cause in parentheses must be readable in full.
func TestWarningRowUsesFullRowAndKeepsCause(t *testing.T) {
	got, textWidth := warningRowText(t, 220, bootClockWarning)
	assertWarningCutAtEnd(t, got, bootClockWarning, textWidth)
	for _, want := range []string{"(open /proc/self/timens_offsets: permission denied)", "assuming none", "time namespace with such an offset"} {
		if !strings.Contains(got, want) {
			t.Fatalf("warning row lost %q:\n%q", want, got)
		}
	}
}

// TestWarningRowAtNarrowWidths: at 120 and 80 columns the row still starts
// with the message's beginning and ends in the marker, on one line.
func TestWarningRowAtNarrowWidths(t *testing.T) {
	for _, width := range []int{80, 120} {
		got, textWidth := warningRowText(t, width, bootClockWarning)
		assertWarningCutAtEnd(t, got, bootClockWarning, textWidth)
		if !strings.HasPrefix(got, "warning: Could not determine the boottime offset") {
			t.Fatalf("width %d: warning row lost its beginning:\n%q", width, got)
		}
	}
}

// TestShortWarningRowIsShownWhole: a message that fits is not cut at all, and
// the placeholder cells of the synthetic row (pid 0, ret -1) are not drawn.
func TestShortWarningRowIsShownWhole(t *testing.T) {
	const message = "ior: -tid 1: not a thread of -pid 7: the trace will stay empty"
	for _, width := range []int{80, 120, 200} {
		got, _ := warningRowText(t, width, message)
		if got != "warning: "+message {
			t.Fatalf("width %d: warning row = %q", width, got)
		}
	}
}

// TestSelectedWarningRowKeepsItsWidth: a paused stream draws the selected
// warning in the selection style; it stays one line of the same text.
func TestSelectedWarningRowKeepsItsWidth(t *testing.T) {
	columns := streamColumns(panelTextWidth(panelContentWidth(120)))
	ev := NewWarningEvent(1, bootClockWarning)
	plain := ansi.Strip(renderEventRow(ev, columns, false, -1))
	selected := ansi.Strip(renderEventRow(ev, columns, true, streamColSyscall))
	if plain != selected || strings.Contains(selected, "\n") {
		t.Fatalf("selected warning row differs from the unselected one:\n%q\n%q", selected, plain)
	}
	if got, want := common.DisplayWidth(selected), panelTextWidth(panelContentWidth(120)); got != want {
		t.Fatalf("selected warning row is %d cells, want %d", got, want)
	}
}

// TestPausedEnterOnWarningRowIsNotHandled: a warning row is one spanning
// line without cells, and every value behind it is a placeholder, so Enter
// pushes no filter from any column, where it used to push pid=0 or ret=-1.
func TestPausedEnterOnWarningRowIsNotHandled(t *testing.T) {
	warning := NewWarningEvent(1, "Trace stopped: boom")
	for col := range streamColumnCount {
		if handled, cmd := pressEnterOnCell(t, warning, col); handled || cmd != nil {
			t.Fatalf("column %d of a warning row: enter was handled (cmd=%v)", col, cmd != nil)
		}
	}
}

// TestStreamViewLayoutAcrossWidths renders the model's own view, the path
// the dashboard draws, at the three widths the task names, and pins the
// Syscall column of each: whole names at 200 and 120, cut ones at 80, never
// a line wider than the terminal, and the warning on a single line.
func TestStreamViewLayoutAcrossWidths(t *testing.T) {
	for _, tt := range []struct {
		width   int
		syscall string
	}{{200, "clock_nanosleep"}, {120, "clock_nanosleep"}, {80, "cl...eep"}} {
		rb := NewRingBuffer()
		rb.Push(NewWarningEvent(1, bootClockWarning))
		rb.Push(widthTestEvents("clock_nanosleep")[0])
		m := NewModel(rb)
		m.Refresh()
		view := ansi.Strip(m.View(tt.width, 20))
		lines := strings.Split(view, "\n")
		for _, line := range lines {
			if w := common.DisplayWidth(line); w > tt.width {
				t.Fatalf("width %d: line is %d cells: %q", tt.width, w, line)
			}
		}
		header, rows := headerAndRows(t, lines)
		if got := cellAt(t, header, rows[1], streamColSyscall); got != tt.syscall {
			t.Fatalf("width %d: Syscall cell = %q, want %q", tt.width, got, tt.syscall)
		}
		assertWarningCutAtEnd(t, panelText(rows[0]), bootClockWarning, panelTextWidth(panelContentWidth(tt.width)))
	}
}
