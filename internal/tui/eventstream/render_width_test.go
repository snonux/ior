package eventstream

import (
	"strings"
	"testing"
	"unicode"

	"ior/internal/tui/common"
	"ior/internal/types"

	"charm.land/lipgloss/v2"
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

// titleCell is the display-cell offset of column col's title in header. The
// titles are ASCII, but the panel's border rune in front of them is not, so a
// byte offset is not a cell offset.
func titleCell(t *testing.T, header string, col int) int {
	t.Helper()
	index := strings.Index(header, streamColumnTitles[col])
	if index < 1 {
		t.Fatalf("title %q missing in header %q", streamColumnTitles[col], header)
	}
	return common.DisplayWidth(header[:index])
}

// cellAt returns the text of column col in line: the cells between that
// title's offset in the header and the next title's. It fails when the cell
// is not preceded by the separator, which is what a shifted row looks like.
// Offsets are display cells (ansi.Cut), not bytes: a number cut from the left
// starts with the three-byte, one-cell marker "…" (task b23), which would
// shift every later cell of the row by two bytes.
func cellAt(t *testing.T, header, line string, col int) string {
	t.Helper()
	start := titleCell(t, header, col)
	if start > common.DisplayWidth(line) {
		t.Fatalf("row too short for column %q\nheader %q\nrow    %q", streamColumnTitles[col], header, line)
	}
	if ansi.Cut(line, start-1, start) != " " {
		t.Fatalf("column %q does not start at the header's offset %d\nheader %q\nrow    %q", streamColumnTitles[col], start, header, line)
	}
	if col+1 == len(streamColumnTitles) {
		// The last cell runs to the panel's border, which panelText drops.
		return panelText(ansi.Cut(line, start, common.DisplayWidth(line)))
	}
	end := min(titleCell(t, header, col+1), common.DisplayWidth(line))
	return strings.TrimSpace(ansi.Cut(line, start, end))
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

// namesWiderThan counts the names that a column of width cells would cut.
func namesWiderThan(names []string, width int) int {
	over := 0
	for _, name := range names {
		if len(name) > width {
			over++
		}
	}
	return over
}

// TestSyscallUsualWidthCoversMostNames keeps the first growth step honest:
// syscallUsualWidth is a literal chosen because about four in five generated
// names fit in it, which is what justifies giving the File column its next
// cells before the Syscall column grows on. A regenerated table in which
// more than a quarter of the names are longer must fail here rather than
// quietly cut them on terminals of about 100 columns.
func TestSyscallUsualWidthCoversMostNames(t *testing.T) {
	names := generatedSyscallNames()
	if over := namesWiderThan(names, syscallUsualWidth); over*4 > len(names) {
		t.Fatalf("%d of %d generated names are wider than syscallUsualWidth (%d): raise it", over, len(names), syscallUsualWidth)
	}
	if syscallUsualWidth >= syscallCommonWidth || syscallCommonWidth >= syscallFullWidth {
		t.Fatalf("growth targets out of order: usual %d, common %d, full %d", syscallUsualWidth, syscallCommonWidth, syscallFullWidth)
	}
}

// TestSyscallCommonWidthCoversNearlyAllNames does the same for the second
// growth step: syscallCommonWidth is a literal, so a regenerated table that
// makes more than 3% of the names longer than it must fail here rather than
// quietly truncate them on mid-sized terminals.
func TestSyscallCommonWidthCoversNearlyAllNames(t *testing.T) {
	names := generatedSyscallNames()
	if over := namesWiderThan(names, syscallCommonWidth); over*100 > len(names)*3 {
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

// TestColumnLayoutNeverNarrowsAsWidthGrows is the layout's contract over
// text widths 1 to 400, across the shrink path, the compact layout and every
// growth step: from the all-ones minimum up the row is exactly as wide as
// the text area, no column is empty, and widening the terminal never narrows
// any column (a cell readable at one width stays readable at every larger
// one). The Syscall and Comm columns stop at the longest value they can hold.
func TestColumnLayoutNeverNarrowsAsWidthGrows(t *testing.T) {
	const minRow = streamColumnCount*2 - 1
	prev := computeColumnLayout(1)
	for width := 1; width <= 400; width++ {
		cols := computeColumnLayout(width)
		if got := rowWidth(&cols); width >= minRow && got != width {
			t.Fatalf("width %d: row is %d cells wide: %+v", width, got, cols)
		}
		before := columnFields(&prev)
		for i, f := range columnFields(&cols) {
			if *f < 1 || *f < *before[i] {
				t.Fatalf("width %d: column %q is %d cells, was %d one cell narrower", width, streamColumnTitles[i], *f, *before[i])
			}
		}
		if cols.syscall > syscallFullWidth || cols.comm > commFullWidth {
			t.Fatalf("width %d: Syscall %d or Comm %d is wider than its longest value (%d, %d)", width, cols.syscall, cols.comm, syscallFullWidth, commFullWidth)
		}
		prev = cols
	}
	if prev.syscall != syscallFullWidth || prev.comm != commFullWidth {
		t.Fatalf("at 400 cells Syscall is %d and Comm %d, want %d and %d", prev.syscall, prev.comm, syscallFullWidth, commFullWidth)
	}
}

// TestColumnGrowOrder pins the order of columnGrowSteps with the exact layout
// at one text width inside each stage (a terminal is four columns wider than
// its text area). The early stages matter most: File reaches 20 cells before
// PID and TID get their seventh, those before the Syscall column grows, and
// the Syscall column stops at syscallUsualWidth until File has 28 cells, so
// a 100-column terminal shows File 24 / Syscall 12 and not File 20 beside a
// mostly blank Syscall 17.
func TestColumnGrowOrder(t *testing.T) {
	full := syscallFullWidth
	for _, tt := range []struct {
		width int
		want  columnLayout
	}{
		{78, columnLayout{gap: 7, latency: 8, comm: 8, pid: 6, tid: 6, syscall: 8, fd: 3, ret: 4, bytes: 7, file: 12}},
		{82, columnLayout{gap: 7, latency: 8, comm: 8, pid: 6, tid: 6, syscall: 8, fd: 3, ret: 4, bytes: 7, file: 16}},
		{87, columnLayout{gap: 7, latency: 8, comm: 8, pid: 7, tid: 6, syscall: 8, fd: 3, ret: 4, bytes: 7, file: 20}},
		{90, columnLayout{gap: 7, latency: 8, comm: 8, pid: 7, tid: 7, syscall: 10, fd: 3, ret: 4, bytes: 7, file: 20}},
		{96, columnLayout{gap: 7, latency: 8, comm: 8, pid: 7, tid: 7, syscall: 12, fd: 3, ret: 4, bytes: 7, file: 24}},
		{104, columnLayout{gap: 7, latency: 8, comm: 8, pid: 7, tid: 7, syscall: 16, fd: 3, ret: 4, bytes: 7, file: 28}},
		{108, columnLayout{gap: 7, latency: 8, comm: 10, pid: 7, tid: 7, syscall: 17, fd: 4, ret: 4, bytes: 7, file: 28}},
		{112, columnLayout{gap: 7, latency: 8, comm: 10, pid: 7, tid: 7, syscall: 17, fd: 4, ret: 5, bytes: 8, file: 30}},
		{124, columnLayout{gap: 7, latency: 8, comm: 10, pid: 7, tid: 7, syscall: 19, fd: 4, ret: 5, bytes: 8, file: 40}},
		{128 + full, columnLayout{gap: 7, latency: 8, comm: 13, pid: 7, tid: 7, syscall: full, fd: 4, ret: 5, bytes: 8, file: 60}},
		{132 + full, columnLayout{gap: 7, latency: 8, comm: 15, pid: 8, tid: 8, syscall: full, fd: 4, ret: 5, bytes: 8, file: 60}},
		{200, columnLayout{gap: 7, latency: 8, comm: 15, pid: 8, tid: 8, syscall: full, fd: 4, ret: 5, bytes: 8, file: 128 - full}},
	} {
		if got := computeColumnLayout(tt.width); got != tt.want {
			t.Fatalf("text width %d:\n got %+v\nwant %+v", tt.width, got, tt.want)
		}
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

// TestWarningRowStyles compares the raw output, SGR sequences included: an
// unselected warning is the padded line in ErrorStyle (what marks it as a
// warning between ordinary rows), a selected one the same line in the row
// selection style and not in ErrorStyle, whatever column is selected.
func TestWarningRowStyles(t *testing.T) {
	const width = 116
	theme := common.Current()
	columns := streamColumns(width)
	ev := NewWarningEvent(1, "Trace stopped: boom")
	line := common.PadRight("warning: Trace stopped: boom", width)
	plain := renderEventRow(ev, columns, false, -1)
	selected := renderEventRow(ev, columns, true, streamColSyscall)
	if want := theme.ErrorStyle.Render(line); plain != want {
		t.Fatalf("unselected warning row:\n got %q\nwant %q", plain, want)
	}
	if want := theme.TableSelectedRowStyle.Render(line); selected != want {
		t.Fatalf("selected warning row:\n got %q\nwant %q", selected, want)
	}
	if plain == line || selected == plain {
		t.Fatalf("the theme's styles emit no SGR here, so the comparison above proves nothing: %q", plain)
	}
}

// styledText returns the text out carries inside style's SGR sequences, byte
// for byte. ansi.Strip is no use to a sanitising test: it would remove an
// escape sequence the row let through together with the style's own.
func styledText(t *testing.T, style lipgloss.Style, out string) string {
	t.Helper()
	pre, post, _ := strings.Cut(style.Render("x"), "x")
	text, hasPre := strings.CutPrefix(out, pre)
	text, hasPost := strings.CutSuffix(text, post)
	if pre == "" || !hasPre || !hasPost {
		t.Fatalf("row is not one run in the expected style (%q...%q): %q", pre, post, out)
	}
	return text
}

// assertCleanRowText fails when text holds a control byte (ESC, tab, line
// feed, DEL, ...) or is not exactly width display cells wide.
func assertCleanRowText(t *testing.T, text string, width int) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < 0x20 || c == 0x7f {
			t.Fatalf("control byte %#x at offset %d of %q", c, i, text)
		}
	}
	if got := common.DisplayWidth(text); got != width {
		t.Fatalf("row text is %d cells, want %d: %q", got, width, text)
	}
}

// TestWarningRowSanitizesItsMessage: a warning's message is foreign text
// (libbpf output, error strings quoting a path). An escape sequence in it
// must not reach the terminal, a tab or line feed must not break the row,
// and a wide rune counts two cells, also when the cut falls beside one.
func TestWarningRowSanitizesItsMessage(t *testing.T) {
	const width = 62
	errorStyle := common.Current().ErrorStyle
	columns := streamColumns(width)

	short := NewWarningEvent(1, "libbpf:\x1b[2Jmap\t'\u754c'\nfailed\x7f")
	got := styledText(t, errorStyle, renderEventRow(short, columns, false, -1))
	want := "warning: libbpf:?[2Jmap '\u754c' failed?"
	if strings.TrimRight(got, " ") != want {
		t.Fatalf("warning row text = %q, want %q padded", got, want)
	}
	assertCleanRowText(t, got, width)

	// "warning: ?" is 10 cells, so the 52 left hold 24 wide runes, the
	// marker and one padding cell: the cut cannot split a rune to fill it.
	long := NewWarningEvent(2, "\x1b"+strings.Repeat("\u754c", 40))
	got = styledText(t, errorStyle, renderEventRow(long, columns, false, -1))
	if want := "warning: ?" + strings.Repeat("\u754c", 24) + common.ASCIIEllipsis + " "; got != want {
		t.Fatalf("cut warning row text = %q, want %q", got, want)
	}
	assertCleanRowText(t, got, width)
}

// TestPausedEnterOnWarningRowPushesNoFilter: a warning row is one spanning
// line without cells, and every value behind it is a placeholder, so Enter
// requests no filter from any column, where it used to push pid=0 or ret=-1.
// The key is consumed all the same: it shows the row's whole message (task
// b23, warningmodal_test.go).
func TestPausedEnterOnWarningRowPushesNoFilter(t *testing.T) {
	warning := NewWarningEvent(1, "Trace stopped: boom")
	for col := range streamColumnCount {
		if handled, cmd := pressEnterOnCell(t, warning, col); !handled || cmd != nil {
			t.Fatalf("column %d of a warning row: enter handled=%v, command=%v", col, handled, cmd != nil)
		}
	}
}

// TestStreamViewLayoutAcrossWidths renders the model's own view, the path
// the dashboard draws, at 200, 120 and 80 columns, and pins the Syscall
// column of each: whole names at 200 and 120, cut ones at 80, never a line
// wider than the terminal, and the warning on a single line.
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
