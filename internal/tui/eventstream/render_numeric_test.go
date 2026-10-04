package eventstream

import (
	"strings"
	"testing"

	"ior/internal/tui/common"
)

// Task b23: a number that does not fit its column was cut like a path, both
// ends kept around "...". With the default pid_max a PID has seven digits, so
// an 80-column terminal (PID 6 cells, TID 4) showed "1...30" and "1..." (or
// "...0"), the same for every thread of a process, and the five-cell Ret
// column turned -1234567 into "-...7". The tests below render the real table
// and read the cells back by the header's column offsets.

// longID is a PID of the seven digits the default pid_max (4194304) allows.
const longID = 1234430

// idTestEvent returns an ordinary row of the thread tid of process pid.
func idTestEvent(seq uint64, pid, tid uint32) StreamEvent {
	return StreamEvent{
		Seq: seq, Syscall: "read", Comm: "sleeper", PID: pid, TID: tid,
		FD: 3, DurationNs: 1500, GapNs: 300, Bytes: 64, RetVal: 64, FileName: "/tmp/f",
	}
}

// rowCells renders events at a terminal width and returns column col's cell
// of every row.
func rowCells(t *testing.T, width int, events []StreamEvent, col int) []string {
	t.Helper()
	header, rows := headerAndRows(t, streamTextLines(t, width, events))
	if len(rows) != len(events) {
		t.Fatalf("width %d: %d rows, want %d", width, len(rows), len(events))
	}
	cells := make([]string, 0, len(rows))
	for _, row := range rows {
		cells = append(cells, cellAt(t, header, row, col))
	}
	return cells
}

// assertCells compares one column's cells of the rendered rows.
func assertCells(t *testing.T, width int, events []StreamEvent, col int, want ...string) {
	t.Helper()
	got := rowCells(t, width, events, col)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("width %d: %s cells = %q, want %q", width, streamColumnTitles[col], got, want)
		}
	}
}

// TestLongIDsKeepTheirLowDigitsAt80 is the reproduction of the first point:
// two threads of one process, and a thread of another, must be told apart by
// their PID and TID cells on an 80-column terminal. The cut is at the left,
// marked by a leading "…", so the digits that differ stay.
func TestLongIDsKeepTheirLowDigitsAt80(t *testing.T) {
	events := []StreamEvent{
		idTestEvent(1, longID, longID+1),
		idTestEvent(2, longID, longID+11),
		idTestEvent(3, longID+500, longID+501),
	}
	assertCells(t, 80, events, streamColPID, "…34430", "…34430", "…34930")
	assertCells(t, 80, events, streamColTID, "…431", "…441", "…931")
	header, rows := headerAndRows(t, streamTextLines(t, 80, events))
	for _, row := range rows {
		for col, want := range map[int]string{streamColComm: "sleeper", streamColSyscall: "read", streamColFD: "3", streamColFile: "/tmp/f"} {
			if got := cellAt(t, header, row, col); got != want {
				t.Fatalf("column %q = %q, want %q: a cut id shifted the row\n%s\n%s", streamColumnTitles[col], got, want, header, row)
			}
		}
	}
}

// TestLongIDsAreWholeFromTheWidthTheyFit pins where the cut ends: the PID
// column gets its seventh cell at 91 columns and the TID column at 92
// (columnGrowSteps), and from there no id of seven digits is cut.
func TestLongIDsAreWholeFromTheWidthTheyFit(t *testing.T) {
	events := []StreamEvent{idTestEvent(1, longID, longID+1)}
	for _, tt := range []struct {
		width    int
		pid, tid string
	}{
		{90, "…34430", "…34431"},
		{91, "1234430", "…34431"},
		{92, "1234430", "1234431"},
		{100, "1234430", "1234431"},
		{120, "1234430", "1234431"},
		{200, "1234430", "1234431"},
	} {
		assertCells(t, tt.width, events, streamColPID, tt.pid)
		assertCells(t, tt.width, events, streamColTID, tt.tid)
	}
}

// TestCutTIDOfTheMainThreadPointsAtThePID: a TID that does not fit and
// equals the PID (the main thread, most rows) reads "=PID" instead of
// repeating the PID cell's low digits in fewer cells, "=" where the column
// has under four cells (78 columns: three, which the four digits of the
// second row's main thread do not fit either). A TID that fits is always
// shown as the number.
func TestCutTIDOfTheMainThreadPointsAtThePID(t *testing.T) {
	events := []StreamEvent{idTestEvent(1, longID, longID), idTestEvent(2, 4100, 4100), idTestEvent(3, longID, longID+1)}
	for _, tt := range []struct {
		width int
		want  []string
	}{
		{78, []string{"=", "=", "…31"}},
		{80, []string{"=PID", "4100", "…431"}},
		{90, []string{"=PID", "4100", "…34431"}},
		{92, []string{"1234430", "4100", "1234431"}},
	} {
		assertCells(t, tt.width, events, streamColTID, tt.want...)
	}
}

// retTestEvent returns an ordinary row with the return value ret.
func retTestEvent(seq uint64, ret int64) StreamEvent {
	ev := idTestEvent(seq, 4100, 4101)
	ev.RetVal = ret
	return ev
}

// TestRetCellKeepsSignAndLowDigits is the reproduction of the third point: a
// return value wider than the Ret column (4 cells at 80 columns, 5 from 113)
// keeps its sign and its low digits behind the marker, where it used to keep
// one digit ("-...7"). Every errno (-1 to -4095) is whole in five cells and
// all but the four-digit ones in four.
func TestRetCellKeepsSignAndLowDigits(t *testing.T) {
	events := []StreamEvent{
		retTestEvent(1, -1234567), retTestEvent(2, -2), retTestEvent(3, -512),
		retTestEvent(4, -4095), retTestEvent(5, 1048576), retTestEvent(6, 140737488355328),
	}
	assertCells(t, 80, events, streamColRet, "-…67", "-2", "-512", "-…95", "…576", "…328")
	assertCells(t, 120, events, streamColRet, "-…567", "-2", "-512", "-4095", "…8576", "…5328")
	assertCells(t, 200, events, streamColRet, "-…567", "-2", "-512", "-4095", "…8576", "…5328")
}

// TestFDAndBytesCellsAreCutFromTheLeft: the other two numeric columns follow
// the same rule. The three-cell FD column used to drop the last digits of a
// four-digit descriptor without any marker ("102" for 1024).
func TestFDAndBytesCellsAreCutFromTheLeft(t *testing.T) {
	ev := idTestEvent(1, 4100, 4101)
	ev.FD, ev.Bytes = 1024, 123456789
	events := []StreamEvent{ev, idTestEvent(2, 4100, 4101)}
	assertCells(t, 80, events, streamColFD, "…24", "3")
	assertCells(t, 80, events, streamColBytes, "…456789", "64")
	assertCells(t, 120, events, streamColFD, "1024", "3")
	assertCells(t, 120, events, streamColBytes, "…3456789", "64")
}

// TestFitNumberCell pins the cut itself: the sign is kept before any digit,
// a number that fits is returned as it is, and a cut number always carries
// the marker. Where one cell is left for the digits the cell is the marker
// alone: the low digit by itself read as another whole value (Bytes
// 1234567890 as "0", the errno -22 as "-2"). A negative number in one cell
// is "…" as well, since "-" is what an absent value shows.
func TestFitNumberCell(t *testing.T) {
	for _, tt := range []struct {
		number string
		width  int
		want   string
	}{
		{"1234567", 8, "1234567"}, {"1234567", 7, "1234567"}, {"1234567", 6, "…34567"},
		{"1234567", 2, "…7"}, {"1234567", 1, "…"}, {"1234567", 0, ""}, {"1234567", -1, ""},
		{"-1234567", 8, "-1234567"}, {"-1234567", 7, "-…34567"}, {"-1234567", 3, "-…7"},
		{"-1234567", 2, "-…"}, {"-1234567", 1, "…"}, {"-1234567", 0, ""},
		{"1234567890", 1, "…"}, {"12", 1, "…"}, {"-22", 2, "-…"}, {"-22", 1, "…"},
		{"-", 3, "-"}, {"-", 1, "-"}, {"0", 1, "0"}, {"-1", 2, "-1"}, {"-1", 1, "…"},
	} {
		got := fitNumberCell(tt.number, tt.width)
		if got != tt.want {
			t.Fatalf("fitNumberCell(%q, %d) = %q, want %q", tt.number, tt.width, got, tt.want)
		}
		if w := common.DisplayWidth(got); w > max(tt.width, 0) {
			t.Fatalf("fitNumberCell(%q, %d) = %q is %d cells wide", tt.number, tt.width, got, w)
		}
	}
}

// TestCutNumberNeverReadsAsAnotherNumber is the property behind those rows:
// at every width a cut cell holds the marker, so no cell of digits alone is
// anything but the whole number.
func TestCutNumberNeverReadsAsAnotherNumber(t *testing.T) {
	for _, number := range []string{"1234567890", "1234437", "-22", "-4095", "10", "-1"} {
		for width := 1; width <= len(number)+1; width++ {
			got := fitNumberCell(number, width)
			if got == number {
				continue
			}
			if !strings.Contains(got, common.Ellipsis) {
				t.Fatalf("fitNumberCell(%q, %d) = %q: a cut cell without the marker", number, width, got)
			}
		}
	}
}

// TestTIDCellInTheNarrowestColumns: under four cells a main thread's cut TID
// is "=" (its value is the PID cell's), another thread's follows the number
// rule down to the lone marker, never a bare low digit.
func TestTIDCellInTheNarrowestColumns(t *testing.T) {
	main, thread := idTestEvent(1, 1234437, 1234437), idTestEvent(2, 1234430, 1234437)
	for _, tt := range []struct {
		width        int
		main, thread string
	}{
		{0, "", ""}, {1, "=", "…"}, {2, "=", "…7"}, {3, "=", "…37"},
		{4, "=PID", "…437"}, {6, "=PID", "…34437"}, {7, "1234437", "1234437"},
	} {
		if got := tidCell(&main, tt.width); got != tt.main {
			t.Fatalf("main thread's TID in %d cells = %q, want %q", tt.width, got, tt.main)
		}
		if got := tidCell(&thread, tt.width); got != tt.thread {
			t.Fatalf("other thread's TID in %d cells = %q, want %q", tt.width, got, tt.thread)
		}
	}
}
