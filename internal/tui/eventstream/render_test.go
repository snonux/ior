package eventstream

import (
	"strings"
	"testing"
	"unicode/utf8"

	"ior/internal/tui/common"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

func TestRenderStatusAndFilterLines(t *testing.T) {
	events := []StreamEvent{{Syscall: "read", Comm: "nginx", PID: 1, TID: 2, DurationNs: 1200, GapNs: 300, Bytes: 64, FileName: "/tmp/a", RetVal: 64}}
	f := Filter{Syscall: &StringFilter{Pattern: "read"}, PID: &NumericFilter{Op: OpEq, Value: 1}}
	out := RenderStreamTable(120, false, 100, 1, 100, 10000, f, nil, events, -1, -1)

	for _, want := range []string{"LIVE", "total:100", "filtered:1", "buffer:100/10000", "Filter:", "syscall~read", "pid=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}

func TestRenderPausedAndErrorRow(t *testing.T) {
	events := []StreamEvent{{Syscall: "write", Comm: "worker", PID: 1, TID: 2, DurationNs: 1000000, GapNs: 5000, Bytes: 32, FileName: "/tmp/b", RetVal: -1, IsError: true}}
	out := RenderStreamTable(120, true, 10, 1, 10, 10000, Filter{}, nil, events, -1, -1)

	if !strings.Contains(out, "PAUSED") {
		t.Fatalf("expected PAUSED indicator\n%s", out)
	}
	if !strings.Contains(out, "-1") {
		t.Fatalf("expected return value in row\n%s", out)
	}
	if !strings.Contains(out, "worker") || !strings.Contains(out, "write") {
		t.Fatalf("expected event row in output\n%s", out)
	}
}

func TestRenderShowsFDWhenPresent(t *testing.T) {
	events := []StreamEvent{{Syscall: "read", Comm: "worker", PID: 1, TID: 2, FD: 9, DurationNs: 10, GapNs: 1, Bytes: 8, FileName: "/tmp/b", RetVal: 8}}
	out := RenderStreamTable(120, false, 1, 1, 1, 10000, Filter{}, nil, events, -1, -1)
	if !strings.Contains(out, "FD") || !strings.Contains(out, " 9 ") {
		t.Fatalf("expected FD column/value in output\n%s", out)
	}
}

func TestRenderHeaderAndTruncate(t *testing.T) {
	events := []StreamEvent{{
		Syscall:    "very_long_syscall_name",
		Comm:       "very-long-command-name",
		PID:        1,
		TID:        2,
		DurationNs: 2_000_000,
		GapNs:      100,
		Bytes:      4096,
		FileName:   "/very/long/path/that/should/be/truncated/for/narrow/views/file.log",
		RetVal:     1,
	}}
	out := RenderStreamTable(80, false, 1, 1, 1, 10000, Filter{}, nil, events, -1, -1)

	for _, col := range []string{"Gap", "Latency", "Comm", "PID", "TID", "Syscall", "FD", "Ret", "Bytes", "File"} {
		if !strings.Contains(out, col) {
			t.Fatalf("missing column %q\n%s", col, out)
		}
	}
	if !strings.Contains(out, "...") {
		t.Fatalf("expected truncated field with ellipsis\n%s", out)
	}
}

func TestFormatDurationNs(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{in: 999, want: "999ns"},
		{in: 1500, want: "1.5us"},
		{in: 2_000_000, want: "2.0ms"},
	}
	for _, tc := range cases {
		if got := formatDurationNs(tc.in); got != tc.want {
			t.Fatalf("formatDurationNs(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRenderEventRowIsSingleLineWithControlCharsAndLongValues(t *testing.T) {
	ev := StreamEvent{
		Syscall:    "very_very_long_syscall_name_that_would_otherwise_overflow",
		Comm:       "cmd\twith\tcontrols",
		PID:        1234567,
		TID:        7654321,
		DurationNs: 123456789012345,
		GapNs:      9988776655443322,
		Bytes:      18446744073709551615,
		FileName:   "/very/long/path/with/newline\nand\ttabs/that/should/not/wrap",
		RetVal:     -9223372036854775808,
	}

	row := renderEventRow(ev, streamColumns(80), false, -1)
	if strings.Contains(row, "\n") || strings.Contains(row, "\r") || strings.Contains(row, "\t") {
		t.Fatalf("expected a sanitized single-line row, got %q", row)
	}
	if !strings.Contains(row, "...") {
		t.Fatalf("expected truncation ellipsis in narrow row, got %q", row)
	}
}

// TestRenderEventRowShowsDashesForNoReturn (task pr2): a noreturn row (exit,
// exit_group, rt_sigreturn) has neither a latency nor a return value, so the
// Stream tab shows "-" in both cells rather than the placeholder 0s, and an
// ordinary row with the same zeros still shows them.
func TestRenderEventRowShowsDashesForNoReturn(t *testing.T) {
	columns := streamColumns(120)
	cellsOf := func(ev StreamEvent) []string {
		return strings.Fields(ansi.Strip(renderEventRow(ev, columns, false, -1)))
	}
	ev := StreamEvent{Syscall: "exit_group", Comm: "proc", PID: 7, TID: 7, FD: -1, FileName: "N:file", NoReturn: true}
	got := cellsOf(ev)
	// gap, latency, comm, pid, tid, syscall, fd, ret, bytes, file
	if len(got) != 10 || got[1] != "-" || got[7] != "-" {
		t.Fatalf("noreturn row cells = %q, want latency and ret \"-\"", got)
	}
	ev.NoReturn = false
	got = cellsOf(ev)
	if len(got) != 10 || got[1] == "-" || got[7] != "0" {
		t.Fatalf("ordinary row cells = %q, want a latency and ret 0", got)
	}
}

// TestComputeColumnLayoutGivesFileMoreSpace: at 120 cells the File column is
// by far the widest column. It was 46 cells while the Syscall column stayed
// at 9; since task 923 the Syscall column takes 8 of those to show syscall
// names whole, and the File column still gets twice what any other has.
func TestComputeColumnLayoutGivesFileMoreSpace(t *testing.T) {
	cols := computeColumnLayout(120)
	if cols.file != 38 {
		t.Fatalf("file column is %d cells at 120, want 38", cols.file)
	}
	for i, f := range columnFields(&cols) {
		if i != streamColFile && *f*2 > cols.file {
			t.Fatalf("column %d is %d wide, more than half the file column's %d", i, *f, cols.file)
		}
	}
}

func TestRenderStreamTableFitsRequestedWidth(t *testing.T) {
	out := RenderStreamTable(80, false, 1, 1, 1, 10000, Filter{}, nil, []StreamEvent{
		{
			Syscall:    "read",
			Comm:       "worker",
			PID:        1,
			TID:        2,
			DurationNs: 2000,
			GapNs:      100,
			Bytes:      64,
			FileName:   "/very/long/path/that/should/be/truncated/for/narrow/views/file.log",
			RetVal:     1,
		},
	}, -1, -1)

	for _, line := range strings.Split(out, "\n") {
		if lipgloss.Width(line) > 80 {
			t.Fatalf("line exceeds width 80: %d %q", lipgloss.Width(line), line)
		}
	}
}

func TestRenderShowsFilterStackLine(t *testing.T) {
	out := RenderStreamTable(100, true, 3, 1, 3, 10000, Filter{Comm: &StringFilter{Pattern: "system"}}, []string{"comm~system", "fd=20"}, []StreamEvent{{Comm: "systemd", Syscall: "write"}}, -1, -1)
	for _, want := range []string{"Stack:", "comm~system", "fd=20"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected stack output missing %q\n%s", want, out)
		}
	}
}

func TestRenderFDTraceTableShowsHeaderAndScope(t *testing.T) {
	out := RenderFDTraceTable(100, 123, 7, 2, []StreamEvent{
		{Syscall: "read", PID: 123, TID: 1, FD: 7, FileName: "/tmp/a"},
		{Syscall: "write", PID: 123, TID: 2, FD: 7, FileName: "/tmp/a"},
	})
	for _, want := range []string{"FD Trace (ring snapshot)", "PID:123 FD:7 matched:2", "read", "write"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q\n%s", want, out)
		}
	}
}

// narrowTestEvents returns rows whose cells all overflow their columns, the
// worst case for wrapping on narrow terminals.
func narrowTestEvents() []StreamEvent {
	return []StreamEvent{
		{Syscall: "very_long_syscall_name", Comm: "very-long-command-name", PID: 4294967295, TID: 4294967295, FD: 12345,
			DurationNs: 123456789012, GapNs: 123456789012, Bytes: 18446744073709551615, RetVal: -9223372036854775808,
			FileName: "/very/long/path/that/should/be/truncated/for/narrow/views/file.log", IsError: true},
		{Syscall: "read", Comm: "worker", PID: 1, TID: 2, FD: 3, FileName: "/tmp/a"},
	}
}

// assertPanelFits checks that out has exactly wantLines terminal lines (no
// wrapping) and that no line is wider than the terminal width. Below the
// smallest possible panel (frame + one cell) that panel's width is the limit.
func assertPanelFits(t *testing.T, width int, out string, wantLines int) {
	t.Helper()
	lines := strings.Split(out, "\n")
	if len(lines) != wantLines {
		t.Fatalf("width %d: got %d lines, want %d (rows wrapped)\n%s", width, len(lines), wantLines, out)
	}
	limit := max(width, common.Current().PanelStyle.GetHorizontalFrameSize()+1)
	for _, line := range lines {
		if w := lipgloss.Width(line); w > limit {
			t.Fatalf("width %d: line is %d cols wide, limit %d: %q", width, w, limit, line)
		}
	}
}

// Regression for task go2: below ~94 columns the column layout was sized for
// the panel's outer width, and the panel had a 20-column floor, so rows
// wrapped to two lines while visibleRows() budgets one, pushing
// footer/status off-screen.
func TestRenderStreamTableDoesNotWrapAtAnyWidth(t *testing.T) {
	filter := Filter{Comm: &StringFilter{Pattern: strings.Repeat("c", 150)}, PID: &NumericFilter{Op: OpEq, Value: 1}}
	stack := []string{strings.Repeat("comm~x", 30), "fd=20"}
	events := narrowTestEvents()
	for width := 1; width <= 160; width++ {
		for _, paused := range []bool{false, true} {
			sel := -1
			if paused {
				sel = 0
			}
			out := RenderStreamTable(width, paused, 123456789, 123456789, 123456, 1234567, filter, stack, events, sel, streamColFile)
			// border top + status + filter + stack + header + rows + border bottom
			assertPanelFits(t, width, out, 5+len(events)+1)
		}
	}
}

func TestRenderFDTraceTableDoesNotWrapAtAnyWidth(t *testing.T) {
	events := narrowTestEvents()
	for width := 1; width <= 160; width++ {
		out := RenderFDTraceTable(width, 4294967295, 2147483647, 123456789, events)
		// border top + title + scope + header + rows + border bottom
		assertPanelFits(t, width, out, 4+len(events)+1)
	}
}

func TestRenderStreamTableNonPositiveWidthUsesDefault(t *testing.T) {
	want := RenderStreamTable(100, false, 1, 1, 1, 10, Filter{}, nil, narrowTestEvents(), -1, -1)
	for _, width := range []int{0, -1, -500} {
		if got := RenderStreamTable(width, false, 1, 1, 1, 10, Filter{}, nil, narrowTestEvents(), -1, -1); got != want {
			t.Fatalf("width %d: expected default-width rendering", width)
		}
	}
}

func TestComputeColumnLayoutFitsWidth(t *testing.T) {
	// 10 one-cell columns plus 9 separators is the smallest possible row.
	const minRow = streamColumnCount*2 - 1
	for width := 1; width <= 200; width++ {
		cols := computeColumnLayout(width)
		for i, f := range columnFields(&cols) {
			if *f < 1 {
				t.Fatalf("width %d: column %d has width %d", width, i, *f)
			}
		}
		got := rowWidth(&cols)
		switch {
		case width >= minRow && got > width:
			t.Fatalf("width %d: row is %d wide", width, got)
		case width < minRow && got != minRow:
			t.Fatalf("width %d: expected minimal row %d, got %d", width, minRow, got)
		case width >= 78 && cols.file < 12:
			t.Fatalf("width %d: file column squeezed to %d", width, cols.file)
		}
	}
}

func TestComputeColumnLayoutNonPositiveWidthUsesDefault(t *testing.T) {
	want := computeColumnLayout(100)
	for _, width := range []int{0, -1} {
		if got := computeColumnLayout(width); got != want {
			t.Fatalf("width %d: got %+v, want %+v", width, got, want)
		}
	}
}

// TestFitCellMultiByteFileName is the regression for byte-based middle
// truncation: cutting "/data/日本語のファイル名.txt" at byte offsets split a
// multi-byte rune and rendered invalid glyphs. fitCell must keep whole
// graphemes and stay within the column's display width.
func TestFitCellMultiByteFileName(t *testing.T) {
	tests := []struct {
		in    string
		width int
		want  string
	}{
		{"/data/日本語のファイル名.txt", 20, "/data/日...ル名.txt"},
		{"/data/日本語のファイル名.txt", 3, "/da"},
		// The newline is flattened to a space ("日本 語", 7 cells); the
		// 1-cell head budget cannot hold 日, so its cell goes to the tail.
		{"日本\n語", 5, "...語"},
		{"x", 0, ""},
		{"x", -1, ""},
	}
	for _, tc := range tests {
		got := fitCell(tc.in, tc.width)
		if got != tc.want {
			t.Fatalf("fitCell(%q, %d) = %q, want %q", tc.in, tc.width, got, tc.want)
		}
		if !utf8.ValidString(got) || common.DisplayWidth(got) > max(tc.width, 0) {
			t.Fatalf("fitCell(%q, %d) = %q: invalid UTF-8 or too wide", tc.in, tc.width, got)
		}
	}
}

// hostileEvent carries attacker-controlled comm and file names: an OSC 8
// hyperlink, SGR hidden text, a raw C1 CSI byte and DEL (task io2).
func hostileEvent() StreamEvent {
	return StreamEvent{
		Syscall:  "openat",
		Comm:     "a\x1b[8mhid\x7f",
		PID:      1,
		TID:      1,
		FD:       3,
		FileName: "/tmp/\x1b]8;;http://evil\aclick\x1b]8;;\a/\x9b31mred",
	}
}

// assertNoInjectedEscapes fails when out contains one of the payloads'
// terminal-control sequences or bytes. The theme's own styling may emit
// ESC [ ... m, so it checks for the payload sequences specifically.
func assertNoInjectedEscapes(t *testing.T, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b]8", "\x1b[8m", "\a", "\x9b", "\x7f"} {
		if strings.Contains(out, bad) {
			t.Fatalf("output contains injected %q:\n%q", bad, out)
		}
	}
}

func TestRenderEventRowSanitizesEscapeSequences(t *testing.T) {
	columns := streamColumns(120)
	row := renderEventRow(hostileEvent(), columns, false, -1)
	if strings.Contains(row, "\x1b") {
		t.Fatalf("unstyled row contains ESC: %q", row)
	}
	if !utf8.ValidString(row) {
		t.Fatalf("row is not valid UTF-8: %q", row)
	}
	layout := computeColumnLayout(120)
	if got, want := common.DisplayWidth(row), rowWidth(&layout); got != want {
		t.Fatalf("row width = %d, want %d: %q", got, want, row)
	}
}

func TestRenderStreamAndFDTraceTablesSanitizeEscapeSequences(t *testing.T) {
	ev := hostileEvent()
	filter := Filter{Comm: &StringFilter{Pattern: ev.Comm}, File: &StringFilter{Pattern: ev.FileName}}
	assertNoInjectedEscapes(t, RenderStreamTable(120, true, 1, 1, 1, 10, filter, []string{"comm~" + ev.Comm}, []StreamEvent{ev}, 0, 9))
	assertNoInjectedEscapes(t, RenderFDTraceTable(120, 1, 3, 1, []StreamEvent{ev}))
}

func TestStreamFooterSanitizesStatusMessage(t *testing.T) {
	m := &Model{}
	m.SetStatusMessage("Exported: /tmp/\x1b]8;;http://evil\a.csv")
	assertNoInjectedEscapes(t, m.appendStreamFooter("base", 0, 2))
}
