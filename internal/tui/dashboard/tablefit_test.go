package dashboard

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

// tableShapeSnapshots are the data shapes the table width tests render: the
// matrix's tallSnapshot, cells far wider than their columns (long names and
// paths, the largest counts and latencies), wide runes (CJK, emoji, keycap
// clusters, combining marks), a dir-grouped ranking with a remainder row, a
// snapshot without rows ("no data") and none at all ("waiting for stats").
func tableShapeSnapshots() map[string]*statsengine.Snapshot {
	empty := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	return map[string]*statsengine.Snapshot{
		"tall":    tallSnapshot(),
		"long":    tableShapeSnapshot(strings.Repeat("long_syscall_name_", 4), strings.Repeat("very-long-comm", 3), "/"+strings.Repeat("deeply/nested/", 15)+"file.log"),
		"wide":    tableShapeSnapshot("読み込み処理システムコール", "📁プロセス名1️⃣2️⃣é̃x", "/データ/ディレクトリ/📁📁/1️⃣#️⃣/ファイル名.txt"),
		"empty":   &empty,
		"waiting": nil,
	}
}

// tableShapeSnapshot returns a snapshot of 12 rows per table whose names,
// comms and paths derive from name, comm and path, with extreme figures, and
// a dir ranking with a remainder row.
func tableShapeSnapshot(name, comm, path string) *statsengine.Snapshot {
	var syscalls []statsengine.SyscallSnapshot
	var files []statsengine.FileSnapshot
	var procs []statsengine.ProcessSnapshot
	var dirs []statsengine.DirSnapshot
	for i := range 12 {
		big := math.MaxUint64 - uint64(i)
		syscalls = append(syscalls, statsengine.SyscallSnapshot{
			Name: fmt.Sprintf("%s%d", name, i), Count: big, RatePerSec: 1e15, Bytes: big, Errors: big,
			LatencyMeanNs: 9e18, LatencyP95Ns: big, LatencyP99Ns: big, LatencyMinNs: big, LatencyMaxNs: big, LatencyP50Ns: big,
		})
		files = append(files, statsengine.FileSnapshot{
			Path: fmt.Sprintf("%s%d", path, i), Accesses: big, BytesRead: big, BytesWritten: big, AvgLatencyNs: 9e18, MaxLatencyNs: big,
		})
		procs = append(procs, statsengine.ProcessSnapshot{
			PID: 4194304 - uint32(i), Lifetime: uint32(i), Comm: fmt.Sprintf("%s%d", comm, i), Syscalls: big, RatePerSec: 1e15, Bytes: big, AvgLatencyNs: 9e18,
		})
		dirs = append(dirs, statsengine.DirSnapshot{
			Dir: fmt.Sprintf("%s%d", path, i), Accesses: big, BytesRead: big, BytesWritten: big, AvgLatencyNs: 9e18, MaxLatencyNs: big, FileCount: big,
		})
	}
	snap := statsengine.NewSnapshot(nil, nil, nil, syscalls, files, procs, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{}).
		WithDirs(dirs, statsengine.DirSnapshot{Accesses: 7, FileCount: 99, Folded: math.MaxUint64})
	return &snap
}

// tableRenderer is one table view with the spec it is fitted by.
type tableRenderer struct {
	name   string
	spec   func(width int) tableSpec
	render func(snap *statsengine.Snapshot, width, height, offset, col int) string
	// rows is the number of table rows snap yields.
	rows func(snap *statsengine.Snapshot) int
	// note is the line drawn below the table (the Processes PID-filter
	// note), "" for none.
	note string
}

// tableRenderers lists every table view of the Syscalls, Files and Processes
// tabs: the Files table plain and dir-grouped, Processes with and without the
// PID-filter note.
func tableRenderers() []tableRenderer {
	syscallRows := func(snap *statsengine.Snapshot) []statsengine.SyscallSnapshot {
		if snap == nil {
			return nil
		}
		return snap.Syscalls()
	}
	return []tableRenderer{
		{"syscalls", syscallTableSpec, func(snap *statsengine.Snapshot, w, h, off, col int) string {
			return renderSyscallsWithSort(snap, syscallRows(snap), w, h, off, col, tableSortState[syscallSortKey]{})
		}, func(snap *statsengine.Snapshot) int { return len(syscallRows(snap)) }, ""},
		{"files", fileTableSpec, func(snap *statsengine.Snapshot, w, h, off, col int) string {
			return renderFilesWithSort(snap, w, h, off, col, tableSortState[fileSortKey]{})
		}, func(snap *statsengine.Snapshot) int { return len(snap.Files()) }, ""},
		{"files-dirs", fileDirTableSpec, func(snap *statsengine.Snapshot, w, h, off, col int) string {
			return renderFilesDirGroupedWithSort(snap, w, h, off, col, tableSortState[fileDirSortKey]{})
		}, func(snap *statsengine.Snapshot) int { return len(snapshotDirRows(snap)) }, ""},
		{"processes", func(int) tableSpec { return processTableSpec() }, func(snap *statsengine.Snapshot, w, h, off, col int) string {
			return renderProcessesWithSort(snap, w, h, off, col, -1, tableSortState[processSortKey]{})
		}, func(snap *statsengine.Snapshot) int { return len(snap.Processes()) }, ""},
		{"processes-note", func(int) tableSpec { return processTableSpec() }, func(snap *statsengine.Snapshot, w, h, off, col int) string {
			return renderProcessesWithSort(snap, w, h, off, col, 77, tableSortState[processSortKey]{})
		}, func(snap *statsengine.Snapshot) int { return len(snap.Processes()) }, "Note: this tab is most useful with All PIDs."},
	}
}

// tableSweepWidths are the widths TestTablesFitTheTerminalWidth renders at:
// every width up to 100, where the tables narrow (the widest natural layout,
// the dir-grouped Files table with its hint, needs 89 columns), and every
// seventh up to 200 (and 139/140, where the Syscalls column set changes).
func tableSweepWidths() []int {
	var widths []int
	for width := 1; width <= 200; width++ {
		if width <= 100 || width%7 == 0 || width == 139 || width == 140 || width == 200 {
			widths = append(widths, width)
		}
	}
	return widths
}

// assertLinesFit fails when a line of out is wider than width, measured both
// by lipgloss.Width and by ansi.StringWidth (the renderers' measure), so a
// disagreement on a cluster cannot hide an overflow.
func assertLinesFit(t *testing.T, label, out string, width int) {
	t.Helper()
	for i, line := range strings.Split(out, "\n") {
		if w, sw := lipgloss.Width(line), ansi.StringWidth(line); w > width || sw > width {
			t.Fatalf("%s: line %d is %d (lipgloss) / %d (ansi) cells wide, terminal has %d: %q\n%s", label, i, w, sw, width, line, out)
		}
	}
}

// The Syscalls, Files and Processes tables used to draw rows of fixed
// columns, 80 to 89 cells wide, at every width (task cz2): bubbletea v2 clips
// such lines at the terminal edge, cutting whichever columns were rightmost
// (Errors, the path, the hint), and a renderer that soft-wraps would break the
// frame's height budget. Swept at every width from 1 to 100 and a spread up
// to 200 (tableSweepWidths), with 10 rows (height 0) and 1 row (height 3),
// the first and the last column selected, over every data shape: no line is wider than the terminal,
// the table is drawn exactly from its minimum width on (the notice below),
// header and rows are aligned on the fitted columns, and the rows shown are
// the window the height allows.
func TestTablesFitTheTerminalWidth(t *testing.T) {
	for shape, snap := range tableShapeSnapshots() {
		for _, r := range tableRenderers() {
			for _, width := range tableSweepWidths() {
				spec := r.spec(width)
				for _, height := range []int{0, 3} {
					for _, col := range []int{0, len(spec.columns) - 1} {
						label := fmt.Sprintf("%s/%s %dx%d col=%d", shape, r.name, width, height, col)
						out := r.render(snap, width, height, 5, col)
						assertLinesFit(t, label, out, width)
						if snap == nil || r.rows(snap) == 0 {
							continue
						}
						assertTableLayout(t, label, cutNote(t, label, out, r.note, width), spec, r.rows(snap), width, height, col)
					}
				}
			}
		}
	}
}

// cutNote returns out without its last line, which must be note cut to the
// width; out itself when note is "".
func cutNote(t *testing.T, label, out, note string, width int) string {
	t.Helper()
	if note == "" {
		return out
	}
	table, last, ok := strings.Cut(out, "\n"+fitTableLine(note, width))
	if !ok || last != "" {
		t.Fatalf("%s: the note %q is not the last line:\n%s", label, note, out)
	}
	return table
}

// assertTableLayout checks a drawn table (rows > 0): the notice exactly below
// spec's minimum width, else a header and data rows that all span the fitted
// row width with every cell in its fitted column (separators are spaces, the
// header titles start their columns), as many data rows as the height allows,
// and the hint line last.
func assertTableLayout(t *testing.T, label, out string, spec tableSpec, rows, width, height, col int) {
	t.Helper()
	lines := strings.Split(ansi.Strip(out), "\n")
	if width < spec.minWidth() {
		if out != spec.tooNarrowNotice(width) {
			t.Fatalf("%s: below the minimum width %d want the notice, got:\n%s", label, spec.minWidth(), out)
		}
		return
	}
	fit, ok := fitTableColumns(spec, width, col)
	if !ok {
		t.Fatalf("%s: no fit from the minimum width %d on", label, spec.minWidth())
	}
	shown := min(rows, tableRowBudget(height))
	if len(lines) < shown+2 || !strings.HasPrefix(lines[shown+1], "[Row ") {
		t.Fatalf("%s: want header, %d rows and the hint line:\n%s", label, shown, out)
	}
	for i, line := range lines[:shown+1] {
		assertLineOnColumns(t, fmt.Sprintf("%s line %d", label, i), line, fit, i == 0, spec)
	}
}

// assertLineOnColumns checks that line (plain text) spans exactly the fitted
// row width and that the separator after every fitted column is a space; on
// the header (header true) each column must also start with its title.
func assertLineOnColumns(t *testing.T, label, line string, fit tableFit, header bool, spec tableSpec) {
	t.Helper()
	if got, want := ansi.StringWidth(line), tableFitWidth(fit); got != want {
		t.Fatalf("%s: %q is %d cells, the fitted row is %d", label, line, got, want)
	}
	// The line is consumed cell by cell with common.TruncateRight, which
	// measures like ansi.StringWidth and the renderers: ansi.Cut counts an
	// ASCII+U+FE0F or keycap cluster as one cell and would shift the columns.
	rest := line
	for i, w := range fit.widths {
		cell := common.TruncateRight(rest, w, "")
		if ansi.StringWidth(cell) != w {
			t.Fatalf("%s: column %d of %q is %q, not %d cells", label, i, line, cell, w)
		}
		if header && !strings.HasPrefix(cell, spec.columns[fit.visible[i]].Title) {
			t.Fatalf("%s: header column %d is %q, want title %q", label, i, cell, spec.columns[fit.visible[i]].Title)
		}
		rest = rest[len(cell):]
		if i < len(fit.widths)-1 {
			if !strings.HasPrefix(rest, " ") {
				t.Fatalf("%s: separator after column %d of %q is not a space: %q", label, i, line, rest)
			}
			rest = rest[1:]
		}
	}
}

// tableSpecsUnderTest are the fitted tables' specs at a given width.
func tableSpecsUnderTest(width int) map[string]tableSpec {
	return map[string]tableSpec{
		"syscalls":   syscallTableSpec(width),
		"files":      fileTableSpec(width),
		"files-dirs": fileDirTableSpec(width),
		"processes":  processTableSpec(),
	}
}

// fitTableColumns, at every width 1..200 and every selected column: a table
// that fits keeps its natural layout; otherwise it is laid out exactly from
// its minimum width on, never wider than the width and using all of it, with
// every required column and the flex column at least flexMin wide; columns go
// in drop order (the selected one last, and only when the flex column could
// not keep flexMin beside it); and a wider terminal never shows fewer
// columns.
func TestFitTableColumnsPolicy(t *testing.T) {
	for width := 1; width <= 200; width++ {
		for name, spec := range tableSpecsUnderTest(width) {
			for col := range spec.columns {
				label := fmt.Sprintf("%s width=%d col=%d", name, width, col)
				fit, ok := fitTableColumns(spec, width, col)
				natural := naturalTableFit(spec.columns)
				switch {
				case tableFitWidth(natural) <= width:
					if !ok || !slices.Equal(fit.visible, natural.visible) || !slices.Equal(fit.widths, natural.widths) {
						t.Fatalf("%s: the natural layout fits but got %+v", label, fit)
					}
					continue
				case ok != (width >= spec.minWidth()):
					t.Fatalf("%s: ok=%v with minimum width %d", label, ok, spec.minWidth())
				case !ok:
					continue
				}
				assertFitPolicy(t, label, spec, fit, width, col)
				if wider, _ := fitTableColumns(tableSpecsUnderTest(width + 1)[name], width+1, col); len(wider.visible) < len(fit.visible) {
					t.Fatalf("%s: %d columns, but %d at one column more", label, len(fit.visible), len(wider.visible))
				}
			}
		}
	}
}

// assertFitPolicy checks one narrowed layout of TestFitTableColumnsPolicy.
func assertFitPolicy(t *testing.T, label string, spec tableSpec, fit tableFit, width, col int) {
	t.Helper()
	if got := tableFitWidth(fit); got != width {
		t.Fatalf("%s: a narrowed table is %d cells wide, want all %d", label, got, width)
	}
	if !slices.IsSorted(fit.visible) {
		t.Fatalf("%s: columns out of logical order: %v", label, fit.visible)
	}
	for idx := range spec.columns {
		shown := fit.visibleIndex(idx) >= 0
		if !shown && !isOptionalColumn(spec, idx) {
			t.Fatalf("%s: required column %d dropped: %v", label, idx, fit.visible)
		}
	}
	if w := fit.widths[fit.visibleIndex(spec.flex)]; w < spec.flexMin {
		t.Fatalf("%s: flex column is %d cells, minimum %d", label, w, spec.flexMin)
	}
	// The selected column goes only when even flexMin would not fit beside it.
	if fit.visibleIndex(col) < 0 && width >= spec.minWidth()+spec.columns[col].Width+1 {
		t.Fatalf("%s: selected column dropped although %d columns hold it: %v", label, width, fit.visible)
	}
	// Drop order: once a column is shown, every later one (but the selected)
	// is shown too.
	seenShown := false
	for _, idx := range spec.dropOrder {
		if idx == col {
			continue
		}
		shown := fit.visibleIndex(idx) >= 0
		if seenShown && !shown {
			t.Fatalf("%s: column %d dropped after a column dropped later in %v: %v", label, idx, spec.dropOrder, fit.visible)
		}
		seenShown = seenShown || shown
	}
}

// A narrowed table still highlights the selected row and, while it is shown,
// the selected cell (projected onto the shown columns), and its hint keeps
// the logical "Col x/N" and whole " [..]" segments only.
func TestNarrowTableKeepsSelectionAndHint(t *testing.T) {
	snap := tallSnapshot()
	spec := syscallTableSpec(40)
	// Column 6 is p99, the first to go; selected, it stays at 40 columns.
	out := renderSyscallsWithSort(snap, snap.Syscalls(), 40, 10, 3, 6, tableSortState[syscallSortKey]{})
	plain := ansi.Strip(out)
	lines := strings.Split(plain, "\n")
	if !strings.Contains(lines[0], "p99") || strings.Contains(lines[0], "p95") {
		t.Fatalf("selected p99 must be kept over p95 at 40 columns:\n%s", plain)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "[Row 4/40 Col 7/9]") {
		t.Fatalf("hint lost the logical position: %q", lines[len(lines)-1])
	}
	selectedCell := common.Current().TableSelectedCellStyle.Render(common.FitRight("0ns", 8, common.ASCIIEllipsis))
	if !strings.Contains(out, selectedCell) {
		t.Fatalf("selected p99 cell not highlighted:\n%q", out)
	}
	fit, _ := fitTableColumns(spec, 40, 6)
	if fit.visibleIndex(6) < 0 {
		t.Fatalf("p99 not in the fit: %v", fit.visible)
	}
	for _, tc := range []struct {
		width int
		want  string
	}{
		{200, "[a b] [cc] [ddd]"},
		{16, "[a b] [cc] [ddd]"},
		{15, "[a b] [cc]"},
		{10, "[a b] [cc]"},
		{9, "[a b]"},
		{4, "[a …"},
		{1, "["},
	} {
		if got := fitHintSegments([]string{"a b", "cc", "ddd"}, tc.width); got != tc.want {
			t.Errorf("fitHintSegments(width=%d) = %q, want %q", tc.width, got, tc.want)
		}
	}
}

// The policy of each table: which columns a typical narrow terminal keeps.
// The required ones (name, count or PID) survive to the minimum width, the
// mean latency is the last optional column to go.
func TestTableFitPolicyPerTable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  tableSpec
		width int
		want  []string
	}{
		{"syscalls", syscallTableSpec(80), 80, []string{"Syscall", "Family", "Count", "Rate/s", "Avg", "p95", "Bytes", "Errors"}},
		{"syscalls", syscallTableSpec(60), 60, []string{"Syscall", "Count", "Rate/s", "Avg", "Bytes", "Errors"}},
		{"syscalls", syscallTableSpec(30), 30, []string{"Syscall", "Count", "Avg"}},
		{"syscalls", syscallTableSpec(15), 15, []string{"Syscall", "Count"}},
		{"files", fileTableSpec(60), 60, []string{"Accesses", "Read", "Write", "Avg Latency", "Path"}},
		{"files", fileTableSpec(30), 30, []string{"Accesses", "Path"}},
		{"files", fileTableSpec(19), 19, []string{"Accesses", "Path"}},
		{"files-dirs", fileDirTableSpec(60), 60, []string{"Accesses", "Read", "Avg Latency", "Files", "Directory"}},
		{"files-dirs", fileDirTableSpec(19), 19, []string{"Accesses", "Directory"}},
		{"processes", processTableSpec(), 60, []string{"PID", "Comm", "Syscalls", "Avg Latency"}},
		{"processes", processTableSpec(), 19, []string{"PID", "Comm"}},
	} {
		fit, ok := fitTableColumns(tc.spec, tc.width, tc.spec.flex)
		var got []string
		for _, c := range fit.columns(tc.spec) {
			got = append(got, c.Title)
		}
		if !ok || !slices.Equal(got, tc.want) {
			t.Errorf("%s at %d columns: %v (ok=%v), want %v", tc.name, tc.width, got, ok, tc.want)
		}
	}
	for name, want := range map[string]int{"syscalls": 15, "files": 19, "files-dirs": 19, "processes": 19} {
		if got := tableSpecsUnderTest(80)[name].minWidth(); got != want {
			t.Errorf("%s minimum width %d, want %d", name, got, want)
		}
	}
	if got := ansi.Strip(renderFilesWithSort(tallSnapshot(), 18, 10, 0, 0, tableSortState[fileSortKey]{})); got != "Files: terminal t…" {
		t.Errorf("Files at 18 columns = %q, want the cut notice", got)
	}
	// The flex cells are cut by the table's own rule at their fitted width:
	// a path keeps both ends (its file name), a comm its start.
	long := tableShapeSnapshots()["long"]
	if out := ansi.Strip(renderFilesWithSort(long, 30, 4, 0, 0, tableSortState[fileSortKey]{})); !strings.Contains(out, " /deeply/n...file.log0") {
		t.Errorf("Files at 30 columns does not cut the path in the middle:\n%s", out)
	}
	if out := ansi.Strip(renderProcessesWithSort(long, 30, 4, 0, 0, -1, tableSortState[processSortKey]{})); !strings.Contains(out, " very-long-commve...") {
		t.Errorf("Processes at 30 columns does not cut the comm with \"...\":\n%s", out)
	}
}

// The Syscalls, Files and Processes tabs in every visualization mode (table,
// dir-grouped table, bubbles, treemap, icicle) through the whole frame at
// every width from 1 to 19 (TestEveryTabFitsTheTerminalHeight starts at 20)
// and around the widths where each table narrows, with and without the help
// bar: the frame contract (assertFrameFits) holds, no line is wider than the
// terminal. The heights are a one-row table (5) and a full one (24); the
// matrix covers every height at its widths, and TestTablesFitTheTerminalWidth
// sweeps the table renderers themselves at every width.
func TestTableTabsFitNarrowTerminals(t *testing.T) {
	var widths []int
	for width := 1; width <= 19; width++ {
		widths = append(widths, width)
	}
	widths = append(widths, 25, 40, 66, 67, 74, 75, 79, 80, 81, 82, 85, 86, 88, 89)
	for _, c := range fitCases() {
		if c.tab != TabSyscalls && c.tab != TabFiles && c.tab != TabProcesses {
			continue
		}
		for _, help := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/help=%v", c, help), func(t *testing.T) {
				for _, width := range widths {
					for _, height := range []int{5, 24} {
						assertViewFits(t, c, help, width, height)
					}
				}
			})
		}
	}
}

// Before the first stats snapshot the table tabs show the "waiting for
// stats" panel (renderWaitingForStats), and a snapshot without rows the
// "no data" line; a narrow terminal shows them right at startup. Through the
// whole frame, every view of the three tabs keeps the frame contract
// (assertFrameFits: no line wider than the terminal) at every width from 1
// to 40.
func TestTableTabPlaceholdersFitNarrowTerminals(t *testing.T) {
	empty := statsengine.NewSnapshot(nil, nil, nil, nil, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	for _, c := range fitCases() {
		if c.tab != TabSyscalls && c.tab != TabFiles && c.tab != TabProcesses {
			continue
		}
		for snapName, snap := range map[string]*statsengine.Snapshot{"waiting": nil, "no data": &empty} {
			for width := 1; width <= 40; width++ {
				for _, height := range []int{5, 24} {
					m := NewModelWithConfig(nil, eventstream.NewRingBuffer(), 250, 200, common.DefaultKeyMap())
					m.activeTab = c.tab
					m.filesDirGrouped = c.grouped
					m.setTabVizMode(c.tab, c.mode)
					next, _ := m.Update(tea.WindowSizeMsg{Width: width, Height: height})
					m = next.(*Model)
					if snap != nil {
						m = tickStats(t, m, messages.StatsTickMsg{Snap: snap})
					}
					assertFrameFits(t, m, c, fmt.Sprintf("%s %s %dx%d", c, snapName, width, height), width, height)
				}
			}
		}
	}
}
