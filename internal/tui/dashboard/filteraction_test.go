package dashboard

import (
	"strings"
	"testing"

	"ior/internal/globalfilter/presenter"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// enterFilterRequest presses enter on m and returns the emitted filter
// request, or ok=false when enter produced no GlobalFilterRequestedMsg.
func enterFilterRequest(t *testing.T, m *Model) (messages.GlobalFilterRequestedMsg, bool) {
	t.Helper()
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd == nil {
		return messages.GlobalFilterRequestedMsg{}, false
	}
	req, ok := cmd().(messages.GlobalFilterRequestedMsg)
	return req, ok
}

func syscallsModel(rows ...statsengine.SyscallSnapshot) *Model {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, rows, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	return m
}

func filesModel(grouped bool, rows ...statsengine.FileSnapshot) *Model {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.filesDirGrouped = grouped
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, rows, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	return m
}

func processesModel(col int, rows ...statsengine.ProcessSnapshot) *Model {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, rows, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesTab.col = col
	return m
}

// TestEnterFilterActionLabelMatchesPresenter pins every dashboard filter
// action label to the presenter's canonical token for the dimension the tab
// sets, across each dimension and values with spaces, filter-syntax
// characters and padding. Syscall and file values become exact (^value$)
// patterns and a directory row a directory-children pattern (^dir/*), so
// the label shows the anchors; a process's Comm cell stays a trimmed
// substring.
func TestEnterFilterActionLabelMatchesPresenter(t *testing.T) {
	familySyscalls := syscallsModel(statsengine.SyscallSnapshot{TraceID: types.SYS_ENTER_READ, Name: "read", Count: 1})
	familySyscalls.syscallsTab.col = syscallFamilyColumn
	wantFamily := "family~" + string(types.SYS_ENTER_READ.Family())

	tests := []struct {
		name string
		m    *Model
		dim  presenter.Dimension
		want string
	}{
		{"syscall", syscallsModel(statsengine.SyscallSnapshot{Name: "openat", Count: 1}), presenter.DimSyscall, "syscall~^openat$"},
		{"family", familySyscalls, presenter.DimFamily, wantFamily},
		{"file path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a b~c=d"}), presenter.DimFile, "file~^/tmp/a b~c=d$"},
		{"file dir", filesModel(true, statsengine.FileSnapshot{Path: "/var/log/x"}), presenter.DimFile, "file~^/var/log/*"},
		{"pid", processesModel(0, statsengine.ProcessSnapshot{PID: 4242, Comm: "sh"}), presenter.DimPID, "pid=4242"},
		{"comm", processesModel(1, statsengine.ProcessSnapshot{PID: 7, Comm: "kworker/0:1"}), presenter.DimComm, "comm~kworker/0:1"},
		// The Comm cell stays a trimmed substring pattern (see rowfilter.go).
		{"padded comm", processesModel(1, statsengine.ProcessSnapshot{PID: 7, Comm: "  sh  "}), presenter.DimComm, "comm~sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ok := enterFilterRequest(t, tt.m)
			if !ok {
				t.Fatalf("expected enter to emit a GlobalFilterRequestedMsg")
			}
			if req.Action != tt.want {
				t.Fatalf("expected action %q, got %q", tt.want, req.Action)
			}
			if canonical := presenter.DimensionSummary(req.Filter, tt.dim); req.Action != canonical {
				t.Fatalf("action %q differs from presenter token %q", req.Action, canonical)
			}
		})
	}
}

// TestEnterFilterRequestRejectsEmptyValues: rows with no filterable value
// emit no request, and a process with a blank comm falls back to its PID.
func TestEnterFilterRequestRejectsEmptyValues(t *testing.T) {
	for _, tt := range []struct {
		name string
		m    *Model
	}{
		{"blank syscall name", syscallsModel(statsengine.SyscallSnapshot{Name: "  ", Count: 1})},
		{"blank file path", filesModel(false, statsengine.FileSnapshot{Path: " "})},
		{"zero pid", processesModel(0, statsengine.ProcessSnapshot{PID: 0, Comm: "sh"})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if req, ok := enterFilterRequest(t, tt.m); ok {
				t.Fatalf("expected no filter request, got %+v", req)
			}
		})
	}

	req, ok := enterFilterRequest(t, processesModel(1, statsengine.ProcessSnapshot{PID: 9, Comm: "   "}))
	if !ok {
		t.Fatalf("expected blank comm to fall back to a pid request")
	}
	if want := presenter.DimensionSummary(req.Filter, presenter.DimPID); req.Action != want || want != "pid=9" {
		t.Fatalf("expected pid=9 fallback, got action %q (presenter %q)", req.Action, want)
	}
}

// TestEnterRowFilterSelectsExactlyTheRow is the regression test for row
// filters that used the row's value as a bare substring pattern: the matcher
// trims blanks and reads an edge ^/$ as an anchor, so Enter on "/tmp/a "
// also selected "/tmp/ab", and Enter on "read" also selected readv. Each
// case runs the emitted filter against real stream rows: the row itself must
// match, every near-miss must not - including case variants of exact rows,
// since ^value$ is case-sensitive (/TMP/A is a different file from /tmp/a).
// The dir rows select exactly their direct files, case-sensitively too
// (task ip2): no subdirectory file, and the root row only top-level entries.
// The comm case pins
// the deliberate exception: thread comms extending the process's comm still
// match.
func TestEnterRowFilterSelectsExactlyTheRow(t *testing.T) {
	file := func(name string) *streamrow.Row { return &streamrow.Row{FileName: name} }
	for _, tt := range []struct {
		name  string
		m     *Model
		match []*streamrow.Row
		miss  []*streamrow.Row
	}{
		{"trailing blank path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a "}),
			[]*streamrow.Row{file("/tmp/a ")},
			[]*streamrow.Row{file("/TMP/A "), file("/tmp/a"), file("/tmp/ab"), file("/tmp/a b"), file("x/tmp/a ")}},
		{"leading blank path", filesModel(false, statsengine.FileSnapshot{Path: " /tmp/a"}),
			[]*streamrow.Row{file(" /tmp/a")},
			[]*streamrow.Row{file("/tmp/a"), file(" /tmp/ab")}},
		{"plain path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a"}),
			[]*streamrow.Row{file("/tmp/a")},
			[]*streamrow.Row{file("/tmp/A"), file("/tmp/abc"), file("/var/tmp/a")}},
		// Literal edge anchors stay literal: bare, "x$" meant "ends with x"
		// and "^x" meant "starts with x".
		{"literal dollar", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/x$"}),
			[]*streamrow.Row{file("/tmp/x$")},
			[]*streamrow.Row{file("/tmp/x"), file("/tmp/x$y")}},
		{"literal caret", filesModel(false, statsengine.FileSnapshot{Path: "^x"}),
			[]*streamrow.Row{file("^x")},
			[]*streamrow.Row{file("x"), file("a^x")}},
		{"dir children", filesModel(true, statsengine.FileSnapshot{Path: "/tmp/a"}),
			[]*streamrow.Row{file("/tmp/a"), file("/tmp/b")},
			[]*streamrow.Row{file("/tmp"), file("/tmp/sub/c"), file("/TMP/a"), file("/tmpfoo/a"), file("/var/tmp/a")}},
		{"root dir", filesModel(true, statsengine.FileSnapshot{Path: "/a"}),
			[]*streamrow.Row{file("/a"), file("/etc")},
			[]*streamrow.Row{file("/etc/passwd"), file("relative"), file("socket:[1]")}},
		{"syscall", syscallsModel(statsengine.SyscallSnapshot{Name: "read", Count: 1}),
			[]*streamrow.Row{{Syscall: "read"}},
			[]*streamrow.Row{{Syscall: "READ"}, {Syscall: "readv"}, {Syscall: "pread64"}}},
		{"comm", processesModel(processCommColumn, statsengine.ProcessSnapshot{PID: 7, Comm: "chrome"}),
			[]*streamrow.Row{{Comm: "chrome"}, {Comm: "Chrome_ChildIOT"}},
			[]*streamrow.Row{{Comm: "firefox"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, ok := enterFilterRequest(t, tt.m)
			if !ok {
				t.Fatalf("expected enter to emit a GlobalFilterRequestedMsg")
			}
			for _, row := range tt.match {
				if !req.Filter.Matches(row) {
					t.Errorf("filter %s should match %+v", req.Action, *row)
				}
			}
			for _, row := range tt.miss {
				if req.Filter.Matches(row) {
					t.Errorf("filter %s should not match %+v", req.Action, *row)
				}
			}
		})
	}
}

// TestEnterFamilyFilterStaysBare pins the one deliberate exception to exact
// row patterns: the family filter keeps the bare family name, which the [/]
// family cycle reads back as the current family. That is only as precise as
// an exact match because no family name contains another; checking that here
// catches a future family that would break it.
func TestEnterFamilyFilterStaysBare(t *testing.T) {
	m := syscallsModel(statsengine.SyscallSnapshot{TraceID: types.SYS_ENTER_READ, Name: "read", Count: 1})
	m.syscallsTab.col = syscallFamilyColumn
	req, ok := enterFilterRequest(t, m)
	if !ok {
		t.Fatalf("expected enter to emit a GlobalFilterRequestedMsg")
	}
	if want := string(types.SYS_ENTER_READ.Family()); req.Filter.Family == nil || req.Filter.Family.Pattern != want {
		t.Fatalf("expected bare family pattern %q, got %+v", want, req.Filter.Family)
	}
	families := types.AllSyscallFamilies()
	for _, a := range families {
		for _, b := range families {
			if a != b && strings.Contains(strings.ToLower(string(b)), strings.ToLower(string(a))) {
				t.Fatalf("family %q contains family %q: a bare family filter would select both", b, a)
			}
		}
	}
}

// TestEnterDirRowFilterSelectsExactlyTheFilesItCounts: a dir row's filter
// must select every file the row aggregates and no other file. That covers
// the old filepath.Dir grouping ("./src/main.go" counted under "src", whose
// filter did not select it; likewise "//usr/lib/x", "a/../b/c") and the old
// subtree prefix ^dir/ (task ip2): the "/tmp" row counted only /tmp's direct
// files but also selected "/tmp/sub/c", and the "/" row selected every
// absolute path. It also covers case: the "/tmp/A" row must not select
// "/tmp/a/x", and "a/" (from "a//b") must not select "a/x".
func TestEnterDirRowFilterSelectsExactlyTheFilesItCounts(t *testing.T) {
	paths := []string{
		"./src/main.go", "./src/util.go", "//usr/lib/x", "a/../b/c",
		"/tmp/a ", "/tmp/b", "/tmp/sub/c", "/etc", "/etc/passwd", "/", "//x",
		"rel/x", "a//b", "a/x", "   /z", "/tmp/A/x", "/tmp/a/x",
	}
	files := make([]statsengine.FileSnapshot, len(paths))
	for i, p := range paths {
		files[i] = statsengine.FileSnapshot{Path: p, Accesses: 1}
	}
	m := filesModel(true, files...)
	dirs := m.sortedDirRows()
	sawRoot := false
	for i, dir := range dirs {
		m.filesDirTab.offset = i
		req, ok := enterFilterRequest(t, m)
		if !ok {
			t.Fatalf("dir row %q: expected a filter request", dir.Dir)
		}
		sawRoot = sawRoot || dir.Dir == "/"
		counted := 0
		for _, p := range paths {
			selected := req.Filter.Matches(&streamrow.Row{FileName: p})
			counts := literalDir(p) == dir.Dir
			if counts {
				counted++
			}
			if selected != counts {
				t.Errorf("dir row %q filter %s: selects %q = %v, row counts it = %v", dir.Dir, req.Action, p, selected, counts)
			}
		}
		if uint64(counted) != dir.FileCount {
			t.Fatalf("dir row %q counts %d files, test found %d", dir.Dir, dir.FileCount, counted)
		}
	}
	if !sawRoot {
		t.Fatalf("expected a %q row among %+v", "/", dirs)
	}
	// Siblings sharing a name prefix stay apart: ./src must not select ./srcx.
	m = filesModel(true, statsengine.FileSnapshot{Path: "./src/a", Accesses: 1})
	req, ok := enterFilterRequest(t, m)
	if !ok || req.Filter.Matches(&streamrow.Row{FileName: "./srcx/a"}) || req.Filter.Matches(&streamrow.Row{FileName: "src/a"}) {
		t.Fatalf("expected ^./src/* to select only ./src/..., got %+v (ok=%v)", req.Filter.File, ok)
	}
}

// TestLiteralDir pins the grouping key: the literal text before the last
// separator, "/" for a top-level entry, noDirGroup without a separator.
func TestLiteralDir(t *testing.T) {
	for path, want := range map[string]string{
		"/tmp/a": "/tmp", "/a": "/", "/": "/", "//x": "/", "//usr/lib/x": "//usr/lib",
		"./src/main.go": "./src", "./a": ".", "a/../b/c": "a/../b", "a//b": "a/",
		"   /z": "   ", "a.log": noDirGroup, "socket:[1]": noDirGroup, "": noDirGroup,
	} {
		if got := literalDir(path); got != want {
			t.Errorf("literalDir(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestEnterOnNoDirGroupShowsNotice: Enter on the "." row cannot filter, so
// it must say so in the filter notice (not stay silent) and emit no request.
func TestEnterOnNoDirGroupShowsNotice(t *testing.T) {
	m := filesModel(true, statsengine.FileSnapshot{Path: "socket:[123]", Accesses: 1})
	_, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if cmd != nil {
		if msg, ok := cmd().(messages.GlobalFilterRequestedMsg); ok {
			t.Fatalf("expected no filter request, got %+v", msg)
		}
	}
	if m.filterNotice != noDirGroupNotice {
		t.Fatalf("expected the no-dir-group notice, got %q", m.filterNotice)
	}
	if !strings.Contains(m.filterSummary(), noDirGroupNotice) {
		t.Fatalf("notice not rendered in the status line: %q", m.filterSummary())
	}

	// A real dir row does not set the notice.
	m = filesModel(true, statsengine.FileSnapshot{Path: "/tmp/a", Accesses: 1})
	if _, ok := enterFilterRequest(t, m); !ok || m.filterNotice != "" {
		t.Fatalf("expected a request and no notice for /tmp, got ok=%v notice=%q", ok, m.filterNotice)
	}
}

// TestDirRowLabelsStayDistinct: the treemap and bubble labels of literal dir
// rows must not collapse the way a Cleaned label does ("./src" and "src"
// were both "root/src"), nor through a "root" prefix ("/etc" vs a relative
// "root/etc", "/" vs a relative "root"), or two tiles read the same.
func TestDirRowLabelsStayDistinct(t *testing.T) {
	want := map[string]string{
		"/": "/", "/var/log": "/var/log", "//usr": "//usr", "/etc": "/etc",
		"./src": "./src", "src": "src", ".": ".", "root": "root", "root/etc": "root/etc",
	}
	seen := map[string]string{}
	for dir, label := range want {
		got := dirRowLabel(dir)
		if got != label {
			t.Errorf("dirRowLabel(%q) = %q, want %q", dir, got, label)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("dirs %q and %q share the label %q", dir, other, got)
		}
		seen[got] = dir
	}

	files := []statsengine.FileSnapshot{{Path: "./src/a", Accesses: 2}, {Path: "src/b", Accesses: 1}}
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, files, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	items := buildFilesTreemapItems(&snap, bubbleMetricCount)
	bubbles := filesDirBubbleData(&snap)
	if len(items) != 2 || items[0].Name == items[1].Name || len(bubbles) != 2 || bubbles[0].Label == bubbles[1].Label {
		t.Fatalf("expected two distinctly labelled dirs, got treemap %#v bubbles %#v", items, bubbles)
	}
}

// TestEnterCommWithEdgeAnchorFallsBackToPID: a comm like "x$" as a substring
// pattern would mean "ends with x", so the Comm cell falls back to the exact
// PID filter for such comms instead.
func TestEnterCommWithEdgeAnchorFallsBackToPID(t *testing.T) {
	for _, comm := range []string{"x$", "^x", " ^x$ "} {
		req, ok := enterFilterRequest(t, processesModel(processCommColumn, statsengine.ProcessSnapshot{PID: 5, Comm: comm}))
		if !ok || req.Filter.Comm != nil || req.Action != "pid=5" {
			t.Fatalf("comm %q: expected pid=5 fallback, got action %q comm %+v (ok=%v)", comm, req.Action, req.Filter.Comm, ok)
		}
	}
	// A ^ or $ inside the comm is harmless and keeps the comm filter.
	req, ok := enterFilterRequest(t, processesModel(processCommColumn, statsengine.ProcessSnapshot{PID: 5, Comm: "a$b^c"}))
	if !ok || req.Action != "comm~a$b^c" {
		t.Fatalf("expected comm~a$b^c, got %q (ok=%v)", req.Action, ok)
	}
}

// TestEnterOnBlankDirRowFilters: an all-blank literal dir ("   " from
// "   /z") is a real directory and gets an exact directory-children filter,
// not a silent no-op.
func TestEnterOnBlankDirRowFilters(t *testing.T) {
	m := filesModel(true, statsengine.FileSnapshot{Path: "   /z", Accesses: 1})
	req, ok := enterFilterRequest(t, m)
	if !ok || req.Filter.File == nil || req.Filter.File.Pattern != "^   /*" {
		t.Fatalf("expected ^   /* filter, got %+v (ok=%v)", req.Filter.File, ok)
	}
	if !req.Filter.Matches(&streamrow.Row{FileName: "   /z"}) || req.Filter.Matches(&streamrow.Row{FileName: "/z"}) {
		t.Fatalf("blank dir filter %q selects the wrong files", req.Filter.File.Pattern)
	}
}
