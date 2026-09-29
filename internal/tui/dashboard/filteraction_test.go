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
// characters and padding. Row values become exact (^value$) patterns and a
// directory row a subtree prefix (^dir/), so the label shows the anchors.
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
		{"file dir", filesModel(true, statsengine.FileSnapshot{Path: "/var/log/x"}), presenter.DimFile, "file~^/var/log/"},
		{"pid", processesModel(0, statsengine.ProcessSnapshot{PID: 4242, Comm: "sh"}), presenter.DimPID, "pid=4242"},
		{"comm", processesModel(1, statsengine.ProcessSnapshot{PID: 7, Comm: "kworker/0:1"}), presenter.DimComm, "comm~^kworker/0:1$"},
		// Padding is part of the value: the anchors keep it significant
		// instead of the matcher trimming "  sh  " into the substring "sh".
		{"padded comm", processesModel(1, statsengine.ProcessSnapshot{PID: 7, Comm: "  sh  "}), presenter.DimComm, "comm~^  sh  $"},
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
		// filepath.Dir of a separator-less name is "."; no prefix selects
		// exactly those names, so the dir row yields no filter.
		{"dot dir", filesModel(true, statsengine.FileSnapshot{Path: "socket:[123]"})},
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
// case runs the emitted filter against real stream rows: the row itself (and
// only case-variants of it) must match, every near-miss must not.
func TestEnterRowFilterSelectsExactlyTheRow(t *testing.T) {
	file := func(name string) *streamrow.Row { return &streamrow.Row{FileName: name} }
	for _, tt := range []struct {
		name  string
		m     *Model
		match []*streamrow.Row
		miss  []*streamrow.Row
	}{
		{"trailing blank path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a "}),
			[]*streamrow.Row{file("/tmp/a "), file("/TMP/A ")},
			[]*streamrow.Row{file("/tmp/a"), file("/tmp/ab"), file("/tmp/a b"), file("x/tmp/a ")}},
		{"leading blank path", filesModel(false, statsengine.FileSnapshot{Path: " /tmp/a"}),
			[]*streamrow.Row{file(" /tmp/a")},
			[]*streamrow.Row{file("/tmp/a"), file(" /tmp/ab")}},
		{"plain path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a"}),
			[]*streamrow.Row{file("/tmp/a")},
			[]*streamrow.Row{file("/tmp/abc"), file("/var/tmp/a")}},
		// Literal edge anchors stay literal: bare, "x$" meant "ends with x"
		// and "^x" meant "starts with x".
		{"literal dollar", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/x$"}),
			[]*streamrow.Row{file("/tmp/x$")},
			[]*streamrow.Row{file("/tmp/x"), file("/tmp/x$y")}},
		{"literal caret", filesModel(false, statsengine.FileSnapshot{Path: "^x"}),
			[]*streamrow.Row{file("^x")},
			[]*streamrow.Row{file("x"), file("a^x")}},
		{"dir subtree", filesModel(true, statsengine.FileSnapshot{Path: "/tmp/a"}),
			[]*streamrow.Row{file("/tmp/a"), file("/tmp/b"), file("/tmp/sub/c")},
			[]*streamrow.Row{file("/tmp"), file("/tmpfoo/a"), file("/var/tmp/a")}},
		{"root dir", filesModel(true, statsengine.FileSnapshot{Path: "/a"}),
			[]*streamrow.Row{file("/a"), file("/etc/passwd")},
			[]*streamrow.Row{file("relative"), file("socket:[1]")}},
		{"syscall", syscallsModel(statsengine.SyscallSnapshot{Name: "read", Count: 1}),
			[]*streamrow.Row{{Syscall: "read"}},
			[]*streamrow.Row{{Syscall: "readv"}, {Syscall: "pread64"}}},
		{"comm", processesModel(processCommColumn, statsengine.ProcessSnapshot{PID: 7, Comm: "bash"}),
			[]*streamrow.Row{{Comm: "bash"}},
			[]*streamrow.Row{{Comm: "bashbug"}, {Comm: "rbash"}}},
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
