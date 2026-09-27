package dashboard

import (
	"testing"

	"ior/internal/globalfilter/presenter"
	"ior/internal/statsengine"
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
// characters and padding.
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
		{"syscall", syscallsModel(statsengine.SyscallSnapshot{Name: "openat", Count: 1}), presenter.DimSyscall, "syscall~openat"},
		{"family", familySyscalls, presenter.DimFamily, wantFamily},
		{"file path", filesModel(false, statsengine.FileSnapshot{Path: "/tmp/a b~c=d"}), presenter.DimFile, "file~/tmp/a b~c=d"},
		{"file dir", filesModel(true, statsengine.FileSnapshot{Path: "/var/log/x"}), presenter.DimFile, "file~/var/log"},
		{"pid", processesModel(0, statsengine.ProcessSnapshot{PID: 4242, Comm: "sh"}), presenter.DimPID, "pid=4242"},
		{"comm", processesModel(1, statsengine.ProcessSnapshot{PID: 7, Comm: "kworker/0:1"}), presenter.DimComm, "comm~kworker/0:1"},
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
