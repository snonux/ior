package dashboard

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/eventstream"
	"ior/internal/tui/messages"

	tea "charm.land/bubbletea/v2"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type fakeSnapshotSource struct {
	snapshots int
	snap      *statsengine.Snapshot
}

func (f *fakeSnapshotSource) Snapshot() *statsengine.Snapshot {
	f.snapshots++
	return f.snap
}

type fakeResettableSnapshotSource struct {
	resetCount int
	snapCount  int
	snap       *statsengine.Snapshot
}

func (f *fakeResettableSnapshotSource) Reset() {
	f.resetCount++
}

func (f *fakeResettableSnapshotSource) Snapshot() *statsengine.Snapshot {
	f.snapCount++
	return f.snap
}

func stripANSIEscape(value string) string {
	return ansiEscapePattern.ReplaceAllString(value, "")
}

func firstLineContaining(value, needle string) string {
	for _, line := range strings.Split(value, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func TestKeySwitchingChangesActiveTab(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	model := next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected overview tab on key 2, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	model = next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected next tab to be syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	model = next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected previous tab to be overview, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	model = next.(Model)
	if model.activeTab != TabStream {
		t.Fatalf("expected stream tab on key 7, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'1'}[0], Text: string([]rune{'1'})})
	model = next.(Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab on key 1, got %v", model.activeTab)
	}
}

func TestArrowAndViKeysDoNotCycleTabs(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabOverview

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected right arrow not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'l'}[0], Text: string([]rune{'l'})})
	model = next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected l not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected left arrow not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'h'}[0], Text: string([]rune{'h'})})
	model = next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected h not to change tabs, got %v", model.activeTab)
	}
}

func TestSyscallsTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}, {Name: "write", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.syscallsOffset != 1 {
		t.Fatalf("expected offset 1 after j, got %d", model.syscallsOffset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(Model)
	if model.syscallsOffset != 0 {
		t.Fatalf("expected offset 0 after k, got %d", model.syscallsOffset)
	}
}

func TestProcessesTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{{PID: 1}, {PID: 2}}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.processesOffset != 1 {
		t.Fatalf("expected processes offset 1 after j, got %d", model.processesOffset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(Model)
	if model.processesOffset != 0 {
		t.Fatalf("expected processes offset 0 after k, got %d", model.processesOffset)
	}
}

func TestSyscallsTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(Model)
	if model.syscallsCol != 1 {
		t.Fatalf("expected syscalls selected column 1 after right, got %d", model.syscallsCol)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(Model)
	if model.syscallsCol != 0 {
		t.Fatalf("expected syscalls selected column 0 after left, got %d", model.syscallsCol)
	}
}

func TestFilesTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{{Path: "/a"}}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(Model)
	if model.filesCol != 1 {
		t.Fatalf("expected files selected column 1 after right, got %d", model.filesCol)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(Model)
	if model.filesCol != 0 {
		t.Fatalf("expected files selected column 0 after left, got %d", model.filesCol)
	}
}

func TestProcessesTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{{PID: 1, Comm: "alpha"}}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(Model)
	if model.processesCol != 1 {
		t.Fatalf("expected processes selected column 1 after right, got %d", model.processesCol)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(Model)
	if model.processesCol != 0 {
		t.Fatalf("expected processes selected column 0 after left, got %d", model.processesCol)
	}
}

func TestProcessesTabEnterEmitsGlobalFilterRequest(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 111, Comm: "alpha", Syscalls: 9},
		{PID: 222, Comm: "beta", Syscalls: 4},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesOffset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on processes tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.PID == nil || req.Filter.PID.Value != 222 {
		t.Fatalf("expected pid=222 filter, got %+v", req.Filter.PID)
	}
	if req.Action != "pid=222" {
		t.Fatalf("expected action pid=222, got %q", req.Action)
	}
}

func TestProcessesTabEnterCommColumnEmitsCommFilterRequest(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 111, Comm: "alpha", Syscalls: 9},
		{PID: 222, Comm: "beta", Syscalls: 4},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesOffset = 1
	m.processesCol = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on processes comm column to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Comm == nil || req.Filter.Comm.Pattern != "beta" {
		t.Fatalf("expected comm beta filter, got %+v", req.Filter.Comm)
	}
	if req.Action != "comm~beta" {
		t.Fatalf("expected action comm~beta, got %q", req.Action)
	}
}

func TestProcessesSortKeyTogglesOnSelectedColumn(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
		{PID: 100, Comm: "agent", Syscalls: 3},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesCol = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if !model.processesSort.active || model.processesSort.key != processSortKeyComm {
		t.Fatalf("expected process comm sort enabled, got %+v", model.processesSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(Model)
	if model.processesSort.active {
		t.Fatalf("expected second s press to restore default process ordering")
	}
}

func TestProcessesReverseSortKeyTogglesOnSelectedColumn(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
		{PID: 100, Comm: "agent", Syscalls: 3},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesCol = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(Model)
	if !model.processesSort.active || model.processesSort.key != processSortKeyComm || !model.processesSort.reverse {
		t.Fatalf("expected reverse process comm sort enabled, got %+v", model.processesSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(Model)
	if model.processesSort.active {
		t.Fatalf("expected second S press to restore default process ordering")
	}
}

func TestProcessesSortEnterUsesSortedVisibleRow(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
		{PID: 100, Comm: "agent", Syscalls: 3},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.processesOffset = 1
	m.processesCol = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted processes tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Comm == nil || req.Filter.Comm.Pattern != "agent" {
		t.Fatalf("expected visible sorted row to filter agent comm, got %+v", req.Filter.Comm)
	}
}

func TestProcessesSortIgnoredOutsideTableMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	m.processesVizMode = tabVizModeTreemap
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if model.processesSort.active {
		t.Fatalf("expected sort key ignored outside processes table mode")
	}
}

func TestStatsTickReanchorsSortedProcessSelectionByPID(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	m.processesSort = tableSortState[processSortKey]{active: true, key: processSortKeyComm}
	oldSnap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 100, Comm: "agent", Syscalls: 3},
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &oldSnap
	m.processesOffset = 1
	m.processesCol = 1

	newSnap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 50, Comm: "alpha", Syscalls: 12},
		{PID: 100, Comm: "agent", Syscalls: 3},
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &newSnap})
	model := next.(Model)
	if model.processesOffset != 2 {
		t.Fatalf("expected selected worker row reanchored to offset 2, got %d", model.processesOffset)
	}
	if selected := model.selectedProcessPID(); selected != 200 {
		t.Fatalf("expected selected process PID 200 after stats refresh, got %d", selected)
	}
}

func TestFilesTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{{Path: "/a"}, {Path: "/b"}}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.filesOffset != 1 {
		t.Fatalf("expected files offset 1 after j, got %d", model.filesOffset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(Model)
	if model.filesOffset != 0 {
		t.Fatalf("expected files offset 0 after k, got %d", model.filesOffset)
	}
}

func TestSyscallsTabEnterEmitsGlobalFilterRequest(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9},
		{Name: "write", Count: 4},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.syscallsOffset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on syscalls tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Syscall == nil || req.Filter.Syscall.Pattern != "write" {
		t.Fatalf("expected syscall write filter, got %+v", req.Filter.Syscall)
	}
	if req.Action != "syscall~write" {
		t.Fatalf("expected action syscall~write, got %q", req.Action)
	}
}

func TestSyscallsSortKeyTogglesOnSelectedColumn(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
		{Name: "read", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if !model.syscallsSort.active || model.syscallsSort.key != syscallSortKeyName {
		t.Fatalf("expected syscall name sort enabled, got %+v", model.syscallsSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(Model)
	if model.syscallsSort.active {
		t.Fatalf("expected second s press to restore default ordering")
	}
}

func TestSyscallsReverseSortKeyTogglesOnSelectedColumn(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
		{Name: "read", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(Model)
	if !model.syscallsSort.active || model.syscallsSort.key != syscallSortKeyName || !model.syscallsSort.reverse {
		t.Fatalf("expected reverse syscall name sort enabled, got %+v", model.syscallsSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(Model)
	if model.syscallsSort.active {
		t.Fatalf("expected second S press to restore default ordering")
	}
}

func TestSyscallsSortReanchorsSelectedSyscall(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
		{Name: "read", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.syscallsOffset = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if model.syscallsOffset != 0 {
		t.Fatalf("expected selected read row reanchored to offset 0, got %d", model.syscallsOffset)
	}
	if selected := model.selectedSyscallName(); selected != "read" {
		t.Fatalf("expected selected syscall read after reanchor, got %q", selected)
	}
}

func TestSyscallsSortEnterUsesSortedVisibleRow(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
		{Name: "read", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.syscallsOffset = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted syscalls tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Syscall == nil || req.Filter.Syscall.Pattern != "read" {
		t.Fatalf("expected visible sorted row to filter read, got %+v", req.Filter.Syscall)
	}
}

func TestSyscallsSortIgnoredOutsideTableMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsVizMode = tabVizModeTreemap
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if model.syscallsSort.active {
		t.Fatalf("expected sort key ignored outside syscall table mode")
	}
}

func TestSyscallsP95SortSurvivesWidthExpansion(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.width = 120
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9, LatencyMinNs: 100, LatencyP95Ns: 10},
		{Name: "read", Count: 3, LatencyMinNs: 1, LatencyP95Ns: 50},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.syscallsCol = 4

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if first := model.sortedSyscallRows()[0].Name; first != "read" {
		t.Fatalf("expected compact p95 sort to put read first, got %q", first)
	}

	next, _ = model.Update(tea.WindowSizeMsg{Width: 160, Height: 30})
	model = next.(Model)
	if first := model.sortedSyscallRows()[0].Name; first != "read" {
		t.Fatalf("expected p95 sort to survive width expansion, got %q", first)
	}
}

func TestStatsTickReanchorsSortedSyscallSelectionByName(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsSort = tableSortState[syscallSortKey]{active: true, key: syscallSortKeyName}
	oldSnap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9},
		{Name: "write", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &oldSnap
	m.syscallsOffset = 1

	newSnap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "close", Count: 50},
		{Name: "read", Count: 9},
		{Name: "write", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &newSnap})
	model := next.(Model)
	if model.syscallsOffset != 2 {
		t.Fatalf("expected selected write row reanchored to offset 2, got %d", model.syscallsOffset)
	}
	if selected := model.selectedSyscallName(); selected != "write" {
		t.Fatalf("expected selected syscall write after stats refresh, got %q", selected)
	}
}

func TestFilesTabGroupedScrollUsesDirectoryOffset(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.filesDirGrouped = true
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/a/f1"},
		{Path: "/a/f2"},
		{Path: "/b/f3"},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.filesDirOffset != 1 {
		t.Fatalf("expected grouped dir offset 1 after j, got %d", model.filesDirOffset)
	}
	if model.filesOffset != 0 {
		t.Fatalf("expected flat files offset unchanged, got %d", model.filesOffset)
	}
}

func TestFilesTabEnterEmitsGlobalFilterRequest(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/a"},
		{Path: "/tmp/b"},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesOffset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "/tmp/b" {
		t.Fatalf("expected file /tmp/b filter, got %+v", req.Filter.File)
	}
	if req.Action != "file~/tmp/b" {
		t.Fatalf("expected action file~/tmp/b, got %q", req.Action)
	}
}

func TestFilesSortKeyTogglesFlatMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesCol = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(Model)
	if !model.filesSort.active || model.filesSort.key != fileSortKeyPath {
		t.Fatalf("expected flat file path sort enabled, got %+v", model.filesSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(Model)
	if model.filesSort.active {
		t.Fatalf("expected second s press to restore default file ordering")
	}
}

func TestFilesReverseSortKeyTogglesFlatMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesCol = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(Model)
	if !model.filesSort.active || model.filesSort.key != fileSortKeyPath || !model.filesSort.reverse {
		t.Fatalf("expected reverse flat file path sort enabled, got %+v", model.filesSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(Model)
	if model.filesSort.active {
		t.Fatalf("expected second S press to restore default file ordering")
	}
}

func TestFilesDirReverseSortKeyTogglesGroupedMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.filesDirGrouped = true
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/var/log/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesDirCol = 6

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(Model)
	if !model.filesDirSort.active || model.filesDirSort.key != fileDirSortKeyDir || !model.filesDirSort.reverse {
		t.Fatalf("expected reverse grouped file dir sort enabled, got %+v", model.filesDirSort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(Model)
	if model.filesDirSort.active {
		t.Fatalf("expected second S press to restore default grouped file ordering")
	}
}

func TestFilesSortEnterUsesSortedVisibleRow(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesOffset = 1
	m.filesCol = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "/tmp/a.log" {
		t.Fatalf("expected visible sorted row to filter /tmp/a.log, got %+v", req.Filter.File)
	}
}

func TestFilesDirSortEnterUsesSortedVisibleRow(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.filesDirGrouped = true
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/var/log/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesDirOffset = 1
	m.filesDirCol = 6

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted grouped files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "/tmp" {
		t.Fatalf("expected visible sorted grouped row to filter /tmp, got %+v", req.Filter.File)
	}
}

func TestFilesSortStatesPersistAcrossDirToggle(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/var/log/z.log", Accesses: 9},
		{Path: "/tmp/a.log", Accesses: 3},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap
	m.filesCol = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	m = next.(Model)
	m.filesDirCol = 6
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(Model)

	if !m.filesSort.active || m.filesSort.key != fileSortKeyPath {
		t.Fatalf("expected flat file sort state preserved, got %+v", m.filesSort)
	}
	if !m.filesDirSort.active || m.filesDirSort.key != fileDirSortKeyDir {
		t.Fatalf("expected dir sort state enabled, got %+v", m.filesDirSort)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	m = next.(Model)
	if !m.filesSort.active || m.filesSort.key != fileSortKeyPath {
		t.Fatalf("expected flat file sort state after returning from dir mode, got %+v", m.filesSort)
	}
}

func TestStreamSpaceUnpauseSchedulesStreamTick(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	m := NewModelWithConfig(nil, rb, 250, common.DefaultKeyMap())
	m.activeTab = TabStream
	m.streamModel.HandleKey("space") // pause

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	_ = next
	if cmd == nil {
		t.Fatalf("expected stream tick command when unpausing stream")
	}
}

func TestFlameTickRefreshesFlamegraphModel(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	liveTrie.Reset()

	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.SetLiveTrie(liveTrie)
	m.activeTab = TabFlame

	next, cmd := m.Update(flameTickMsg{})
	model := next.(Model)
	if cmd == nil {
		t.Fatalf("expected flame tick to schedule next tick command")
	}
	if got, want := model.flamegraphModel.LastVersion(), liveTrie.Version(); got != want {
		t.Fatalf("expected flame model version %d, got %d", want, got)
	}
}

func TestSetLiveTriePreloadsInitialSnapshotWithoutVersionChange(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")

	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.SetLiveTrie(liveTrie)
	m.activeTab = TabFlame
	if !m.flamegraphModel.HasSnapshot() {
		t.Fatalf("expected SetLiveTrie to preload a baseline snapshot")
	}

	next, _ := m.Update(flameTickMsg{})
	model := next.(Model)
	if !model.flamegraphModel.HasSnapshot() {
		t.Fatalf("expected flame tick to retain initial snapshot even when trie version is unchanged")
	}
}

func TestFlameTickPausedFreezesAfterInitialSnapshot(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.SetLiveTrie(liveTrie)
	m.activeTab = TabFlame

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	model := next.(Model)

	next, _ = model.Update(flameTickMsg{})
	model = next.(Model)
	initialVersion := model.flamegraphModel.LastVersion()

	liveTrie.Reset()
	if liveTrie.Version() == initialVersion {
		t.Fatalf("expected reset to advance trie version")
	}

	next, _ = model.Update(flameTickMsg{})
	model = next.(Model)
	if got, want := model.flamegraphModel.LastVersion(), initialVersion; got != want {
		t.Fatalf("expected paused flame tick to freeze version at %d, got %d", want, got)
	}
}

func TestPausedFlameDashboardViewPreservesZoomedSelectedLine(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestFlameData(liveTrie)

	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFlame

	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	m.SetLiveTrie(liveTrie)

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(Model)

	if !m.flamegraphModel.Paused() {
		t.Fatalf("expected flamegraph model to be paused")
	}

	flameView := stripANSIEscape(m.flamegraphModel.View().Content)
	selectedLine := firstLineContaining(flameView, "Selected:")
	if selectedLine == "" {
		t.Fatalf("expected flame view to include a selected line, got %q", flameView)
	}
	if !strings.Contains(selectedLine, "width=") {
		t.Fatalf("expected selected line to include width details, got %q", selectedLine)
	}

	dashboardView := stripANSIEscape(m.View().Content)
	if !strings.Contains(dashboardView, selectedLine) {
		t.Fatalf("expected dashboard view to preserve paused zoom selected line %q, got %q", selectedLine, dashboardView)
	}

	dashboardViewAgain := stripANSIEscape(m.View().Content)
	if !strings.Contains(dashboardViewAgain, selectedLine) {
		t.Fatalf("expected repeated dashboard view to preserve paused zoom selected line %q, got %q", selectedLine, dashboardViewAgain)
	}
}

func TestStreamPausedSupportsJKArrowsAndPageKeys(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	for i := 0; i < 300; i++ {
		rb.Push(eventstream.StreamEvent{
			Seq:      uint64(i + 1),
			Syscall:  "read",
			Comm:     "proc",
			PID:      1000,
			TID:      uint32(2000 + i),
			FileName: fmt.Sprintf("/tmp/file-%03d", i),
		})
	}

	m := NewModelWithConfig(nil, rb, 250, common.DefaultKeyMap())
	m.activeTab = TabStream
	m.showHelp = true
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)

	m.streamModel.Refresh()
	_ = m.View()

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace}) // pause
	m = next.(Model)
	before := rowFromStreamView(t, m.View().Content)

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	m = next.(Model)
	afterK := rowFromStreamView(t, m.View().Content)
	if afterK >= before {
		t.Fatalf("expected k to scroll up while paused: before=%d afterK=%d", before, afterK)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = next.(Model)
	afterDown := rowFromStreamView(t, m.View().Content)
	if afterDown <= afterK {
		t.Fatalf("expected down arrow to scroll down while paused: afterK=%d afterDown=%d", afterK, afterDown)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyPgUp})
	m = next.(Model)
	afterPgUp := rowFromStreamView(t, m.View().Content)
	if afterPgUp >= afterDown {
		t.Fatalf("expected pgup to scroll up while paused: afterDown=%d afterPgUp=%d", afterDown, afterPgUp)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	m = next.(Model)
	afterPgDown := rowFromStreamView(t, m.View().Content)
	if afterPgDown <= afterPgUp {
		t.Fatalf("expected pgdown to scroll down while paused: afterPgUp=%d afterPgDown=%d", afterPgUp, afterPgDown)
	}
}

func rowFromStreamView(t *testing.T, view string) int {
	t.Helper()
	re := regexp.MustCompile(`Row ([0-9]+)/([0-9]+)`)
	m := re.FindStringSubmatch(view)
	if len(m) != 3 {
		t.Fatalf("stream row status not found in view")
	}
	row, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("invalid row value %q: %v", m[1], err)
	}
	return row
}

func TestDirGroupKeyTogglesOnlyOnFilesTab(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	model := next.(Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected filesDirGrouped to toggle on files tab")
	}

	model.activeTab = TabOverview
	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	model = next.(Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected filesDirGrouped unchanged outside files tab")
	}
}

func TestVisualizationCycleForSyscallsTab(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
		{Name: "write", Count: 3, Bytes: 1024},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model := next.(Model)
	if got := model.syscallsVizMode; got != tabVizModeBubbles {
		t.Fatalf("expected syscalls bubbles mode enabled")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.syscallsVizMode; got != tabVizModeTreemap {
		t.Fatalf("expected syscalls treemap mode enabled")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.syscallsVizMode; got != tabVizModeTable {
		t.Fatalf("expected syscalls mode cycled back to table")
	}
}

func TestBubbleMetricToggleForSyscallsTab(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'b'}[0], Text: string([]rune{'b'})})
	model := next.(Model)
	if got := model.syscallsChart.Metric(); got != bubbleMetricBytes {
		t.Fatalf("expected syscalls bubble metric bytes, got %q", got)
	}
}

func TestMetricToggleAppliesInFilesTreemapMode(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/var/log/a", Accesses: 5, BytesRead: 120, BytesWritten: 40},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap
	m.filesDirGrouped = true
	m.filesVizMode = tabVizModeTreemap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'b'}[0], Text: string([]rune{'b'})})
	model := next.(Model)
	if got := model.filesChart.Metric(); got != bubbleMetricBytes {
		t.Fatalf("expected files metric toggle to bytes in treemap mode, got %q", got)
	}
}

func TestFilesVisualizationRequiresDirectoryMode(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/a", Accesses: 3},
		{Path: "/tmp/b", Accesses: 1},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model := next.(Model)
	if got := model.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files treemap mode to stay disabled without directory mode")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	model = next.(Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected files dir mode enabled")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.filesVizMode; got != tabVizModeBubbles {
		t.Fatalf("expected files bubbles mode enabled in directory mode")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.filesVizMode; got != tabVizModeTreemap {
		t.Fatalf("expected files treemap mode enabled in directory mode")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.filesVizMode; got != tabVizModeIcicle {
		t.Fatalf("expected files icicle mode enabled in directory mode")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(Model)
	if got := model.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files mode cycled back to table")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	model = next.(Model)
	if got := model.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files mode reset to table when leaving directory mode")
	}
}

func TestBubbleModeUsesJKForSelection(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
		{Name: "write", Count: 3, Bytes: 1024},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.latest = &snap
	m.syscallsVizMode = tabVizModeBubbles
	m.refreshBubbleData()
	if len(m.syscallsChart.nodes) < 2 {
		t.Fatalf("expected at least two syscall bubbles")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.syscallsChart.selected != 1 {
		t.Fatalf("expected bubble selection to move to index 1, got %d", model.syscallsChart.selected)
	}
}

func TestTreemapModeUsesJKForSelection(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
		{Name: "write", Count: 3, Bytes: 1024},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.latest = &snap
	m.syscallsVizMode = tabVizModeTreemap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(Model)
	if model.syscallsTreemapSelection != 1 {
		t.Fatalf("expected treemap selection to move to index 1, got %d", model.syscallsTreemapSelection)
	}
}

func TestFilesIcicleModeSelectionUsesIcicleTileCount(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/a/b/c/file1", Accesses: 9},
		{Path: "/a/d/e/file2", Accesses: 7},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap
	m.filesDirGrouped = true
	m.filesVizMode = tabVizModeIcicle
	m.width = 120
	m.height = 28

	expectedMax := m.maxFilesDirRowsForMode()
	if expectedMax <= m.maxFilesDirRows() {
		t.Fatalf("expected icicle tile count to exceed grouped dir count: tiles=%d dirs=%d", expectedMax, m.maxFilesDirRows())
	}

	for i := 0; i < expectedMax+4; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
		m = next.(Model)
	}
	if m.filesDirOffset != expectedMax-1 {
		t.Fatalf("expected icicle selection clamped by tile count to %d, got %d", expectedMax-1, m.filesDirOffset)
	}
}

func TestTreemapModeRendersTreemapHeader(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
		{Name: "write", Count: 3, Bytes: 1024},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.latest = &snap
	m.syscallsVizMode = tabVizModeTreemap
	m.width = 120
	m.height = 28

	out := m.View().Content
	if !strings.Contains(out, "Syscalls treemap") {
		t.Fatalf("expected treemap header in syscalls view")
	}
}

func TestTreemapModeRendersFilesHeader(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/srv/log/a", Accesses: 9, BytesRead: 400, BytesWritten: 200},
		{Path: "/srv/log/b", Accesses: 4, BytesRead: 100, BytesWritten: 40},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap
	m.filesDirGrouped = true
	m.filesVizMode = tabVizModeTreemap
	m.width = 120
	m.height = 28

	out := m.View().Content
	if !strings.Contains(out, "Files treemap") {
		t.Fatalf("expected treemap header in files view")
	}
}

func TestIcicleModeRendersFilesHeader(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/srv/log/a", Accesses: 9, BytesRead: 400, BytesWritten: 200},
		{Path: "/srv/log/b", Accesses: 4, BytesRead: 100, BytesWritten: 40},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap
	m.filesDirGrouped = true
	m.filesVizMode = tabVizModeIcicle
	m.width = 120
	m.height = 28

	out := m.View().Content
	if !strings.Contains(out, "Files icicle") {
		t.Fatalf("expected icicle header in files view")
	}
}

func TestTreemapModeRendersProcessesHeader(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 10, Comm: "worker", Syscalls: 12, Bytes: 500},
		{PID: 11, Comm: "agent", Syscalls: 4, Bytes: 120},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	m.latest = &snap
	m.processesVizMode = tabVizModeTreemap
	m.width = 120
	m.height = 28

	out := m.View().Content
	if !strings.Contains(out, "Processes treemap") {
		t.Fatalf("expected treemap header in processes view")
	}
}

func TestScrollOffsetDoesNotGrowUnbounded(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}, {Name: "write", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	for i := 0; i < 50; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
		m = next.(Model)
	}
	if m.syscallsOffset != 1 {
		t.Fatalf("expected bounded offset 1, got %d", m.syscallsOffset)
	}
}

func TestRefreshKeyEmitsRefreshTick(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 13}
	engine := &fakeSnapshotSource{snap: snap}
	m := NewModelWithConfig(engine, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabOverview
	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	_ = next
	if cmd == nil {
		t.Fatalf("expected refresh command")
	}
	msg := cmd()
	stats, ok := msg.(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected StatsTickMsg from refresh key command, got %T", msg)
	}
	if stats.Snap != snap {
		t.Fatalf("expected refreshed snapshot from engine")
	}
}

func TestRefreshKeyResetsBaselineWhenSourceSupportsReset(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 5}
	engine := &fakeResettableSnapshotSource{snap: snap}
	m := NewModelWithConfig(engine, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabOverview

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	_ = next
	if cmd == nil {
		t.Fatalf("expected reset baseline command")
	}
	if engine.resetCount != 1 {
		t.Fatalf("expected reset count 1, got %d", engine.resetCount)
	}
	msg := cmd()
	stats, ok := msg.(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected StatsTickMsg from reset baseline, got %T", msg)
	}
	if stats.Snap != snap {
		t.Fatalf("expected snapshot after reset")
	}
}

func TestRefreshKeyResetsLiveTrieOutsideFlameTab(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.SetLiveTrie(liveTrie)
	m.activeTab = TabSyscalls
	before := liveTrie.Version()

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	_ = next
	if cmd == nil {
		t.Fatalf("expected baseline reset command")
	}
	if liveTrie.Version() == before {
		t.Fatalf("expected live trie version to change after baseline reset")
	}
}

func TestFlameTabReceivesSlashKey(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFlame
	m.width = 120
	m.height = 30

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: string([]rune{'/'})})
	model := next.(Model)
	if cmd != nil {
		t.Fatalf("did not expect global command for flame search key")
	}
	if !strings.Contains(model.View().Content, "0/0 matches") {
		t.Fatalf("expected flame search footer after pressing /")
	}
}

func TestFlameTabReceivesResetAndPauseKeys(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFlame
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	model := next.(Model)
	if !strings.Contains(model.View().Content, "[PAUSED]") {
		t.Fatalf("expected flame space key to toggle paused state")
	}

	next, cmd := model.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	model = next.(Model)
	if cmd != nil {
		t.Fatalf("expected flame reset key to be handled by flame tab without global refresh command")
	}
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab to stay active after reset key")
	}
}

func TestFlameSearchConsumesNumericTabKeys(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFlame
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: string([]rune{'/'})})
	model := next.(Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab to stay active after opening search")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	model = next.(Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected numeric key while searching to stay in flame tab")
	}
}

func TestRefreshTickEmitsStatsTickMsg(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 9}
	engine := &fakeSnapshotSource{snap: snap}
	m := NewModelWithConfig(engine, nil, 100, common.DefaultKeyMap())

	next, cmd := m.Update(refreshTickMsg{})
	if cmd == nil {
		t.Fatalf("expected tick command batch")
	}
	if engine.snapshots != 1 {
		t.Fatalf("expected one snapshot call, got %d", engine.snapshots)
	}

	msg := cmd()
	switch v := msg.(type) {
	case tea.BatchMsg:
		var sawStats bool
		for _, c := range v {
			out := c()
			if stats, ok := out.(messages.StatsTickMsg); ok && stats.Snap == snap {
				sawStats = true
			}
		}
		if !sawStats {
			t.Fatalf("expected StatsTickMsg in batch output")
		}
	default:
		t.Fatalf("expected batch message, got %T", msg)
	}

	_ = next
}

func TestStatsTickMsgUpdatesLatestSnapshot(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 11}
	m := NewModel(nil, nil)

	next, _ := m.Update(messages.StatsTickMsg{Snap: snap})
	model := next.(Model)
	if model.latest != snap {
		t.Fatalf("expected latest snapshot to be updated")
	}
}

func TestStatsTickClampsGroupedFilesOffset(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil,
		nil,
		nil,
		nil,
		[]statsengine.FileSnapshot{{Path: "/a/f1"}, {Path: "/a/f2"}},
		nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)
	m := NewModel(nil, nil)
	m.filesDirOffset = 10

	next, _ := m.Update(messages.StatsTickMsg{Snap: &snap})
	model := next.(Model)
	if model.filesDirOffset != 0 {
		t.Fatalf("expected grouped files offset clamped to 0, got %d", model.filesDirOffset)
	}
}

func TestViewRendersTabBarAndHelp(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, common.DefaultKeyMap())
	out := m.View().Content
	if !strings.Contains(out, "Flame") {
		t.Fatalf("expected flame tab label in view")
	}
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected help hint text in view")
	}
	if strings.Contains(out, "tab next tab") {
		t.Fatalf("did not expect expanded help bar by default")
	}
}

func TestFlameTabRendersWaitingForDataPlaceholder(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, common.DefaultKeyMap())
	m.activeTab = TabFlame
	m.width = 120
	m.height = 30

	out := m.View().Content
	if !strings.Contains(out, "Flame: waiting for data...") {
		t.Fatalf("expected flame waiting placeholder, got %q", out)
	}
}

func TestRenderActiveTabUsesDirectoryFilesViewWhenGrouped(t *testing.T) {
	snap := statsengine.NewSnapshot(
		nil, nil, nil, nil,
		[]statsengine.FileSnapshot{{Path: "/tmp/a.log", Accesses: 2}},
		nil,
		statsengine.HistogramSnapshot{},
		statsengine.HistogramSnapshot{},
	)
	out := renderActiveTab(TabFiles, &snap, nil, nil, 120, 30, -1, 0, 0, 0, 0, true, 0, 0, 0, 0)
	if !strings.Contains(out, "Directory") {
		t.Fatalf("expected grouped directory files view header, got %q", out)
	}
}

func TestStreamTabViewKeepsTabAndHelpChromeVisible(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	for i := 0; i < 200; i++ {
		rb.Push(eventstream.StreamEvent{Syscall: "read"})
	}

	m := NewModelWithConfig(nil, rb, 1000, common.DefaultKeyMap())
	m.activeTab = TabStream
	m.width = 120
	m.height = 30
	m.streamModel.SetSource(rb)
	m.streamModel.Refresh()

	out := m.View().Content
	if !strings.Contains(out, "1:Flame") {
		t.Fatalf("expected tab bar to remain visible in stream view")
	}
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected help hint to remain visible in stream view")
	}
}

func TestHelpToggleWithH(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, common.DefaultKeyMap())
	out := m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected default help hint")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(Model)
	out = m.View().Content
	if !strings.Contains(out, "tab next tab") {
		t.Fatalf("expected expanded help after pressing h")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(Model)
	out = m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected help hint after pressing h again")
	}
}

func TestTranslateFlamegraphMouseMsgOffsetsTabBarRow(t *testing.T) {
	translated := translateFlamegraphMsg(tea.MouseClickMsg{
		X:      17,
		Y:      9,
		Button: tea.MouseLeft,
	})
	click, ok := translated.(tea.MouseClickMsg)
	if !ok {
		t.Fatalf("expected translated message to stay mouse click, got %T", translated)
	}
	if click.X != 17 || click.Y != 8 {
		t.Fatalf("expected click coordinates (17,8), got (%d,%d)", click.X, click.Y)
	}
}

func TestTranslateFlamegraphMsgLeavesNonMouseUnchanged(t *testing.T) {
	msg := messages.StatsTickMsg{}
	translated := translateFlamegraphMsg(msg)
	if _, ok := translated.(messages.StatsTickMsg); !ok {
		t.Fatalf("expected non-mouse message to remain unchanged, got %T", translated)
	}
}
