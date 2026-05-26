package dashboard

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

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

func (f *fakeSnapshotSource) Snapshot() (*statsengine.Snapshot, error) {
	f.snapshots++
	return f.snap, nil
}

type fakeResettableSnapshotSource struct {
	resetCount int
	snapCount  int
	snap       *statsengine.Snapshot
}

func (f *fakeResettableSnapshotSource) Reset() {
	f.resetCount++
}

func (f *fakeResettableSnapshotSource) Snapshot() (*statsengine.Snapshot, error) {
	f.snapCount++
	return f.snap, nil
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

func TestStreamViewportUsesSharedChromeCalculator(t *testing.T) {
	wantWidth, wantHeight := common.EffectiveViewport(120, 40)
	wantHeight -= streamChromeRows

	width, height := streamViewport(120, 40)
	if width != wantWidth || height != wantHeight {
		t.Fatalf("streamViewport() = %dx%d, want %dx%d", width, height, wantWidth, wantHeight)
	}
}

func TestFlameViewportClampsHeightWithExpandedHelp(t *testing.T) {
	wantWidth, _ := common.EffectiveViewport(80, 2)

	width, height := flameViewport(80, 2, true)
	if width != wantWidth || height != 1 {
		t.Fatalf("flameViewport() = %dx%d, want %dx%d", width, height, wantWidth, 1)
	}
}

func TestSnapshotOrZeroReturnsZeroSnapshotWhenLatestMissing(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())

	snap := m.snapshotOrZero()
	if snap.SyscallsCount() != 0 || snap.FilesCount() != 0 || snap.ProcessesCount() != 0 {
		t.Fatalf("snapshotOrZero() should return an empty snapshot when latest is nil, got counts %d/%d/%d", snap.SyscallsCount(), snap.FilesCount(), snap.ProcessesCount())
	}
}

func TestKeySwitchingChangesActiveTab(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())

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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, rb, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabStream
	m.streamModel.HandleKey("space") // pause

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeySpace})
	_ = next
	if cmd == nil {
		t.Fatalf("expected stream tick command when unpausing stream")
	}
}

func TestFlameTickRefreshesFlamegraphModel(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	liveTrie.Reset()

	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")

	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count", "count")
	coreflamegraph.SeedTestFlameData(liveTrie)

	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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

// newPausedStreamModel creates a stream tab model with 300 events, sized at
// 120x30, and already paused — ready for scroll key assertions.
func newPausedStreamModel(t *testing.T) Model {
	t.Helper()
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
	m := NewModelWithConfig(nil, rb, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabStream
	m.showHelp = true
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	m.streamModel.Refresh()
	_ = m.View()
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace}) // pause
	return next.(Model)
}

func TestStreamPausedSupportsJKArrowsAndPageKeys(t *testing.T) {
	m := newPausedStreamModel(t)
	before := rowFromStreamView(t, m.View().Content)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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

// pressKey sends a single rune key to model and returns the updated model.
func pressKey(m Model, r rune) Model {
	next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	return next.(Model)
}

func TestFilesVisualizationRequiresDirectoryMode(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{
		{Path: "/tmp/a", Accesses: 3},
		{Path: "/tmp/b", Accesses: 1},
	}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	m.latest = &snap

	// v should not cycle viz mode when directory mode is off.
	m = pressKey(m, 'v')
	if got := m.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files treemap mode to stay disabled without directory mode")
	}

	// Enable directory mode; cycling should now work.
	m = pressKey(m, 'd')
	if !m.filesDirGrouped {
		t.Fatalf("expected files dir mode enabled")
	}

	assertFilesVizCycle(t, m)
}

// assertFilesVizCycle verifies the full table→bubbles→treemap→icicle→table
// cycle when directory mode is on, and that leaving dir mode resets to table.
func assertFilesVizCycle(t *testing.T, m Model) {
	t.Helper()
	m = pressKey(m, 'v')
	if got := m.filesVizMode; got != tabVizModeBubbles {
		t.Fatalf("expected files bubbles mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesVizMode; got != tabVizModeTreemap {
		t.Fatalf("expected files treemap mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesVizMode; got != tabVizModeIcicle {
		t.Fatalf("expected files icicle mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files mode cycled back to table")
	}
	m = pressKey(m, 'd') // leave dir mode
	if got := m.filesVizMode; got != tabVizModeTable {
		t.Fatalf("expected files mode reset to table when leaving directory mode")
	}
}

func TestBubbleModeUsesJKForSelection(t *testing.T) {
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9, Bytes: 512},
		{Name: "write", Count: 3, Bytes: 1024},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
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
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(engine, nil, 100, 200, common.DefaultKeyMap())

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
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())
	m.activeTab = TabFlame
	// Dimensions must flow through Update so that sub-model viewports are
	// kept in sync. Direct field assignment bypasses the sync logic in
	// handleWindowSize, so use a WindowSizeMsg instead.
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)

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
	// Build a minimal model with dir-grouped mode enabled so the registry
	// render function routes to the directory view.
	m := Model{filesDirGrouped: true, pidFilter: -1}
	out := renderActiveTabContent(&m, TabFiles, &snap, nil, nil, 120, 30)
	if !strings.Contains(out, "Directory") {
		t.Fatalf("expected grouped directory files view header, got %q", out)
	}
}

func TestStreamTabViewKeepsTabAndHelpChromeVisible(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	for i := 0; i < 200; i++ {
		rb.Push(eventstream.StreamEvent{Syscall: "read"})
	}

	m := NewModelWithConfig(nil, rb, 1000, 200, common.DefaultKeyMap())
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
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())
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

// TestAutoResetTickIgnoredWhileBlurred drives the same tick the
// tea.Tick scheduler would deliver after the cadence elapses, but
// from a blurred state. The expected behavior is: no reset fires
// (no Reset() call on the engine), and no new tick is re-armed —
// SetFocused will arm a fresh one when focus returns.
func TestAutoResetTickIgnoredWhileBlurred(t *testing.T) {
	engine := &fakeResettableSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	if cmd := m.SetAutoResetInterval(50 * time.Millisecond); cmd == nil {
		t.Fatalf("SetAutoResetInterval should return a tick command for a positive interval")
	}
	gen := m.autoResetGen

	// Simulate blur. The returned cmd must be nil (no rearm).
	if cmd := m.SetFocused(false); cmd != nil {
		t.Fatalf("SetFocused(false) should not return a tick command, got %v", cmd)
	}
	if m.autoResetGen == gen {
		t.Fatalf("SetFocused(false) should bump autoResetGen so in-flight ticks are dropped")
	}

	// Deliver the in-flight tick that was scheduled before the blur. It
	// carries the pre-blur generation, so it must be silently dropped.
	staleTick := autoResetTickMsg{generation: gen}
	next, cmd := m.Update(staleTick)
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("blurred dashboard should not re-arm the timer on a stale tick, got %v", cmd)
	}
	if engine.resetCount != 0 {
		t.Fatalf("blurred dashboard should not reset the engine, got resetCount=%d", engine.resetCount)
	}

	// Even a tick crafted with the current generation must not fire
	// while blurred — handleAutoResetTick gates on m.focused.
	currentTick := autoResetTickMsg{generation: m.autoResetGen}
	next, cmd = m.Update(currentTick)
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("blurred dashboard must not re-arm even on a current-gen tick, got %v", cmd)
	}
	if engine.resetCount != 0 {
		t.Fatalf("blurred dashboard must not reset on a current-gen tick, got resetCount=%d", engine.resetCount)
	}
}

// TestAutoResetTickResumesOnFocusRegain checks that focus regain arms
// a fresh tick at the configured cadence, and that the next tick fires
// the reset path. We deliver the tick by direct injection (the same
// payload tea.Tick would deliver) rather than waiting on real time.
func TestAutoResetTickResumesOnFocusRegain(t *testing.T) {
	engine := &fakeResettableSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	m.SetAutoResetInterval(50 * time.Millisecond)
	m.SetFocused(false)

	// Focus regain must return a non-nil tick cmd because the timer is
	// still configured, and bump the generation again.
	preGen := m.autoResetGen
	cmd := m.SetFocused(true)
	if cmd == nil {
		t.Fatalf("SetFocused(true) should return a fresh tick cmd when timer is enabled")
	}
	if m.autoResetGen == preGen {
		t.Fatalf("SetFocused(true) should bump autoResetGen to invalidate any leftover ticks")
	}

	// Deliver a tick at the post-regain generation: the reset must fire
	// and a fresh tick must be re-armed for the next interval.
	tick := autoResetTickMsg{generation: m.autoResetGen}
	next, cmd := m.Update(tick)
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("focused dashboard should re-arm timer and emit reset cmd, got nil")
	}
	if engine.resetCount != 1 {
		t.Fatalf("focused tick should reset engine exactly once, got resetCount=%d", engine.resetCount)
	}
}

// TestSetFocusedNoOpWhenStateUnchanged guards against accidental
// generation churn when focus messages arrive without an actual state
// change (e.g. a duplicate FocusMsg). Bumping the generation in that
// case would silently invalidate a healthy in-flight tick.
func TestSetFocusedNoOpWhenStateUnchanged(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.SetAutoResetInterval(50 * time.Millisecond)
	gen := m.autoResetGen

	if cmd := m.SetFocused(true); cmd != nil {
		t.Fatalf("SetFocused(true) on already-focused model should be a no-op, got %v", cmd)
	}
	if m.autoResetGen != gen {
		t.Fatalf("autoResetGen should not change on no-op focus call, was %d now %d", gen, m.autoResetGen)
	}
}

// TestSetFocusedReturnsNilWhenTimerDisabled is the corner case where
// focus returns but the user has the auto-reset timer turned off. No
// tick should be armed (it would never fire anyway).
func TestSetFocusedReturnsNilWhenTimerDisabled(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	// Timer disabled by default.
	m.SetFocused(false)
	if cmd := m.SetFocused(true); cmd != nil {
		t.Fatalf("SetFocused(true) with disabled timer should return nil, got %v", cmd)
	}
}

// TestAutoResetStatusAddsPausedSuffixWhenBlurred locks in the chrome
// label contract:
//   - enabled+focused -> "auto-reset: <remaining>/30s" (countdown).
//   - enabled+blurred -> "auto-reset: 30s (paused)".
//   - disabled stays "auto-reset: off" regardless of focus.
//
// The countdown value can fluctuate by a second between SetAutoResetInterval
// and the status read, so we accept "30s/30s" or "29s/30s" rather than
// pinning an exact remaining string.
func TestAutoResetStatusAddsPausedSuffixWhenBlurred(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.SetAutoResetInterval(30 * time.Second)
	got := m.autoResetStatus()
	if got != "auto-reset: 30s/30s" && got != "auto-reset: 29s/30s" {
		t.Fatalf("focused enabled status = %q, want auto-reset: 30s/30s or 29s/30s", got)
	}

	m.SetFocused(false)
	if got, want := m.autoResetStatus(), "auto-reset: 30s (paused)"; got != want {
		t.Fatalf("blurred enabled status = %q, want %q", got, want)
	}

	m.SetAutoResetInterval(0)
	if got, want := m.autoResetStatus(), "auto-reset: off"; got != want {
		t.Fatalf("blurred disabled status = %q, want %q", got, want)
	}

	m.SetFocused(true)
	if got, want := m.autoResetStatus(), "auto-reset: off"; got != want {
		t.Fatalf("focused disabled status = %q, want %q", got, want)
	}
}

// TestNewModelWithConfigZeroFastRefreshUsesDefault verifies that passing 0 for
// fastRefreshMs results in the model using the package-level constant cadence
// (streamRefreshMs / flameRefreshMs) rather than a zero-duration tick, keeping
// backward-compatibility for callers that do not supply a fast refresh interval.
func TestNewModelWithConfigZeroFastRefreshUsesDefault(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 0, common.DefaultKeyMap())
	if m.fastRefreshEvery != 0 {
		t.Fatalf("expected fastRefreshEvery=0 (use constant default), got %v", m.fastRefreshEvery)
	}
	// streamTickCmd and flameTickCmd should return non-nil commands even when
	// fastRefreshEvery is zero, falling back to the constant cadence.
	if cmd := m.streamTickCmd(); cmd == nil {
		t.Fatalf("streamTickCmd() returned nil with zero fastRefreshEvery")
	}
	if cmd := m.flameTickCmd(); cmd == nil {
		t.Fatalf("flameTickCmd() returned nil with zero fastRefreshEvery")
	}
}

// TestNewModelWithConfigFastRefreshStored verifies that a positive fastRefreshMs
// value is stored on the model and that the tick commands return non-nil commands.
func TestNewModelWithConfigFastRefreshStored(t *testing.T) {
	const fastMs = 150
	m := NewModelWithConfig(nil, nil, 1000, fastMs, common.DefaultKeyMap())
	want := time.Duration(fastMs) * time.Millisecond
	if m.fastRefreshEvery != want {
		t.Fatalf("expected fastRefreshEvery=%v, got %v", want, m.fastRefreshEvery)
	}
	if cmd := m.streamTickCmd(); cmd == nil {
		t.Fatalf("streamTickCmd() returned nil with fastRefreshEvery=%v", want)
	}
	if cmd := m.flameTickCmd(); cmd == nil {
		t.Fatalf("flameTickCmd() returned nil with fastRefreshEvery=%v", want)
	}
}

// TestSetFastRefreshIntervalUpdatesModel verifies that SetFastRefreshInterval
// overwrites fastRefreshEvery and that negative values are clamped to zero
// (which restores the constant fallback).
func TestSetFastRefreshIntervalUpdatesModel(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())

	m.SetFastRefreshInterval(500 * time.Millisecond)
	if m.fastRefreshEvery != 500*time.Millisecond {
		t.Fatalf("expected fastRefreshEvery=500ms after Set, got %v", m.fastRefreshEvery)
	}

	// Negative value should be clamped to zero (constant fallback).
	m.SetFastRefreshInterval(-1 * time.Millisecond)
	if m.fastRefreshEvery != 0 {
		t.Fatalf("expected fastRefreshEvery=0 after negative Set, got %v", m.fastRefreshEvery)
	}
}

// TestFormatAutoResetRemainingFormats exercises the duration formatter
// used by the chrome countdown: sub-minute durations stay in seconds,
// whole minutes drop the trailing "0s", and mixed values use "MmSs".
// Zero/negative remaining (deadline elapsed before the next tick) and
// the zero armedAt sentinel both render "0s" so the status line never
// shows an empty placeholder.
func TestFormatAutoResetRemainingFormats(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name    string
		armedAt time.Time
		every   time.Duration
		want    string
	}{
		{"sub-minute", now, 12 * time.Second, "12s"},
		{"whole minute", now, 2 * time.Minute, "2m"},
		{"mixed", now, time.Minute + 23*time.Second, "1m23s"},
		{"zero armedAt", time.Time{}, 30 * time.Second, "0s"},
		{"elapsed deadline", now.Add(-5 * time.Second), 1 * time.Second, "0s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatAutoResetRemaining(tc.armedAt, tc.every); got != tc.want {
				t.Fatalf("formatAutoResetRemaining(%v, %v) = %q, want %q", tc.armedAt, tc.every, got, tc.want)
			}
		})
	}
}
