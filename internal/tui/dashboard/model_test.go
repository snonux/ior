package dashboard

import (
	"errors"
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

// fakeSnapshotSource is a SnapshotSource test double. Reset swaps in
// resetSnap (when set) so tests can tell a post-reset snapshot from a stale
// one; err makes Snapshot fail.
type fakeSnapshotSource struct {
	snapshots  int
	resetCount int
	snap       *statsengine.Snapshot
	resetSnap  *statsengine.Snapshot
	err        error
}

func (f *fakeSnapshotSource) Reset() {
	f.resetCount++
	if f.resetSnap != nil {
		f.snap = f.resetSnap
	}
}

func (f *fakeSnapshotSource) Snapshot() (*statsengine.Snapshot, error) {
	f.snapshots++
	if f.err != nil {
		return nil, f.err
	}
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
	model := next.(*Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected overview tab on key 2, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	model = next.(*Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected next tab to be syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	model = next.(*Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected previous tab to be overview, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	model = next.(*Model)
	if model.activeTab != TabStream {
		t.Fatalf("expected stream tab on key 7, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'1'}[0], Text: string([]rune{'1'})})
	model = next.(*Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab on key 1, got %v", model.activeTab)
	}
}

func TestArrowAndViKeysDoNotCycleTabs(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabOverview

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(*Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected right arrow not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'l'}[0], Text: string([]rune{'l'})})
	model = next.(*Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected l not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(*Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected left arrow not to change tabs, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'h'}[0], Text: string([]rune{'h'})})
	model = next.(*Model)
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
	model := next.(*Model)
	if model.syscallsTab.offset != 1 {
		t.Fatalf("expected offset 1 after j, got %d", model.syscallsTab.offset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(*Model)
	if model.syscallsTab.offset != 0 {
		t.Fatalf("expected offset 0 after k, got %d", model.syscallsTab.offset)
	}
}

func TestProcessesTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{{PID: 1}, {PID: 2}}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(*Model)
	if model.processesTab.offset != 1 {
		t.Fatalf("expected processes offset 1 after j, got %d", model.processesTab.offset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(*Model)
	if model.processesTab.offset != 0 {
		t.Fatalf("expected processes offset 0 after k, got %d", model.processesTab.offset)
	}
}

func TestSyscallsTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(*Model)
	if model.syscallsTab.col != 1 {
		t.Fatalf("expected syscalls selected column 1 after right, got %d", model.syscallsTab.col)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(*Model)
	if model.syscallsTab.col != 0 {
		t.Fatalf("expected syscalls selected column 0 after left, got %d", model.syscallsTab.col)
	}
}

func TestFilesTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{{Path: "/a"}}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(*Model)
	if model.filesTab.col != 1 {
		t.Fatalf("expected files selected column 1 after right, got %d", model.filesTab.col)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(*Model)
	if model.filesTab.col != 0 {
		t.Fatalf("expected files selected column 0 after left, got %d", model.filesTab.col)
	}
}

func TestProcessesTabSupportsHorizontalColumnNavigation(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{{PID: 1, Comm: "alpha"}}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	model := next.(*Model)
	if model.processesTab.col != 1 {
		t.Fatalf("expected processes selected column 1 after right, got %d", model.processesTab.col)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyLeft})
	model = next.(*Model)
	if model.processesTab.col != 0 {
		t.Fatalf("expected processes selected column 0 after left, got %d", model.processesTab.col)
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
	m.processesTab.offset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
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
	m.processesTab.offset = 1
	m.processesTab.col = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
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
	m.processesTab.col = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if !model.processesTab.sort.active || model.processesTab.sort.key != processSortKeyComm {
		t.Fatalf("expected process comm sort enabled, got %+v", model.processesTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(*Model)
	if model.processesTab.sort.active {
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
	m.processesTab.col = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(*Model)
	if !model.processesTab.sort.active || model.processesTab.sort.key != processSortKeyComm || !model.processesTab.sort.reverse {
		t.Fatalf("expected reverse process comm sort enabled, got %+v", model.processesTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(*Model)
	if model.processesTab.sort.active {
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
	m.processesTab.offset = 1
	m.processesTab.col = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
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
	m.processesTab.mode = tabVizModeTreemap
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if model.processesTab.sort.active {
		t.Fatalf("expected sort key ignored outside processes table mode")
	}
}

func TestStatsTickReanchorsSortedProcessSelectionByPID(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabProcesses
	m.processesTab.sort = tableSortState[processSortKey]{active: true, key: processSortKeyComm}
	oldSnap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 100, Comm: "agent", Syscalls: 3},
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &oldSnap
	m.processesTab.offset = 1
	m.processesTab.col = 1

	newSnap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 50, Comm: "alpha", Syscalls: 12},
		{PID: 100, Comm: "agent", Syscalls: 3},
		{PID: 200, Comm: "worker", Syscalls: 9},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &newSnap})
	model := next.(*Model)
	if model.processesTab.offset != 2 {
		t.Fatalf("expected selected worker row reanchored to offset 2, got %d", model.processesTab.offset)
	}
	if selected, _ := model.selectedProcessSnapshot(); selected.PID != 200 {
		t.Fatalf("expected selected process PID 200 after stats refresh, got %d", selected.PID)
	}
}

func TestFilesTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{{Path: "/a"}, {Path: "/b"}}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(*Model)
	if model.filesTab.offset != 1 {
		t.Fatalf("expected files offset 1 after j, got %d", model.filesTab.offset)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	model = next.(*Model)
	if model.filesTab.offset != 0 {
		t.Fatalf("expected files offset 0 after k, got %d", model.filesTab.offset)
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
	m.syscallsTab.offset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on syscalls tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Syscall == nil || req.Filter.Syscall.Pattern != "^write$" {
		t.Fatalf("expected syscall write filter, got %+v", req.Filter.Syscall)
	}
	if req.Action != "syscall~^write$" {
		t.Fatalf("expected action syscall~^write$, got %q", req.Action)
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
	model := next.(*Model)
	if !model.syscallsTab.sort.active || model.syscallsTab.sort.key != syscallSortKeyName {
		t.Fatalf("expected syscall name sort enabled, got %+v", model.syscallsTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(*Model)
	if model.syscallsTab.sort.active {
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
	model := next.(*Model)
	if !model.syscallsTab.sort.active || model.syscallsTab.sort.key != syscallSortKeyName || !model.syscallsTab.sort.reverse {
		t.Fatalf("expected reverse syscall name sort enabled, got %+v", model.syscallsTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(*Model)
	if model.syscallsTab.sort.active {
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
	m.syscallsTab.offset = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if model.syscallsTab.offset != 0 {
		t.Fatalf("expected selected read row reanchored to offset 0, got %d", model.syscallsTab.offset)
	}
	if selected, _ := model.selectedSyscallSnapshot(); selected.Name != "read" {
		t.Fatalf("expected selected syscall read after reanchor, got %q", selected.Name)
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
	m.syscallsTab.offset = 1

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted syscalls tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.Syscall == nil || req.Filter.Syscall.Pattern != "^read$" {
		t.Fatalf("expected visible sorted row to filter read, got %+v", req.Filter.Syscall)
	}
}

func TestSyscallsSortIgnoredOutsideTableMode(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsTab.mode = tabVizModeTreemap
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "write", Count: 9},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if model.syscallsTab.sort.active {
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
	m.syscallsTab.col = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if first := model.sortedSyscallRows()[0].Name; first != "read" {
		t.Fatalf("expected compact p95 sort to put read first, got %q", first)
	}

	next, _ = model.Update(tea.WindowSizeMsg{Width: 160, Height: 30})
	model = next.(*Model)
	if first := model.sortedSyscallRows()[0].Name; first != "read" {
		t.Fatalf("expected p95 sort to survive width expansion, got %q", first)
	}
}

func TestStatsTickReanchorsSortedSyscallSelectionByName(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	m.syscallsTab.sort = tableSortState[syscallSortKey]{active: true, key: syscallSortKeyName}
	oldSnap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "read", Count: 9},
		{Name: "write", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &oldSnap
	m.syscallsTab.offset = 1

	newSnap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{
		{Name: "close", Count: 50},
		{Name: "read", Count: 9},
		{Name: "write", Count: 3},
	}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &newSnap})
	model := next.(*Model)
	if model.syscallsTab.offset != 2 {
		t.Fatalf("expected selected write row reanchored to offset 2, got %d", model.syscallsTab.offset)
	}
	if selected, _ := model.selectedSyscallSnapshot(); selected.Name != "write" {
		t.Fatalf("expected selected syscall write after stats refresh, got %q", selected.Name)
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
	model := next.(*Model)
	if model.filesDirTab.offset != 1 {
		t.Fatalf("expected grouped dir offset 1 after j, got %d", model.filesDirTab.offset)
	}
	if model.filesTab.offset != 0 {
		t.Fatalf("expected flat files offset unchanged, got %d", model.filesTab.offset)
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
	m.filesTab.offset = 1

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "^/tmp/b$" {
		t.Fatalf("expected file /tmp/b filter, got %+v", req.Filter.File)
	}
	if req.Action != "file~^/tmp/b$" {
		t.Fatalf("expected action file~^/tmp/b$, got %q", req.Action)
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
	m.filesTab.col = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model := next.(*Model)
	if !model.filesTab.sort.active || model.filesTab.sort.key != fileSortKeyPath {
		t.Fatalf("expected flat file path sort enabled, got %+v", model.filesTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	model = next.(*Model)
	if model.filesTab.sort.active {
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
	m.filesTab.col = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(*Model)
	if !model.filesTab.sort.active || model.filesTab.sort.key != fileSortKeyPath || !model.filesTab.sort.reverse {
		t.Fatalf("expected reverse flat file path sort enabled, got %+v", model.filesTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(*Model)
	if model.filesTab.sort.active {
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
	m.filesDirTab.col = 6

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model := next.(*Model)
	if !model.filesDirTab.sort.active || model.filesDirTab.sort.key != fileDirSortKeyDir || !model.filesDirTab.sort.reverse {
		t.Fatalf("expected reverse grouped file dir sort enabled, got %+v", model.filesDirTab.sort)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'S'}[0], Text: "S"})
	model = next.(*Model)
	if model.filesDirTab.sort.active {
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
	m.filesTab.offset = 1
	m.filesTab.col = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "^/tmp/a.log$" {
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
	m.filesDirTab.offset = 1
	m.filesDirTab.col = 6

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)
	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	_ = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected enter on sorted grouped files tab to emit a filter request")
	}
	msg := cmd()
	req, ok := msg.(messages.GlobalFilterRequestedMsg)
	if !ok {
		t.Fatalf("expected GlobalFilterRequestedMsg, got %T", msg)
	}
	if req.Filter.File == nil || req.Filter.File.Pattern != "^/tmp/*" {
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
	m.filesTab.col = 5

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	m = next.(*Model)
	m.filesDirTab.col = 6
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'s'}[0], Text: string([]rune{'s'})})
	m = next.(*Model)

	if !m.filesTab.sort.active || m.filesTab.sort.key != fileSortKeyPath {
		t.Fatalf("expected flat file sort state preserved, got %+v", m.filesTab.sort)
	}
	if !m.filesDirTab.sort.active || m.filesDirTab.sort.key != fileDirSortKeyDir {
		t.Fatalf("expected dir sort state enabled, got %+v", m.filesDirTab.sort)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	m = next.(*Model)
	if !m.filesTab.sort.active || m.filesTab.sort.key != fileSortKeyPath {
		t.Fatalf("expected flat file sort state after returning from dir mode, got %+v", m.filesTab.sort)
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

func TestFlameTickDispatchesAndAppliesFlamegraphRefresh(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")

	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	m.SetLiveTrie(liveTrie)
	m.activeTab = TabFlame
	initialVersion := m.flamegraphModel.LastVersion()
	coreflamegraph.SeedTestFlameData(liveTrie)
	wantVersion := liveTrie.Version()
	if wantVersion == initialVersion {
		t.Fatal("seed data did not advance the live trie version")
	}

	next, cmd := m.Update(flameTickMsg{})
	model := next.(*Model)
	if cmd == nil {
		t.Fatalf("expected flame tick to schedule next tick command")
	}
	if got := model.flamegraphModel.LastVersion(); got != initialVersion {
		t.Fatalf("flame tick applied the background refresh synchronously: version=%d want=%d", got, initialVersion)
	}

	batch, ok := cmd().(tea.BatchMsg)
	if !ok {
		t.Fatalf("flame tick returned a non-batch command")
	}
	for _, batchedCmd := range batch {
		msg := batchedCmd()
		next, _ = model.Update(msg)
		model = next.(*Model)
	}
	if got := model.flamegraphModel.LastVersion(); got != wantVersion {
		t.Fatalf("dashboard did not dispatch and apply the flame refresh: version=%d want=%d", got, wantVersion)
	}
}

func TestValidFlameRefreshCompletionOffTabIsDiscardedAndAllowsLaterRefresh(t *testing.T) {
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 0)

	m := NewModelWithConfig(nil, nil, 250, 1, common.DefaultKeyMap())
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	m.SetLiveTrie(liveTrie)
	if !m.flamegraphModel.HasSnapshot() {
		t.Fatal("expected an existing flame snapshot before the asynchronous refresh")
	}
	initialVersion := m.flamegraphModel.LastVersion()
	initialView := m.flamegraphModel.View().Content

	coreflamegraph.SeedTestLiveFlameData(liveTrie, 1)
	wantVersion := liveTrie.Version()
	next, cmd := m.Update(flameTickMsg{})
	m = next.(*Model)
	firstBatch := requireDashboardBatch(t, cmd)
	if len(firstBatch) < 2 {
		t.Fatalf("expected tick and background refresh commands, got %d", len(firstBatch))
	}

	m = pressKey(m, '2')
	if m.activeTab != TabOverview {
		t.Fatalf("expected to leave flame tab for overview, got %v", m.activeTab)
	}
	for _, batchedCmd := range firstBatch {
		msg := batchedCmd()
		var completionCmd tea.Cmd
		next, completionCmd = m.Update(msg)
		m = next.(*Model)
		if completionCmd != nil {
			t.Fatalf("off-tab batch message %T scheduled a command", msg)
		}
	}
	if got := m.flamegraphModel.LastVersion(); got != initialVersion {
		t.Fatalf("off-tab completion applied hidden snapshot version %d, want retained version %d", got, initialVersion)
	}
	if got := m.flamegraphModel.View().Content; got != initialView {
		t.Fatal("off-tab completion changed the rendered flamegraph state")
	}

	m = pressKey(m, '1')
	if m.activeTab != TabFlame {
		t.Fatalf("expected to return to flame tab, got %v", m.activeTab)
	}
	// Re-entering the tab started a new fast chain; deliver its tick.
	next, cmd = m.Update(flameTickMsg{generation: m.ticks.fast.gen})
	m = next.(*Model)
	secondBatch := requireDashboardBatch(t, cmd)
	if len(secondBatch) < 2 {
		t.Fatalf("expected a later background refresh after returning to Flame, got %d commands", len(secondBatch))
	}
	for _, batchedCmd := range secondBatch {
		next, _ = m.Update(batchedCmd())
		m = next.(*Model)
	}
	if got := m.flamegraphModel.LastVersion(); got != wantVersion {
		t.Fatalf("later flame refresh version=%d want=%d", got, wantVersion)
	}
}

func requireDashboardBatch(t *testing.T, cmd tea.Cmd) tea.BatchMsg {
	t.Helper()
	if cmd == nil {
		t.Fatal("expected dashboard batch command")
	}
	msg := cmd()
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		t.Fatalf("dashboard command returned %T, want tea.BatchMsg", msg)
	}
	return batch
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
	model := next.(*Model)
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
	model := next.(*Model)

	next, _ = model.Update(flameTickMsg{})
	model = next.(*Model)
	initialVersion := model.flamegraphModel.LastVersion()

	liveTrie.Reset()
	if liveTrie.Version() == initialVersion {
		t.Fatalf("expected reset to advance trie version")
	}

	next, _ = model.Update(flameTickMsg{})
	model = next.(*Model)
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
	m = next.(*Model)
	m.SetLiveTrie(liveTrie)

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(*Model)

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
func newPausedStreamModel(t *testing.T) *Model {
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
	m = next.(*Model)
	m.streamModel.Refresh()
	_ = m.View()
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace}) // pause
	return next.(*Model)
}

func TestStreamPausedSupportsJKArrowsAndPageKeys(t *testing.T) {
	m := newPausedStreamModel(t)
	before := rowFromStreamView(t, m.View().Content)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'k'}[0], Text: string([]rune{'k'})})
	m = next.(*Model)
	afterK := rowFromStreamView(t, m.View().Content)
	if afterK >= before {
		t.Fatalf("expected k to scroll up while paused: before=%d afterK=%d", before, afterK)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyDown})
	m = next.(*Model)
	afterDown := rowFromStreamView(t, m.View().Content)
	if afterDown <= afterK {
		t.Fatalf("expected down arrow to scroll down while paused: afterK=%d afterDown=%d", afterK, afterDown)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyPgUp})
	m = next.(*Model)
	afterPgUp := rowFromStreamView(t, m.View().Content)
	if afterPgUp >= afterDown {
		t.Fatalf("expected pgup to scroll up while paused: afterDown=%d afterPgUp=%d", afterDown, afterPgUp)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyPgDown})
	m = next.(*Model)
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
	model := next.(*Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected filesDirGrouped to toggle on files tab")
	}

	model.activeTab = TabOverview
	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'d'}[0], Text: string([]rune{'d'})})
	model = next.(*Model)
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
	model := next.(*Model)
	if got := model.syscallsTab.mode; got != tabVizModeBubbles {
		t.Fatalf("expected syscalls bubbles mode enabled")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(*Model)
	if got := model.syscallsTab.mode; got != tabVizModeTreemap {
		t.Fatalf("expected syscalls treemap mode enabled")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'v'}[0], Text: string([]rune{'v'})})
	model = next.(*Model)
	if got := model.syscallsTab.mode; got != tabVizModeTable {
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
	model := next.(*Model)
	if got := model.syscallsTab.bubble.Metric(); got != bubbleMetricBytes {
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
	m.filesTab.mode = tabVizModeTreemap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'b'}[0], Text: string([]rune{'b'})})
	model := next.(*Model)
	if got := model.filesTab.bubble.Metric(); got != bubbleMetricBytes {
		t.Fatalf("expected files metric toggle to bytes in treemap mode, got %q", got)
	}
}

// pressKey sends a single rune key to model and returns the updated model.
func pressKey(m *Model, r rune) *Model {
	next, _ := m.Update(tea.KeyPressMsg{Code: r, Text: string(r)})
	return next.(*Model)
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
	if got := m.filesTab.mode; got != tabVizModeTable {
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
func assertFilesVizCycle(t *testing.T, m *Model) {
	t.Helper()
	m = pressKey(m, 'v')
	if got := m.filesTab.mode; got != tabVizModeBubbles {
		t.Fatalf("expected files bubbles mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesTab.mode; got != tabVizModeTreemap {
		t.Fatalf("expected files treemap mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesTab.mode; got != tabVizModeIcicle {
		t.Fatalf("expected files icicle mode enabled in directory mode")
	}
	m = pressKey(m, 'v')
	if got := m.filesTab.mode; got != tabVizModeTable {
		t.Fatalf("expected files mode cycled back to table")
	}
	m = pressKey(m, 'd') // leave dir mode
	if got := m.filesTab.mode; got != tabVizModeTable {
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
	m.syscallsTab.mode = tabVizModeBubbles
	m.refreshBubbleData()
	if len(m.syscallsTab.bubble.nodes) < 2 {
		t.Fatalf("expected at least two syscall bubbles")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(*Model)
	if model.syscallsTab.bubble.selected != 1 {
		t.Fatalf("expected bubble selection to move to index 1, got %d", model.syscallsTab.bubble.selected)
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
	m.syscallsTab.mode = tabVizModeTreemap

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	model := next.(*Model)
	if model.syscallsTreemapOffset != 1 {
		t.Fatalf("expected treemap selection to move to index 1, got %d", model.syscallsTreemapOffset)
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
	m.filesTab.mode = tabVizModeIcicle
	m.width = 120
	m.height = 28

	expectedMax := m.filesDirRowCountForMode()
	if expectedMax <= m.filesDirRowCount() {
		t.Fatalf("expected icicle tile count to exceed grouped dir count: tiles=%d dirs=%d", expectedMax, m.filesDirRowCount())
	}

	for i := 0; i < expectedMax+4; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
		m = next.(*Model)
	}
	if m.filesDirTab.offset != expectedMax-1 {
		t.Fatalf("expected icicle selection clamped by tile count to %d, got %d", expectedMax-1, m.filesDirTab.offset)
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
	m.syscallsTab.mode = tabVizModeTreemap
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
	m.filesTab.mode = tabVizModeTreemap
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
	m.filesTab.mode = tabVizModeIcicle
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
	m.processesTab.mode = tabVizModeTreemap
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
		m = next.(*Model)
	}
	if m.syscallsTab.offset != 1 {
		t.Fatalf("expected bounded offset 1, got %d", m.syscallsTab.offset)
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

func TestRefreshKeyResetsBaseline(t *testing.T) {
	stale := &statsengine.Snapshot{TotalSyscalls: 5}
	fresh := &statsengine.Snapshot{TotalSyscalls: 0}
	engine := &fakeSnapshotSource{snap: stale, resetSnap: fresh}
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
	if stats.Snap != fresh {
		t.Fatalf("expected the post-reset snapshot, got %+v", stats.Snap)
	}
}

// TestRefreshKeyResetWithoutSourceEmitsNilSnapshot covers a dashboard whose
// source has not been wired yet: the reset must not panic and must publish a
// nil snapshot rather than inventing one.
func TestRefreshKeyResetWithoutSourceEmitsNilSnapshot(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabOverview

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	if cmd == nil {
		t.Fatalf("expected reset baseline command")
	}
	stats, ok := cmd().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected StatsTickMsg from reset baseline")
	}
	if stats.Snap != nil {
		t.Fatalf("expected nil snapshot without a source, got %+v", stats.Snap)
	}
}

// TestRefreshKeyResetDiscardsFailedSnapshot checks that a Snapshot error after
// the reset is not published as data: the source is still reset, the tick
// carries the error instead of a snapshot, and feeding that tick back keeps
// the dashboard's last good snapshot rather than blanking the view.
func TestRefreshKeyResetDiscardsFailedSnapshot(t *testing.T) {
	good := &statsengine.Snapshot{TotalSyscalls: 7}
	buildErr := errors.New("snapshot build failed")
	engine := &fakeSnapshotSource{snap: good, err: buildErr}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	m.activeTab = TabOverview
	next, _ := m.Update(messages.StatsTickMsg{Snap: good})
	m = next.(*Model)

	_, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	if cmd == nil {
		t.Fatalf("expected reset baseline command")
	}
	if engine.resetCount != 1 {
		t.Fatalf("expected reset count 1, got %d", engine.resetCount)
	}
	stats, ok := cmd().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected StatsTickMsg from reset baseline")
	}
	if stats.Snap != nil {
		t.Fatalf("expected failed snapshot to be discarded, got %+v", stats.Snap)
	}
	if !errors.Is(stats.Err, buildErr) {
		t.Fatalf("expected tick to carry the snapshot error, got %v", stats.Err)
	}

	next, _ = m.Update(stats)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got != good {
		t.Fatalf("expected last good snapshot to survive a failed tick, got %+v", got)
	}
}

// TestRefreshTickFailureKeepsLastGoodSnapshot drives the periodic refresh
// through Update: the StatsTickMsg that handleRefreshTick batches must carry
// the error, and feeding it back must not blank a dashboard that has data.
func TestRefreshTickFailureKeepsLastGoodSnapshot(t *testing.T) {
	good := &statsengine.Snapshot{TotalSyscalls: 3}
	buildErr := errors.New("snapshot build failed")
	engine := &fakeSnapshotSource{err: buildErr}
	m := NewModelWithConfig(engine, nil, 100, 200, common.DefaultKeyMap())
	next, _ := m.Update(messages.StatsTickMsg{Snap: good})
	m = next.(*Model)

	next, cmd := m.Update(refreshTickMsg{})
	m = next.(*Model)
	tick := requireStatsTickInBatch(t, requireDashboardBatch(t, cmd))
	if tick.Snap != nil || !errors.Is(tick.Err, buildErr) {
		t.Fatalf("expected an error-only tick from a failing source, got %+v", tick)
	}

	next, _ = m.Update(tick)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got != good {
		t.Fatalf("expected last good snapshot to survive a failed refresh, got %+v", got)
	}
}

// TestSnapshotCmdFailureKeepsLastGoodSnapshot covers SnapshotCmd, which the
// TUI uses to refresh the dashboard on focus and trace start.
func TestSnapshotCmdFailureKeepsLastGoodSnapshot(t *testing.T) {
	good := &statsengine.Snapshot{TotalSyscalls: 4}
	buildErr := errors.New("snapshot build failed")
	engine := &fakeSnapshotSource{err: buildErr}
	m := NewModelWithConfig(engine, nil, 100, 200, common.DefaultKeyMap())
	next, _ := m.Update(messages.StatsTickMsg{Snap: good})
	m = next.(*Model)

	tick, ok := m.SnapshotCmd()().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected SnapshotCmd to emit a StatsTickMsg")
	}
	if tick.Snap != nil || !errors.Is(tick.Err, buildErr) {
		t.Fatalf("expected an error-only tick from a failing source, got %+v", tick)
	}

	next, _ = m.Update(tick)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got != good {
		t.Fatalf("expected last good snapshot to survive a failed SnapshotCmd, got %+v", got)
	}
}

// requireStatsTickInBatch runs each command of a dashboard batch and returns
// the single StatsTickMsg among their results.
func requireStatsTickInBatch(t *testing.T, batch tea.BatchMsg) messages.StatsTickMsg {
	t.Helper()
	var (
		found messages.StatsTickMsg
		seen  int
	)
	for _, c := range batch {
		if c == nil {
			continue
		}
		if stats, ok := c().(messages.StatsTickMsg); ok {
			found = stats
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("expected exactly one StatsTickMsg in batch, got %d", seen)
	}
	return found
}

// TestStatsTickWithoutSourceClearsSnapshot pins the other half of the
// StatsTickMsg contract: a nil snapshot without an error means "no source
// wired" and does clear the view, unlike a failed snapshot build.
func TestStatsTickWithoutSourceClearsSnapshot(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 100, 200, common.DefaultKeyMap())
	next, _ := m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{TotalSyscalls: 3}})
	m = next.(*Model)

	tick := m.statsTick()
	if tick.Err != nil || tick.Snap != nil {
		t.Fatalf("expected an empty tick without a source, got %+v", tick)
	}
	next, _ = m.Update(tick)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got != nil {
		t.Fatalf("expected no-source tick to clear the snapshot, got %+v", got)
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
	model := next.(*Model)
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
	model := next.(*Model)
	if !strings.Contains(model.View().Content, "[PAUSED]") {
		t.Fatalf("expected flame space key to toggle paused state")
	}

	next, cmd := model.Update(tea.KeyPressMsg{Code: []rune{'r'}[0], Text: string([]rune{'r'})})
	model = next.(*Model)
	if cmd == nil {
		t.Fatalf("expected flame reset key to return the shared baseline reset command")
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
	model := next.(*Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab to stay active after opening search")
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	model = next.(*Model)
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
	// The snapshot is built by the returned command, not by Update itself
	// (TestRefreshTickBuildsTheSnapshotOffTheUpdatePath pins this).
	if engine.snapshots != 0 {
		t.Fatalf("Update built a snapshot on the UI goroutine: %d calls", engine.snapshots)
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

	if engine.snapshots != 1 {
		t.Fatalf("expected one snapshot call once the commands ran, got %d", engine.snapshots)
	}
	_ = next
}

func TestStatsTickMsgUpdatesLatestSnapshot(t *testing.T) {
	snap := &statsengine.Snapshot{TotalSyscalls: 11}
	m := NewModel(nil, nil)

	next, _ := m.Update(messages.StatsTickMsg{Snap: snap})
	model := next.(*Model)
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
	m.filesDirTab.offset = 10

	next, _ := m.Update(messages.StatsTickMsg{Snap: &snap})
	model := next.(*Model)
	if model.filesDirTab.offset != 0 {
		t.Fatalf("expected grouped files offset clamped to 0, got %d", model.filesDirTab.offset)
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
	m = next.(*Model)

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
	// Build a minimal model with dir-grouped mode enabled and drive the real
	// render path: renderActiveContent is what View uses, and the Files
	// tab's registered Render hook draws the directory view when dir
	// grouping is on.
	m := Model{activeTab: TabFiles, filesDirGrouped: true, pidFilter: -1, latest: &snap}
	out := m.renderActiveContent(120, 30, &m.streamModel, m.flamegraphModel)
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

func TestHelpToggleWithF1(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())
	out := m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected default help hint")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
	m = next.(*Model)
	out = m.View().Content
	if !strings.Contains(out, "tab next tab") {
		t.Fatalf("expected expanded help after pressing F1")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyF1})
	m = next.(*Model)
	out = m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected help hint after pressing F1 again")
	}
}

// TestHelpToggleIgnoresH locks the rewiring (audit domain-05 F4): H belongs
// to the global help overlay handled above the dashboard model, so pressing
// it here must not expand the dashboard help bar.
func TestHelpToggleIgnoresH(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(*Model)
	out := m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("H must not toggle the dashboard help bar; expected the collapsed hint to remain")
	}
}

func TestTranslateFlamegraphMouseMsgOffsetsTabBarRow(t *testing.T) {
	translated, forward := translateFlamegraphMsg(tea.MouseClickMsg{
		X:      17,
		Y:      9,
		Button: tea.MouseLeft,
	}, true)
	if !forward {
		t.Fatal("a click must reach a drawn flamegraph")
	}
	click, ok := translated.(tea.MouseClickMsg)
	if !ok {
		t.Fatalf("expected translated message to stay mouse click, got %T", translated)
	}
	if click.X != 17 || click.Y != 8 {
		t.Fatalf("expected click coordinates (17,8), got (%d,%d)", click.X, click.Y)
	}
	// With the flamegraph not drawn (the "terminal too small" notice) every
	// pointer event is dropped.
	for _, msg := range []tea.Msg{
		tea.MouseClickMsg{Y: 9}, tea.MouseReleaseMsg{Y: 9}, tea.MouseMotionMsg{Y: 9}, tea.MouseWheelMsg{Y: 9},
	} {
		if _, forward := translateFlamegraphMsg(msg, false); forward {
			t.Errorf("%T reached a flamegraph that is not drawn", msg)
		}
	}
}

func TestTranslateFlamegraphMsgLeavesNonMouseUnchanged(t *testing.T) {
	msg := messages.StatsTickMsg{}
	// Non-mouse messages pass even while the flamegraph is not drawn.
	translated, forward := translateFlamegraphMsg(msg, false)
	if !forward {
		t.Fatal("a non-mouse message must always reach the flamegraph")
	}
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
	engine := &fakeSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	if cmd := m.SetAutoResetInterval(50 * time.Millisecond); cmd == nil {
		t.Fatalf("SetAutoResetInterval should return a tick command for a positive interval")
	}
	gen := m.autoReset.gen

	// Simulate blur. The returned cmd must be nil (no rearm).
	if cmd := m.SetFocused(false); cmd != nil {
		t.Fatalf("SetFocused(false) should not return a tick command, got %v", cmd)
	}
	if m.autoReset.gen == gen {
		t.Fatalf("SetFocused(false) should bump autoReset.gen so in-flight ticks are dropped")
	}

	// Deliver the in-flight tick that was scheduled before the blur. It
	// carries the pre-blur generation, so it must be silently dropped.
	staleTick := autoResetTickMsg{generation: gen}
	next, cmd := m.Update(staleTick)
	m = next.(*Model)
	if cmd != nil {
		t.Fatalf("blurred dashboard should not re-arm the timer on a stale tick, got %v", cmd)
	}
	if engine.resetCount != 0 {
		t.Fatalf("blurred dashboard should not reset the engine, got resetCount=%d", engine.resetCount)
	}

	// Even a tick crafted with the current generation must not fire
	// while blurred — handleAutoResetTick gates on m.focused.
	currentTick := autoResetTickMsg{generation: m.autoReset.gen}
	next, cmd = m.Update(currentTick)
	_ = next.(*Model)
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
	engine := &fakeSnapshotSource{}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	m.SetAutoResetInterval(50 * time.Millisecond)
	m.SetFocused(false)

	// Focus regain must return a non-nil tick cmd because the timer is
	// still configured, and bump the generation again.
	preGen := m.autoReset.gen
	cmd := m.SetFocused(true)
	if cmd == nil {
		t.Fatalf("SetFocused(true) should return a fresh tick cmd when timer is enabled")
	}
	if m.autoReset.gen == preGen {
		t.Fatalf("SetFocused(true) should bump autoReset.gen to invalidate any leftover ticks")
	}

	// Deliver a tick at the post-regain generation: the reset must fire
	// and a fresh tick must be re-armed for the next interval.
	tick := autoResetTickMsg{generation: m.autoReset.gen}
	next, cmd := m.Update(tick)
	_ = next.(*Model)
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
	gen := m.autoReset.gen

	if cmd := m.SetFocused(true); cmd != nil {
		t.Fatalf("SetFocused(true) on already-focused model should be a no-op, got %v", cmd)
	}
	if m.autoReset.gen != gen {
		t.Fatalf("autoReset.gen should not change on no-op focus call, was %d now %d", gen, m.autoReset.gen)
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
	if m.ticks.fastRefreshEvery != 0 {
		t.Fatalf("expected fastRefreshEvery=0 (use constant default), got %v", m.ticks.fastRefreshEvery)
	}
	// streamTickCmd and flameTickCmd should return non-nil commands even when
	// fastRefreshEvery is zero, falling back to the constant cadence.
	if cmd := m.ticks.streamCmd(); cmd == nil {
		t.Fatalf("streamTickCmd() returned nil with zero fastRefreshEvery")
	}
	if cmd := m.ticks.flameCmd(); cmd == nil {
		t.Fatalf("flameTickCmd() returned nil with zero fastRefreshEvery")
	}
}

// TestNewModelWithConfigFastRefreshStored verifies that a positive fastRefreshMs
// value is stored on the model and that the tick commands return non-nil commands.
func TestNewModelWithConfigFastRefreshStored(t *testing.T) {
	const fastMs = 150
	m := NewModelWithConfig(nil, nil, 1000, fastMs, common.DefaultKeyMap())
	want := time.Duration(fastMs) * time.Millisecond
	if m.ticks.fastRefreshEvery != want {
		t.Fatalf("expected fastRefreshEvery=%v, got %v", want, m.ticks.fastRefreshEvery)
	}
	if cmd := m.ticks.streamCmd(); cmd == nil {
		t.Fatalf("streamTickCmd() returned nil with fastRefreshEvery=%v", want)
	}
	if cmd := m.ticks.flameCmd(); cmd == nil {
		t.Fatalf("flameTickCmd() returned nil with fastRefreshEvery=%v", want)
	}
}

// TestSetFastRefreshIntervalUpdatesModel verifies that SetFastRefreshInterval
// overwrites fastRefreshEvery and that negative values are clamped to zero
// (which restores the constant fallback).
func TestSetFastRefreshIntervalUpdatesModel(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 1000, 200, common.DefaultKeyMap())

	m.SetFastRefreshInterval(500 * time.Millisecond)
	if m.ticks.fastRefreshEvery != 500*time.Millisecond {
		t.Fatalf("expected fastRefreshEvery=500ms after Set, got %v", m.ticks.fastRefreshEvery)
	}

	// Negative value should be clamped to zero (constant fallback).
	m.SetFastRefreshInterval(-1 * time.Millisecond)
	if m.ticks.fastRefreshEvery != 0 {
		t.Fatalf("expected fastRefreshEvery=0 after negative Set, got %v", m.ticks.fastRefreshEvery)
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
			if got := formatAutoResetRemaining(tc.armedAt, tc.every, now); got != tc.want {
				t.Fatalf("formatAutoResetRemaining(%v, %v) = %q, want %q", tc.armedAt, tc.every, got, tc.want)
			}
		})
	}
}

// newFlameResetDashboard returns a dashboard on the Flame tab with a seeded
// live trie (and so a flame snapshot), backed by a stats source that counts
// its resets.
func newFlameResetDashboard(t *testing.T) (*Model, *fakeSnapshotSource, *coreflamegraph.LiveTrie) {
	t.Helper()
	liveTrie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count", "count")
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 0)
	engine := &fakeSnapshotSource{
		snap:      &statsengine.Snapshot{TotalSyscalls: 42},
		resetSnap: &statsengine.Snapshot{TotalSyscalls: 0},
	}
	m := NewModelWithConfig(engine, nil, 250, 200, common.DefaultKeyMap())
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(*Model)
	m.SetLiveTrie(liveTrie)
	if m.activeTab != TabFlame || !m.flamegraphModel.HasSnapshot() {
		t.Fatal("expected a laid-out flamegraph on the Flame tab")
	}
	return m, engine, liveTrie
}

// TestFlameResetKeyResetsStatsBaselineToo: `r` on the Flame tab restarts the
// whole baseline, not just the flamegraph. Before the fix the flame model
// consumed the key itself, so the stats engine was never reset, the stats
// generation stayed put and the other tabs kept their pre-reset totals.
func TestFlameResetKeyResetsStatsBaselineToo(t *testing.T) {
	m, engine, liveTrie := newFlameResetDashboard(t)
	genBefore := m.statsGen
	versionBefore := liveTrie.Version()

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	m = next.(*Model)

	if engine.resetCount != 1 {
		t.Fatalf("stats engine resets = %d, want 1", engine.resetCount)
	}
	if m.statsGen != genBefore+1 {
		t.Fatalf("statsGen = %d, want %d", m.statsGen, genBefore+1)
	}
	if liveTrie.Version() == versionBefore {
		t.Fatalf("expected the live trie to be reset")
	}
	if m.flamegraphModel.HasSnapshot() {
		t.Fatalf("expected the flame snapshot state to be cleared")
	}
	if m.activeTab != TabFlame {
		t.Fatalf("expected the Flame tab to stay active")
	}
	if cmd == nil {
		t.Fatalf("expected the post-reset stats command")
	}
	tick, ok := cmd().(messages.StatsTickMsg)
	if !ok {
		t.Fatalf("expected a StatsTickMsg from the reset command")
	}
	if tick.Generation != m.statsGen || tick.Snap == nil || tick.Snap.TotalSyscalls != 0 {
		t.Fatalf("expected a post-reset tick of the new generation, got %+v", tick)
	}
	next, _ = m.Update(tick)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got == nil || got.TotalSyscalls != 0 {
		t.Fatalf("stats tabs still show pre-reset totals: %+v", got)
	}
}

// TestFlameSearchTypedRDoesNotResetBaseline is the negative half: while the
// flame search input is open `r` is search text and must reset nothing.
func TestFlameSearchTypedRDoesNotResetBaseline(t *testing.T) {
	m, engine, liveTrie := newFlameResetDashboard(t)
	genBefore := m.statsGen
	versionBefore := liveTrie.Version()

	next, _ := m.Update(tea.KeyPressMsg{Code: '/', Text: "/"})
	m = next.(*Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	m = next.(*Model)

	if !m.flamegraphModel.SearchActive() {
		t.Fatalf("expected the search input to stay open")
	}
	if engine.resetCount != 0 || m.statsGen != genBefore || liveTrie.Version() != versionBefore {
		t.Fatalf("typing r in the search reset the baseline: resets %d gen %d->%d", engine.resetCount, genBefore, m.statsGen)
	}
	if !m.flamegraphModel.HasSnapshot() {
		t.Fatalf("typing r in the search cleared the flame snapshot")
	}
}

// TestFlameResetKeyDropsInFlightResults drives `r` through the real dashboard
// while a flame refresh and a stats tick are in flight. Both were built before
// the reset, so neither may repaint pre-reset data: the flame result is
// dropped by the flame's refresh generation (ClearBaseline) and the stats tick
// by the stats generation (resetBaselineCmd). The flame model's own `r`
// handling is not the production path any more, so this is the test that
// covers the stale-result guards end to end.
func TestFlameResetKeyDropsInFlightResults(t *testing.T) {
	m, _, liveTrie := newFlameResetDashboard(t)
	genBefore := m.statsGen

	// A refresh job that already snapshotted the pre-reset trie.
	coreflamegraph.SeedTestLiveFlameData(liveTrie, 1)
	refreshCmd := m.flamegraphModel.RefreshFromLiveTrieCmd()
	if refreshCmd == nil {
		t.Fatal("expected a flame refresh to dispatch")
	}
	staleFlame := refreshCmd()
	staleTick := messages.StatsTickMsg{Generation: genBefore, Snap: &statsengine.Snapshot{TotalSyscalls: 99}}

	next, cmd := m.Update(tea.KeyPressMsg{Code: 'r', Text: "r"})
	m = next.(*Model)
	if m.statsGen != genBefore+1 {
		t.Fatalf("statsGen = %d, want %d", m.statsGen, genBefore+1)
	}

	next, _ = m.Update(staleFlame)
	m = next.(*Model)
	if m.flamegraphModel.HasSnapshot() {
		t.Fatal("stale flame refresh result repainted the pre-reset flamegraph")
	}
	next, _ = m.Update(staleTick)
	m = next.(*Model)
	if got := m.LatestSnapshot(); got != nil && got.TotalSyscalls == 99 {
		t.Fatal("stale stats tick was applied after the reset")
	}

	// The post-reset tick of the new generation still lands.
	next, _ = m.Update(cmd())
	m = next.(*Model)
	if got := m.LatestSnapshot(); got == nil || got.TotalSyscalls != 0 {
		t.Fatalf("post-reset tick not applied: %+v", got)
	}
}
