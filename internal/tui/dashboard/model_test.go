package dashboard

import (
	"strings"
	"testing"

	"ior/internal/statsengine"
	common "ior/internal/tui/common"
	"ior/internal/tui/messages"

	tea "github.com/charmbracelet/bubbletea"
)

type fakeSnapshotSource struct {
	snapshots int
	snap      *statsengine.Snapshot
}

func (f *fakeSnapshotSource) Snapshot() *statsengine.Snapshot {
	f.snapshots++
	return f.snap
}

func TestKeySwitchingChangesActiveTab(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	model := next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected syscalls tab, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyTab})
	model = next.(Model)
	if model.activeTab != TabFiles {
		t.Fatalf("expected next tab to be files, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	model = next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected previous tab to be syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	model = next.(Model)
	if model.activeTab != TabStream {
		t.Fatalf("expected stream tab on key 7, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	model = next.(Model)
	if model.activeTab != TabStream {
		t.Fatalf("expected stream tab on key 6, got %v", model.activeTab)
	}
}

func TestArrowAndViKeysCycleTabs(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRight})
	model := next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected right arrow to move to syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'l'}})
	model = next.(Model)
	if model.activeTab != TabFiles {
		t.Fatalf("expected l to move to files, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyLeft})
	model = next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected left arrow to move back to syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'h'}})
	model = next.(Model)
	if model.activeTab != TabOverview {
		t.Fatalf("expected h to move back to overview, got %v", model.activeTab)
	}
}

func TestSyscallsTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}, {Name: "write", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model := next.(Model)
	if model.syscallsOffset != 1 {
		t.Fatalf("expected offset 1 after j, got %d", model.syscallsOffset)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
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

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model := next.(Model)
	if model.processesOffset != 1 {
		t.Fatalf("expected processes offset 1 after j, got %d", model.processesOffset)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	model = next.(Model)
	if model.processesOffset != 0 {
		t.Fatalf("expected processes offset 0 after k, got %d", model.processesOffset)
	}
}

func TestFilesTabScrollsWithJK(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles
	snap := statsengine.NewSnapshot(nil, nil, nil, nil, []statsengine.FileSnapshot{{Path: "/a"}, {Path: "/b"}}, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model := next.(Model)
	if model.filesOffset != 1 {
		t.Fatalf("expected files offset 1 after j, got %d", model.filesOffset)
	}

	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'k'}})
	model = next.(Model)
	if model.filesOffset != 0 {
		t.Fatalf("expected files offset 0 after k, got %d", model.filesOffset)
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

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
	model := next.(Model)
	if model.filesDirOffset != 1 {
		t.Fatalf("expected grouped dir offset 1 after j, got %d", model.filesDirOffset)
	}
	if model.filesOffset != 0 {
		t.Fatalf("expected flat files offset unchanged, got %d", model.filesOffset)
	}
}

func TestDirGroupKeyTogglesOnlyOnFilesTab(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabFiles

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	model := next.(Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected filesDirGrouped to toggle on files tab")
	}

	model.activeTab = TabOverview
	next, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	model = next.(Model)
	if !model.filesDirGrouped {
		t.Fatalf("expected filesDirGrouped unchanged outside files tab")
	}
}

func TestScrollOffsetDoesNotGrowUnbounded(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())
	m.activeTab = TabSyscalls
	snap := statsengine.NewSnapshot(nil, nil, nil, []statsengine.SyscallSnapshot{{Name: "read", Count: 1}, {Name: "write", Count: 1}}, nil, nil, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})
	m.latest = &snap

	for i := 0; i < 50; i++ {
		next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'j'}})
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
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
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
	out := m.View()
	if !strings.Contains(out, "Overview") {
		t.Fatalf("expected overview label in view")
	}
	if !strings.Contains(out, "Press ? for help") {
		t.Fatalf("expected inline help hint in view")
	}
	if !strings.Contains(out, "tab next tab") {
		t.Fatalf("expected help bar text in view")
	}
}
