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

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	model := next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected syscalls tab, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	model = next.(Model)
	if model.activeTab != TabFiles {
		t.Fatalf("expected next tab to be files, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift})
	model = next.(Model)
	if model.activeTab != TabSyscalls {
		t.Fatalf("expected previous tab to be syscalls, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	model = next.(Model)
	if model.activeTab != TabFlame {
		t.Fatalf("expected flame tab on key 7, got %v", model.activeTab)
	}

	next, _ = model.Update(tea.KeyPressMsg{Code: []rune{'6'}[0], Text: string([]rune{'6'})})
	model = next.(Model)
	if model.activeTab != TabStream {
		t.Fatalf("expected stream tab on key 6, got %v", model.activeTab)
	}
}

func TestArrowAndViKeysDoNotCycleTabs(t *testing.T) {
	m := NewModelWithConfig(nil, nil, 250, common.DefaultKeyMap())

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
	if !strings.Contains(out, "Overview") {
		t.Fatalf("expected overview label in view")
	}
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected help hint text in view")
	}
	if strings.Contains(out, "tab next tab") {
		t.Fatalf("did not expect expanded help bar by default")
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
	out := renderActiveTab(TabFiles, &snap, nil, nil, 120, 30, -1, 0, 0, true, 0, 0)
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
	if !strings.Contains(out, "1:Overview") {
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
