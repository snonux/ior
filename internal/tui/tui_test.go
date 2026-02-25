package tui

import (
	"context"
	"errors"
	"ior/internal/statsengine"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ior/internal/flags"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

func TestPidSelectedTransitionsToDashboardAndSetsPIDFilter(t *testing.T) {
	flags.SetPidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(PidSelectedMsg{Pid: 42})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}

	updated := next.(Model)
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.screen)
	}
	if !updated.attaching {
		t.Fatalf("expected attaching state to be true")
	}
	if got := flags.Get().PidFilter; got != 42 {
		t.Fatalf("expected pid filter 42, got %d", got)
	}
}

func TestInitialPIDSkipsPickerAndStartsTracing(t *testing.T) {
	flags.SetPidFilter(-1)
	m := NewModel(7, func(context.Context) error { return nil })

	if m.screen != ScreenDashboard {
		t.Fatalf("expected initial screen dashboard, got %v", m.screen)
	}

	cmd := m.Init()
	if cmd == nil {
		t.Fatalf("expected init command when initial pid is set")
	}
}

func TestPidSelectedAllSetsNoFilter(t *testing.T) {
	flags.SetPidFilter(999)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, _ := m.Update(PidSelectedMsg{Pid: 0})
	updated := next.(Model)

	if got := flags.Get().PidFilter; got != -1 {
		t.Fatalf("expected pid filter -1 for all pids, got %d", got)
	}
	_ = updated
}

func TestTracingErrorMessageClearsAttachingState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.attaching = true

	next, _ := m.Update(TracingErrorMsg{Err: errors.New("boom")})
	updated := next.(Model)
	if updated.attaching {
		t.Fatalf("expected attaching to be false after tracing error")
	}
	if updated.lastErr == nil || updated.lastErr.Error() != "boom" {
		t.Fatalf("expected tracing error to be stored")
	}
}

func TestViewShowsAttachingAndErrorStates(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.attaching = true
	attachingView := m.View()
	if !strings.Contains(attachingView, "Attaching tracepoints...") {
		t.Fatalf("expected attaching view, got %q", attachingView)
	}

	m.attaching = false
	m.lastErr = errors.New("failed")
	errorView := m.View()
	if !strings.Contains(errorView, "failed") {
		t.Fatalf("expected error view, got %q", errorView)
	}
}

func TestQuitKeySetsQuittingState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("expected tea.QuitMsg")
	}

	updated := next.(Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestQuitKeyMatchesSingleBindingWithoutPanic(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.keys.Quit = key.NewBinding(key.WithKeys("x"), key.WithHelp("x", "quit"))

	_, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'z'}})

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if cmd == nil {
		t.Fatalf("expected quit cmd")
	}
	updated := next.(Model)
	if !updated.quitting {
		t.Fatalf("expected quitting state")
	}
}

func TestStartTraceCmdLaunchesBeforeStarterReturns(t *testing.T) {
	cmd := startTraceCmd(func(context.Context) error { return nil }, context.Background())
	msg := cmd()
	if _, ok := msg.(TracingStartedMsg); !ok {
		t.Fatalf("expected TracingStartedMsg, got %T", msg)
	}
}

func TestStartTraceCmdEmitsErrorMsg(t *testing.T) {
	cmd := startTraceCmd(func(context.Context) error { return errors.New("trace failed") }, context.Background())
	msg := cmd()
	traceErr, ok := msg.(TracingErrorMsg)
	if !ok {
		t.Fatalf("expected TracingErrorMsg, got %T", msg)
	}
	if traceErr.Err == nil || traceErr.Err.Error() != "trace failed" {
		t.Fatalf("unexpected trace error message: %+v", traceErr)
	}
}

func TestQuitInvokesTraceStop(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	done := make(chan struct{})
	m.traceStop = func() {
		close(done)
	}

	_, quitCmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if quitCmd == nil {
		t.Fatalf("expected quit command")
	}

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("expected stopTrace to be invoked on quit")
	}
}

type fakeDashboardSource struct {
	snap *statsengine.Snapshot
}

func (f fakeDashboardSource) Snapshot() *statsengine.Snapshot {
	return f.snap
}

func TestDashboardRefreshPicksLateBoundSource(t *testing.T) {
	orig := getDashboardSnapshotSource()
	defer SetDashboardSnapshotSource(orig)

	SetDashboardSnapshotSource(nil)
	source := lateBoundDashboardSource{}

	want := &statsengine.Snapshot{TotalSyscalls: 77}
	SetDashboardSnapshotSource(fakeDashboardSource{snap: want})

	got := source.Snapshot()
	if got != want {
		t.Fatalf("expected late-bound source to use latest global source")
	}
}

func TestTracingStartedRebindsEventStreamSource(t *testing.T) {
	orig := getEventStreamSource()
	defer SetEventStreamSource(orig)

	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "proc", PID: 1, TID: 1})
	SetEventStreamSource(rb)

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = true

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(Model)

	next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(Model)

	if !strings.Contains(m.View(), "read") {
		t.Fatalf("expected stream tab to render rebound stream event")
	}
}

func TestExportKeyOpensModalOnDashboard(t *testing.T) {
	flags.SetTUIExportEnable(true)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	updated := next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open on e key")
	}
}

func TestExportKeyIgnoredWhenExportDisabled(t *testing.T) {
	flags.SetTUIExportEnable(false)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	updated := next.(Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected export modal to remain closed when export is disabled")
	}
}

func TestStreamFilterModalConsumesEKeyInsteadOfOpeningExport(t *testing.T) {
	flags.SetTUIExportEnable(true)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	for _, r := range []rune{'o', 'p', 'e'} {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(Model)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)

	if m.exporter.Visible() {
		t.Fatalf("expected export modal to remain closed while stream filter modal handles typing")
	}
	if !strings.Contains(m.View(), "syscall~ope") {
		t.Fatalf("expected typed syscall filter to be applied")
	}
}

func TestRunExportCmdCSVWritesFile(t *testing.T) {
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	snap := &statsengine.Snapshot{TotalSyscalls: 1}
	msg := runExportCmd(tuiexport.OptionCSV, snap)()
	done, ok := msg.(tuiexport.CompletedMsg)
	if !ok {
		t.Fatalf("expected CompletedMsg, got %T", msg)
	}
	if done.Path == "" {
		t.Fatalf("expected export path")
	}
	if _, err := os.Stat(filepath.Join(dir, done.Path)); err != nil {
		t.Fatalf("expected CSV file to exist: %v", err)
	}
}

func TestHelpKeyTogglesOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	if m.showHelp {
		t.Fatalf("expected help hidden by default")
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updated := next.(Model)
	if !updated.showHelp {
		t.Fatalf("expected help to be shown after ?")
	}

	next, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updated = next.(Model)
	if updated.showHelp {
		t.Fatalf("expected help to toggle off after second ?")
	}
}

func TestViewShowsHelpOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.showHelp = true
	m.width = 100
	m.height = 30

	out := m.View()
	if !strings.Contains(out, "Help") {
		t.Fatalf("expected help title in overlay")
	}
	if !strings.Contains(out, "tab next tab") {
		t.Fatalf("expected keybinding text in overlay")
	}
}

func TestHelpOverlayBlocksUnderlyingActions(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.showHelp = true

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	updated := next.(Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected export modal to stay closed while help overlay is active")
	}
}

func TestHelpOverlayUsesPickerBindingsOnPickerScreen(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenPIDPicker
	m.showHelp = true
	m.width = 100
	m.height = 30

	out := m.View()
	if !strings.Contains(out, "enter select") || !strings.Contains(out, "r refresh") {
		t.Fatalf("expected picker shortcuts in help overlay")
	}
	if strings.Contains(out, "e export") {
		t.Fatalf("did not expect dashboard-only shortcut in picker help overlay")
	}
}

func TestHelpToggleDoesNotBreakExportModalInput(t *testing.T) {
	flags.SetTUIExportEnable(true)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	updated := next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open")
	}

	next, _ = updated.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	updated = next.(Model)
	if updated.showHelp {
		t.Fatalf("did not expect hidden help flag while export modal is open")
	}

	next, _ = updated.Update(tea.KeyMsg{Type: tea.KeyEsc})
	updated = next.(Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected esc to close export modal")
	}
}

func TestHelpOverlayHidesExportBindingWhenExportDisabled(t *testing.T) {
	flags.SetTUIExportEnable(false)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.showHelp = true
	m.width = 100
	m.height = 30

	out := m.View()
	if strings.Contains(out, "e export") {
		t.Fatalf("did not expect export shortcut in help overlay when export is disabled")
	}
}

func TestExportModalStillAllowsDashboardStatsUpdates(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.exporter = m.exporter.Open()

	snap := &statsengine.Snapshot{TotalSyscalls: 99}
	next, _ := m.Update(StatsTickMsg{Snap: snap})
	updated := next.(Model)

	if got := updated.dashboard.LatestSnapshot(); got != snap {
		t.Fatalf("expected dashboard snapshot update while export modal visible")
	}
}

func TestDashboardTabKeysChangeActiveView(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	out := m.View()
	if !strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected overview waiting view by default")
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	updated := next.(Model)
	out = updated.View()
	if !strings.Contains(out, "Syscalls: waiting for stats") {
		t.Fatalf("expected syscalls waiting view after pressing 2")
	}

	next, _ = updated.Update(tea.KeyMsg{Type: tea.KeyTab})
	updated = next.(Model)
	out = updated.View()
	if !strings.Contains(out, "Files: waiting for stats") {
		t.Fatalf("expected files waiting view after tab")
	}
}
