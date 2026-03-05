package tui

import (
	"context"
	"errors"
	"ior/internal/probemanager"
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
	"ior/internal/tui/probes"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
)

type fakeProbeManager struct {
	states []probemanager.ProbeState
}

func (f fakeProbeManager) States() []probemanager.ProbeState { return f.states }
func (f fakeProbeManager) Toggle(string) error               { return nil }
func (f fakeProbeManager) ActiveCount() (int, int)           { return len(f.states), len(f.states) }

func TestPidSelectedTransitionsToDashboardAndSetsPIDFilter(t *testing.T) {
	flags.SetPidFilter(-1)
	flags.SetTidFilter(99)
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
	if got := flags.Get().TidFilter; got != -1 {
		t.Fatalf("expected tid filter reset to -1, got %d", got)
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
	attachingView := m.View().Content
	if !strings.Contains(attachingView, "Attaching tracepoints...") {
		t.Fatalf("expected attaching view, got %q", attachingView)
	}

	m.attaching = false
	m.lastErr = errors.New("failed")
	errorView := m.View().Content
	if !strings.Contains(errorView, "failed") {
		t.Fatalf("expected error view, got %q", errorView)
	}
}

func TestQuitKeySetsQuittingState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
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

	_, _ = m.Update(tea.KeyPressMsg{Code: []rune{'z'}[0], Text: string([]rune{'z'})})

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'x'}[0], Text: string([]rune{'x'})})
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

	_, quitCmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
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

type fakeResettableDashboardSource struct {
	snap       *statsengine.Snapshot
	resetCalls int
}

func (f *fakeResettableDashboardSource) Snapshot() *statsengine.Snapshot {
	return f.snap
}

func (f *fakeResettableDashboardSource) Reset() {
	f.resetCalls++
	f.snap = &statsengine.Snapshot{TotalSyscalls: 0}
}

func TestDashboardRefreshPicksLateBoundSource(t *testing.T) {
	runtime := newRuntimeBindings()
	source := lateBoundDashboardSource{runtime: runtime}

	want := &statsengine.Snapshot{TotalSyscalls: 77}
	runtime.SetDashboardSnapshotSource(fakeDashboardSource{snap: want})

	got := source.Snapshot()
	if got != want {
		t.Fatalf("expected late-bound source to use latest runtime source")
	}
}

func TestProbeToggledMsgResetsDashboardStatsSource(t *testing.T) {
	src := &fakeResettableDashboardSource{snap: &statsengine.Snapshot{TotalSyscalls: 99}}

	m := NewModel(-1, func(context.Context) error { return nil })
	m.runtime.SetDashboardSnapshotSource(src)
	m.screen = ScreenDashboard
	m.attaching = false
	m.probeModal = probes.NewModel(fakeProbeManager{states: []probemanager.ProbeState{{Syscall: "read", Active: true}}}).Open()

	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read"})
	updated := next.(Model)

	if src.resetCalls != 1 {
		t.Fatalf("expected one reset call, got %d", src.resetCalls)
	}
	snap := updated.dashboard.LatestSnapshot()
	if snap == nil || snap.TotalSyscalls != 0 {
		t.Fatalf("expected dashboard snapshot refreshed from reset source, got %+v", snap)
	}
}

func TestTracingStartedRebindsEventStreamSource(t *testing.T) {
	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "proc", PID: 1, TID: 1})

	m := NewModel(-1, func(context.Context) error { return nil })
	m.runtime.SetEventStreamSource(rb)
	m.screen = ScreenDashboard
	m.attaching = true

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(Model)

	next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(Model)

	if !strings.Contains(m.View().Content, "read") {
		t.Fatalf("expected stream tab to render rebound stream event")
	}
}

func TestExportKeyOpensModalOnDashboard(t *testing.T) {
	flags.SetTUIExportEnable(true)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open on e key")
	}
}

func TestSelectPIDKeyReturnsToFreshPickerAndStopsTrace(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30
	stopped := false
	m.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: string([]rune{'p'})})
	updated := next.(Model)

	if !stopped {
		t.Fatalf("expected active tracing to be stopped before returning to picker")
	}
	if updated.screen != ScreenPIDPicker {
		t.Fatalf("expected PID picker screen, got %v", updated.screen)
	}
	if updated.attaching {
		t.Fatalf("expected attaching=false on picker screen")
	}
	if updated.traceStop != nil {
		t.Fatalf("expected traceStop to be cleared after stopping")
	}
	if cmd == nil {
		t.Fatalf("expected picker init command when returning to picker")
	}
}

func TestSelectTIDKeyReturnsToPickerWhenPIDFilterIsAll(t *testing.T) {
	flags.SetPidFilter(-1)
	flags.SetTidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'t'}[0], Text: string([]rune{'t'})})
	updated := next.(Model)
	if !stopped {
		t.Fatalf("expected tracing stop before tid reselect")
	}
	if updated.screen != ScreenPIDPicker {
		t.Fatalf("expected picker screen, got %v", updated.screen)
	}
	if cmd == nil {
		t.Fatalf("expected picker init command")
	}
}

func TestSelectTIDKeyReturnsToPickerWhenSinglePIDSelected(t *testing.T) {
	flags.SetPidFilter(1234)
	flags.SetTidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'t'}[0], Text: string([]rune{'t'})})
	updated := next.(Model)
	if !stopped {
		t.Fatalf("expected tracing stop before tid reselect")
	}
	if updated.screen != ScreenPIDPicker {
		t.Fatalf("expected picker screen, got %v", updated.screen)
	}
	if cmd == nil {
		t.Fatalf("expected picker init command")
	}
}

func TestTidSelectedTransitionsToDashboardAndSetsTIDFilter(t *testing.T) {
	flags.SetPidFilter(2222)
	flags.SetTidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(TidSelectedMsg{Pid: 0, Tid: 3333})
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
	if got := flags.Get().TidFilter; got != 3333 {
		t.Fatalf("expected tid filter 3333, got %d", got)
	}
	if got := flags.Get().PidFilter; got != 2222 {
		t.Fatalf("expected pid filter to remain 2222, got %d", got)
	}
}

func TestTidSelectedFromAllPIDModeSetsOwningPID(t *testing.T) {
	flags.SetPidFilter(-1)
	flags.SetTidFilter(-1)
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(TidSelectedMsg{Pid: 4444, Tid: 5555})
	if cmd == nil {
		t.Fatalf("expected tracing start command")
	}
	updated := next.(Model)
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected dashboard screen, got %v", updated.screen)
	}
	if got := flags.Get().PidFilter; got != 4444 {
		t.Fatalf("expected pid filter switched to owning pid 4444, got %d", got)
	}
	if got := flags.Get().TidFilter; got != 5555 {
		t.Fatalf("expected tid filter 5555, got %d", got)
	}
}

func TestExportKeyIgnoredWhenExportDisabled(t *testing.T) {
	flags.SetTUIExportEnable(false)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
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

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	for _, r := range []rune{'o', 'p', 'e'} {
		next, _ = m.Update(tea.KeyPressMsg{Code: []rune{r}[0], Text: string([]rune{r})})
		m = next.(Model)
	}
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if m.exporter.Visible() {
		t.Fatalf("expected export modal to remain closed while stream filter modal handles typing")
	}
	if !strings.Contains(m.View().Content, "syscall~ope") {
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
	msg := runExportCmd(true, tuiexport.OptionCSV, snap)()
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

func TestHelpKeyDoesNotToggleOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'?'}[0], Text: string([]rune{'?'})})
	updated := next.(Model)
	if updated.screen != ScreenPIDPicker {
		t.Fatalf("expected ? to have no effect, got screen %v", updated.screen)
	}
}

func TestViewShowsDashboardWithoutHelpOverlay(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.width = 100
	m.height = 30

	out := m.View().Content
	if !strings.Contains(out, "press H for help") {
		t.Fatalf("expected bottom help hint in dashboard")
	}
}

func TestQuestionMarkDoesNotBlockUnderlyingActions(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open; ? overlay is removed")
	}
}

func TestQuestionMarkDoesNotBreakExportModalInput(t *testing.T) {
	flags.SetTUIExportEnable(true)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'e'}[0], Text: string([]rune{'e'})})
	updated := next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to open")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: []rune{'?'}[0], Text: string([]rune{'?'})})
	updated = next.(Model)
	if !updated.exporter.Visible() {
		t.Fatalf("expected export modal to remain open after ? key")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	updated = next.(Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected esc to close export modal")
	}
}

func TestStatusBarHidesExportBindingWhenExportDisabled(t *testing.T) {
	flags.SetTUIExportEnable(false)
	t.Cleanup(func() { flags.SetTUIExportEnable(true) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.width = 100
	m.height = 30

	out := m.View().Content
	if strings.Contains(out, "e snapshot export") {
		t.Fatalf("did not expect export shortcut in status bar when export is disabled")
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

	out := m.View().Content
	if !strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected overview waiting view by default")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	updated := next.(Model)
	out = updated.View().Content
	if !strings.Contains(out, "Syscalls: waiting for stats") {
		t.Fatalf("expected syscalls waiting view after pressing 2")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	updated = next.(Model)
	out = updated.View().Content
	if !strings.Contains(out, "Files: waiting for stats") {
		t.Fatalf("expected files waiting view after tab")
	}
}

func TestProbeModalViewDoesNotStackDashboardContent(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.runtime.SetProbeManager(fakeProbeManager{states: []probemanager.ProbeState{{Syscall: "read", Active: true}}})
	m.probeModal = probes.NewModel(m.runtime.currentProbeManager())
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30
	m.probeModal = m.probeModal.Open()

	out := m.View().Content
	if !strings.Contains(out, "Probes (") {
		t.Fatalf("expected probe modal content, got %q", out)
	}
	if strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected probe modal to render as standalone view, got stacked dashboard content")
	}
}
