package tui

import (
	"context"
	"encoding/csv"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	coreflamegraph "ior/internal/flamegraph"
	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/statsengine"
	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/eventstream"
	tuiexport "ior/internal/tui/export"
	"ior/internal/tui/messages"

	"ior/internal/flags"
	"ior/internal/tui/probes"
	"ior/internal/types"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type fakeProbeManager struct {
	states []probemanager.ProbeState
}

func (f fakeProbeManager) States() []probemanager.ProbeState { return f.states }
func (f fakeProbeManager) Toggle(string) error               { return nil }
func (f fakeProbeManager) ActiveCount() (int, int)           { return len(f.states), len(f.states) }

type testStreamSink interface {
	eventstream.Source
	Push(eventstream.StreamEvent)
}

func requireTestStreamSink(t *testing.T, source eventstream.Source) testStreamSink {
	t.Helper()
	sink, ok := source.(testStreamSink)
	if !ok {
		t.Fatalf("expected stream source to support Push, got %T", source)
	}
	return sink
}

func TestTraceFiltersContextRoundTripClonesPayload(t *testing.T) {
	original := globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "nginx"},
		File: &globalfilter.StringFilter{Pattern: "/var/log"},
		PID:  &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42},
	}

	ctx := ContextWithTraceFilters(context.Background(), original)
	original.Comm.Pattern = "mutated"
	original.PID.Value = 7

	got, ok := TraceFiltersFromContext(ctx)
	if !ok {
		t.Fatalf("expected trace filters in context")
	}
	if got.Comm == nil || got.Comm.Pattern != "nginx" {
		t.Fatalf("expected comm pattern cloned into context, got %+v", got.Comm)
	}
	if got.PID == nil || got.PID.Value != 42 {
		t.Fatalf("expected pid filter cloned into context, got %+v", got.PID)
	}
}

func TestRuntimeBindingsContextRoundTrip(t *testing.T) {
	runtime := newRuntimeBindings()

	ctx := ContextWithRuntimeBindings(context.Background(), runtime)
	got, ok := RuntimeBindingsFromContext(ctx)
	if !ok {
		t.Fatalf("expected runtime bindings in context")
	}
	if got != runtime {
		t.Fatalf("expected same runtime bindings instance from context")
	}
}

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
	if updated.pidFilter != 42 {
		t.Fatalf("expected pid filter 42, got %d", updated.pidFilter)
	}
	if updated.tidFilter != -1 {
		t.Fatalf("expected tid filter reset to -1, got %d", updated.tidFilter)
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

	if updated.pidFilter != -1 {
		t.Fatalf("expected pid filter -1 for all pids, got %d", updated.pidFilter)
	}
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
	m.screen = ScreenDashboard
	m.attaching = false

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
	m.screen = ScreenDashboard
	m.attaching = false

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
	m.screen = ScreenDashboard
	m.attaching = false
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

func TestQuitKeyDoesNotExitOnPIDPickerScreen(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	if m.screen != ScreenPIDPicker {
		t.Fatalf("expected default screen to be PID picker")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(Model)
	if cmd != nil {
		t.Fatalf("expected no quit command outside main dashboard")
	}
	if updated.quitting {
		t.Fatalf("expected q outside main dashboard not to set quitting state")
	}
}

func TestQuitKeyOnReselectPIDPickerReturnsToDashboardLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30
	m.pidFilter = 1111
	m.tidFilter = 2222
	m.dashboard.SetPidFilter(1111)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: string([]rune{'p'})})
	m = next.(Model)
	if m.screen != ScreenPIDPicker {
		t.Fatalf("expected pid picker screen after reselect, got %v", m.screen)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(Model)
	if cmd == nil {
		t.Fatalf("expected q in reselect picker to return to dashboard and restart tracing")
	}
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected dashboard screen after q cancel, got %v", updated.screen)
	}
	if !updated.attaching {
		t.Fatalf("expected attaching=true after q cancel")
	}
	if updated.quitting {
		t.Fatalf("expected q in reselect picker to behave like esc, not quit")
	}
	if updated.pickerReturn != nil {
		t.Fatalf("expected picker return context to clear after cancel")
	}
	if updated.pidFilter != 1111 || updated.tidFilter != 2222 {
		t.Fatalf("expected previous pid/tid filters restored, got pid=%d tid=%d", updated.pidFilter, updated.tidFilter)
	}
}

func TestEscOnReselectPIDPickerReturnsToDashboard(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30
	m.pidFilter = 3333
	m.tidFilter = 4444
	m.dashboard.SetPidFilter(3333)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: string([]rune{'p'})})
	m = next.(Model)
	if m.screen != ScreenPIDPicker {
		t.Fatalf("expected pid picker screen after reselect, got %v", m.screen)
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	updated := next.(Model)
	if cmd == nil {
		t.Fatalf("expected esc in reselect picker to return to dashboard and restart tracing")
	}
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected dashboard screen after esc cancel, got %v", updated.screen)
	}
	if !updated.attaching {
		t.Fatalf("expected attaching=true after esc cancel")
	}
	if updated.quitting {
		t.Fatalf("expected esc in reselect picker not to quit app")
	}
	if updated.pickerReturn != nil {
		t.Fatalf("expected picker return context to clear after cancel")
	}
	if updated.pidFilter != 3333 || updated.tidFilter != 4444 {
		t.Fatalf("expected previous pid/tid filters restored, got pid=%d tid=%d", updated.pidFilter, updated.tidFilter)
	}
}

func TestQuitKeyClosesProbeModalLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.probeModal = probes.NewModel(fakeProbeManager{
		states: []probemanager.ProbeState{{Syscall: "read", Active: true}},
	}).Open()

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(Model)
	if cmd != nil {
		_ = cmd()
	}
	if updated.probeModal.Visible() {
		t.Fatalf("expected q to close probe modal like esc")
	}
	if updated.quitting {
		t.Fatalf("expected q in probe modal not to quit app")
	}
}

func TestQuitKeyClosesExportModalLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.exporter = m.exporter.Open()

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	updated := next.(Model)
	if updated.exporter.Visible() {
		t.Fatalf("expected q to close export modal like esc")
	}
	if updated.quitting {
		t.Fatalf("expected q in export modal not to quit app")
	}
}

func TestQuitKeyClosesFlameSearchLikeEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'/'}[0], Text: string([]rune{'/'})})
	m = next.(Model)
	if !strings.Contains(m.View().Content, "0/0 matches") {
		t.Fatalf("expected flame search footer to open on /")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("expected q in flame search to close search, not quit")
	}
	if m.quitting {
		t.Fatalf("expected q in flame search not to set quitting state")
	}
	if strings.Contains(m.View().Content, "0/0 matches") {
		t.Fatalf("expected q to close flame search like esc")
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

func TestRuntimeBindingsStoreAndExposeLiveTrie(t *testing.T) {
	runtime := newRuntimeBindings()
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path"}, "count")
	runtime.SetLiveTrie(trie)
	if got := runtime.liveTrie(); got != trie {
		t.Fatalf("expected live trie to be stored and returned")
	}

	runtime.SetLiveTrie(nil)
	if got := runtime.liveTrie(); got != nil {
		t.Fatalf("expected live trie to clear on nil assignment")
	}
}

func TestRuntimeBindingsProvidePersistentStreamBuffer(t *testing.T) {
	runtime := newRuntimeBindings()
	buffer := requireTestStreamSink(t, runtime.StreamBuffer())
	if buffer == nil {
		t.Fatalf("expected persistent stream buffer")
	}
	if got := runtime.eventStreamSource(); got != buffer {
		t.Fatalf("expected runtime stream source to default to persistent buffer")
	}

	buffer.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read"})
	if buffer.Len() != 1 {
		t.Fatalf("expected pushed event in persistent buffer")
	}

	runtime.resetStreamBuffer()
	if buffer.Len() != 0 {
		t.Fatalf("expected resetStreamBuffer to clear existing buffer contents")
	}
	if got := runtime.eventStreamSource(); got != buffer {
		t.Fatalf("expected resetStreamBuffer to preserve the same buffer source")
	}
}

func TestRuntimeBindingsProvidePersistentRecorderAndSequencer(t *testing.T) {
	runtime := newRuntimeBindings()

	recorder := runtime.Recorder()
	if recorder == nil {
		t.Fatalf("expected persistent recorder")
	}
	if got := runtime.Recorder(); got != recorder {
		t.Fatalf("expected recorder pointer to remain stable")
	}

	seq := runtime.StreamSequencer()
	if seq == nil {
		t.Fatalf("expected persistent stream sequencer")
	}
	if got := seq.Next(); got != 1 {
		t.Fatalf("first persistent sequence = %d, want 1", got)
	}
	if got := runtime.StreamSequencer().Next(); got != 2 {
		t.Fatalf("second persistent sequence = %d, want 2", got)
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

	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context) error { return nil })
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

func TestGlobalFilterApplyPreservesBufferedStreamRowsAcrossRestart(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	buffer := requireTestStreamSink(t, m.runtime.StreamBuffer())
	buffer.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "proc", PID: 1, TID: 1, FileName: "/tmp/read"})
	buffer.Push(eventstream.StreamEvent{Seq: 2, Syscall: "write", Comm: "proc", PID: 1, TID: 2, FileName: "/tmp/write"})
	m.dashboard.SetStreamSource(buffer)

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(Model)
	initial := m.View().Content
	if !strings.Contains(initial, "read") || !strings.Contains(initial, "write") {
		t.Fatalf("expected initial stream view to show buffered rows, got %q", initial)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if buffer.Len() != 2 {
		t.Fatalf("expected filter apply not to clear persistent stream buffer")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}

	next, _ = m.Update(TracingStartedMsg{})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{})
	m = next.(Model)

	view := m.View().Content
	if !strings.Contains(view, "read") {
		t.Fatalf("expected matching historical row to remain visible, got %q", view)
	}
	if strings.Contains(view, "write") {
		t.Fatalf("expected non-matching historical row to be hidden after refilter, got %q", view)
	}
}

func TestGlobalFilterApplyAdvancesRuntimeFilterEpochAndKeepsRecorder(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	initialRecorder := m.runtime.Recorder()
	if initialRecorder == nil {
		t.Fatalf("expected runtime recorder")
	}
	if got := m.runtime.FilterEpoch(); got != 0 {
		t.Fatalf("initial filter epoch = %d, want 0", got)
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if got := m.runtime.FilterEpoch(); got != 1 {
		t.Fatalf("filter epoch after apply = %d, want 1", got)
	}
	if got := m.runtime.Recorder(); got != initialRecorder {
		t.Fatalf("expected runtime recorder to survive filter restart")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}
}

func TestTracingStartedUsesCurrentViewportForFlameNavigationWithoutResize(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = true
	m.width = 120
	m.height = 30
	m.runtime.SetLiveTrie(trie)

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(Model)

	if strings.Contains(m.View().Content, "sel:none") {
		t.Fatalf("expected flamegraph selection to be available immediately after tracing start")
	}

	selectedLabel := func(view string) string {
		re := regexp.MustCompile(`sel:[0-9]+/[0-9]+ ([^|]+) \|`)
		match := re.FindStringSubmatch(view)
		if len(match) != 2 {
			return ""
		}
		return strings.TrimSpace(match[1])
	}

	moved := false
	before := selectedLabel(m.View().Content)
	for i := 0; i < 12 && !moved; i++ {
		next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
		m = next.(Model)
		after := selectedLabel(m.View().Content)
		if after != "" && after != before {
			moved = true
			break
		}
	}
	if !moved {
		t.Fatalf("expected arrow navigation to move selection without requiring resize, view=%q", m.View().Content)
	}
}

func TestTracingStartedAppliesViewportWhenModelSizeIsUnset(t *testing.T) {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "path", "tracepoint"}, "count")
	coreflamegraph.SeedTestFlameData(trie)

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = true
	m.runtime.SetLiveTrie(trie)
	m.width = 0
	m.height = 0

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(Model)

	view := m.View().Content
	if strings.Contains(view, "sel:none") {
		t.Fatalf("expected tracing start to apply an effective viewport even when width/height are unset")
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

func TestFlamePauseKeyDoesNotTriggerPIDReselect(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(Model)
	if updated.screen != ScreenDashboard {
		t.Fatalf("expected flame space key to keep dashboard screen, got %v", updated.screen)
	}
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected flame space key to toggle flame paused state")
	}
}

func TestFlamePIDShortcutOpensPIDPickerInsteadOfPausing(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'p'}[0], Text: "p"})
	updated := next.(Model)
	if updated.screen != ScreenPIDPicker {
		t.Fatalf("expected p to open PID picker from flame tab, got %v", updated.screen)
	}
	if strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected p not to pause flame tab")
	}
	if cmd == nil {
		t.Fatalf("expected picker init command on p")
	}
}

func TestFlameSpaceKeyReleaseFallbackTogglesPause(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release fallback to toggle flame paused state")
	}
}

func TestFlameSpacePressReleaseDoesNotDoubleTogglePause(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key press to pause flame")
	}

	next, _ = updated.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated = next.(Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release after key press to be ignored as duplicate")
	}
}

func TestFlameSpaceReleasePressDoesNotDoubleTogglePause(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	updated := next.(Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected key release fallback to pause flame")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	updated = next.(Model)
	if !strings.Contains(updated.View().Content, "[PAUSED]") {
		t.Fatalf("expected immediate matching key press after release fallback to be ignored")
	}
}

func TestNormalizeKeyEventReleaseFallbackSuppressesImmediatePressOnly(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{Code: tea.KeySpace, Text: " "})
	if !ok {
		t.Fatalf("expected release fallback to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected release fallback to normalize to KeyPressMsg, got %T", normalized)
	}

	if normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}); ok {
		t.Fatalf("expected immediate matching press to be suppressed, got %T", normalized)
	}

	// Expire suppression deterministically instead of waiting on wall clock time.
	m.suppressPressUntil = time.Now().Add(-time.Nanosecond)
	if normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}); !ok {
		t.Fatalf("expected press to be accepted after suppression window")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected accepted message to be KeyPressMsg, got %T", normalized)
	}
}

func TestNormalizeKeyEventIgnoresUnidentifiedRelease(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	if normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{}); ok {
		t.Fatalf("expected unidentified release to be ignored, got %T", normalized)
	}

	normalized, ok := m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	if !ok {
		t.Fatalf("expected subsequent real key press to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected normalized message to be KeyPressMsg, got %T", normalized)
	}
}

func TestNormalizeKeyEventReleaseFallbackDoesNotSuppressArrowPress(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	normalized, ok := m.normalizeKeyEvent(tea.KeyReleaseMsg{Code: tea.KeyRight})
	if !ok {
		t.Fatalf("expected right release fallback to be handled")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected release fallback to normalize to KeyPressMsg, got %T", normalized)
	}

	normalized, ok = m.normalizeKeyEvent(tea.KeyPressMsg{Code: tea.KeyRight})
	if !ok {
		t.Fatalf("expected right key press to be accepted after release fallback")
	}
	if _, isPress := normalized.(tea.KeyPressMsg); !isPress {
		t.Fatalf("expected normalized message to be KeyPressMsg, got %T", normalized)
	}
}

func TestFlameOrderKeyDoesNotOpenProbeModal(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'o'}[0], Text: string([]rune{'o'})})
	updated := next.(Model)
	if updated.probeModal.Visible() {
		t.Fatalf("expected flame order key to stay in flame tab, not open probes modal")
	}
}

func TestFlameMetricKeyDoesNotOpenProbeModal(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'b'}[0], Text: string([]rune{'b'})})
	updated := next.(Model)
	if updated.probeModal.Visible() {
		t.Fatalf("expected flame metric key to stay in flame tab, not open probes modal")
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

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)

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

func TestPidSelectedClearsPersistentStreamBuffer(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context) error { return nil })
	requireTestStreamSink(t, m.runtime.StreamBuffer()).Push(eventstream.StreamEvent{Seq: 1, Syscall: "read"})

	next, _ := m.Update(PidSelectedMsg{Pid: 42})
	m = next.(Model)

	if got := m.runtime.StreamBuffer().Len(); got != 0 {
		t.Fatalf("expected pid reselection to clear persistent stream buffer, got len=%d", got)
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

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)

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

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)

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
	if updated.tidFilter != 3333 {
		t.Fatalf("expected tid filter 3333, got %d", updated.tidFilter)
	}
	if updated.pidFilter != 2222 {
		t.Fatalf("expected pid filter to remain 2222, got %d", updated.pidFilter)
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
	if updated.pidFilter != 4444 {
		t.Fatalf("expected pid filter switched to owning pid 4444, got %d", updated.pidFilter)
	}
	if updated.tidFilter != 5555 {
		t.Fatalf("expected tid filter 5555, got %d", updated.tidFilter)
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
	if m.globalFilter.Syscall == nil || m.globalFilter.Syscall.Pattern != "ope" {
		t.Fatalf("expected typed syscall filter to be stored globally, got %+v", m.globalFilter.Syscall)
	}
}

func TestRunExportCmdCSVWritesFilteredStreamSnapshot(t *testing.T) {
	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	buffer := requireTestStreamSink(t, m.runtime.StreamBuffer())
	buffer.Push(eventstream.StreamEvent{Seq: 1, Comm: "firefox", PID: 10, TID: 100, Syscall: "read", FileName: "/tmp/a"})
	buffer.Push(eventstream.StreamEvent{Seq: 2, Comm: "bash", PID: 11, TID: 110, Syscall: "write", FileName: "/tmp/b"})
	m.setGlobalFilter(globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "firefox"}})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{}})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: "7"})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(Model)

	buffer.Push(eventstream.StreamEvent{Seq: 3, Comm: "firefox", PID: 12, TID: 120, Syscall: "open", FileName: "/tmp/c"})
	next, _ = m.Update(messages.StatsTickMsg{Snap: &statsengine.Snapshot{}})
	m = next.(Model)

	msg := runExportCmd(true, tuiexport.OptionCSV, m.dashboard)()
	done, ok := msg.(tuiexport.CompletedMsg)
	if !ok {
		t.Fatalf("expected CompletedMsg, got %T", msg)
	}
	if done.Path == "" {
		t.Fatalf("expected export path")
	}
	if _, err := os.Stat(done.Path); err != nil {
		t.Fatalf("expected CSV file to exist: %v", err)
	}
	f, err := os.Open(done.Path)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected header + 2 filtered rows, got %d records", len(records))
	}
	if records[1][0] != "1" || records[2][0] != "3" {
		t.Fatalf("expected fresh filtered stream snapshot rows 1 and 3, got %v", records[1:])
	}
	if records[1][4] != "firefox" || records[2][4] != "firefox" {
		t.Fatalf("expected firefox rows only, got %v", records[1:])
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

func TestHelpOverlayOpensWithUppercaseHAndClosesWithEsc(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 100
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to become visible after H")
	}
	view := m.View().Content
	if !strings.Contains(view, "Help") || !strings.Contains(view, "Global") || !strings.Contains(view, "Esc/q close") {
		t.Fatalf("expected global help overlay content, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)
	if m.helpOverlayVisible {
		t.Fatalf("expected esc to close help overlay")
	}
	if !strings.Contains(m.View().Content, "press H for help") {
		t.Fatalf("expected dashboard help hint after closing overlay")
	}
}

func TestHelpOverlayClosesWithQWithoutQuitting(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 100
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to become visible after H")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("expected no quit command when closing help with q")
	}
	if m.helpOverlayVisible {
		t.Fatalf("expected q to close help overlay")
	}
	if m.quitting {
		t.Fatalf("expected q in help overlay not to set quitting state")
	}
}

func TestHelpOverlayCanOpenFromPIDPicker(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenPIDPicker
	m.width = 100
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'H'}[0], Text: string([]rune{'H'})})
	m = next.(Model)
	if !m.helpOverlayVisible {
		t.Fatalf("expected help overlay to open on pid picker screen")
	}
	if !strings.Contains(m.View().Content, "PID/TID Picker") {
		t.Fatalf("expected picker shortcuts in help overlay")
	}
}

func TestGlobalFilterModalOpensFromDashboardShortcut(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to open on f")
	}
}

func TestQuitClosesGlobalFilterModalWithoutQuitting(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.filterModal = m.filterModal.Open(m.globalFilter)

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'q'}[0], Text: string([]rune{'q'})})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("expected no quit command while closing filter modal")
	}
	if m.filterModal.Visible() {
		t.Fatalf("expected q to close global filter modal")
	}
	if m.quitting {
		t.Fatalf("expected q in filter modal not to set quitting state")
	}
}

func TestGlobalFilterModalUpdatesStoredFilterState(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	stopped := false
	m.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to open")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if m.filterModal.Visible() {
		t.Fatalf("expected global filter modal to close after esc")
	}
	if m.globalFilter.Syscall == nil || m.globalFilter.Syscall.Pattern != "read" {
		t.Fatalf("expected stored global filter updated from modal, got %+v", m.globalFilter.Syscall)
	}
	if !stopped {
		t.Fatalf("expected filter apply to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}
}

func TestGlobalFilterCloseWithoutChangesDoesNotRestartTrace(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	stopped := false
	m.traceStop = func() { stopped = true }

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	if !m.filterModal.Visible() {
		t.Fatalf("expected filter modal to open")
	}

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if cmd != nil {
		t.Fatalf("expected no restart command when filter is unchanged")
	}
	if stopped {
		t.Fatalf("expected unchanged filter close not to stop tracing")
	}
	if m.attaching {
		t.Fatalf("expected unchanged filter close not to restart tracing")
	}
}

func TestPausedStreamEnterAppliesSelectedCellAsGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.traceStop = func() { stopped = true }

	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{
		Seq:        1,
		Syscall:    "write",
		Comm:       "systemd",
		PID:        3655,
		TID:        4862,
		FileName:   "/var/lib/clickhouse/data",
		DurationNs: 1234,
		GapNs:      44,
		FD:         20,
	})
	m.dashboard.SetStreamSource(rb)

	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
	m = next.(Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on paused stream selection to emit a global filter request")
	}

	next, cmd = m.Update(cmd())
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected applying selected-cell global filter to restart tracing")
	}
	if m.globalFilter.Comm == nil || m.globalFilter.Comm.Pattern != "systemd" {
		t.Fatalf("expected selected comm applied globally, got %+v", m.globalFilter.Comm)
	}
	if !stopped {
		t.Fatalf("expected selected-cell global filter to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected selected-cell global filter to restart tracing")
	}
	if len(m.filterStack) != 1 || m.filterStack[0] != "comm~systemd" {
		t.Fatalf("expected selected-cell action pushed to filter stack, got %+v", m.filterStack)
	}
}

func TestGlobalFilterUndoKeyPopsLatestStackEntry(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	m.attaching = false
	stopped := false
	m.traceStop = func() { stopped = true }

	next, cmd := m.Update(tea.KeyPressMsg{Code: []rune{'F'}[0], Text: string([]rune{'F'})})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected F to trigger global filter undo")
	}
	if m.globalFilter.IsActive() {
		t.Fatalf("expected undo to restore the previous all-filter state, got %+v", m.globalFilter)
	}
	if len(m.filterStack) != 0 || len(m.filterHistory) != 0 {
		t.Fatalf("expected filter stack/history cleared after undo, got stack=%+v history=%d", m.filterStack, len(m.filterHistory))
	}
	if !stopped {
		t.Fatalf("expected undo to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected undo to restart tracing")
	}
}

func TestPausedStreamEscUndoesLatestGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	rb := eventstream.NewRingBuffer()
	rb.Push(eventstream.StreamEvent{Seq: 1, Syscall: "read", Comm: "systemd", PID: 1, TID: 2})
	m.dashboard.SetStreamSource(rb)
	m.attaching = false
	stopped := false
	m.traceStop = func() { stopped = true }

	next, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 30})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'7'}[0], Text: string([]rune{'7'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	m = next.(Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected esc in paused stream to undo one global filter layer")
	}
	next, cmd = m.Update(cmd())
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected esc undo to restart tracing")
	}
	if m.globalFilter.IsActive() {
		t.Fatalf("expected esc undo to restore all-filter state, got %+v", m.globalFilter)
	}
	if len(m.filterStack) != 0 {
		t.Fatalf("expected filter stack cleared after esc undo, got %+v", m.filterStack)
	}
	if !stopped {
		t.Fatalf("expected esc undo to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected esc undo to restart tracing")
	}
}

func TestDashboardFooterShowsGlobalFilterStack(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 140
	m.height = 35

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	m.attaching = false
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(Model)

	view := m.View().Content
	for _, want := range []string{"filter: syscall~read", "stack: syscall~read"} {
		if !strings.Contains(view, want) {
			t.Fatalf("expected dashboard footer to show %q\n%s", want, view)
		}
	}
}

func TestProcessesTabEnterAppliesSelectedProcessAsGlobalFilter(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 120
	m.height = 30

	stopped := false
	m.traceStop = func() { stopped = true }

	snap := statsengine.NewSnapshot(nil, nil, nil, nil, nil, []statsengine.ProcessSnapshot{
		{PID: 111, Comm: "alpha", Syscalls: 9},
		{PID: 222, Comm: "beta", Syscalls: 4},
	}, statsengine.HistogramSnapshot{}, statsengine.HistogramSnapshot{})

	next, _ := m.Update(messages.StatsTickMsg{Snap: &snap})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'5'}[0], Text: string([]rune{'5'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'j'}[0], Text: string([]rune{'j'})})
	m = next.(Model)

	next, cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected enter on processes tab to emit a filter request")
	}

	next, cmd = m.Update(cmd())
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected selected process filter to restart tracing")
	}
	if m.globalFilter.PID == nil || m.globalFilter.PID.Value != 222 {
		t.Fatalf("expected selected process pid applied globally, got %+v", m.globalFilter.PID)
	}
	if len(m.filterStack) != 1 || m.filterStack[0] != "pid=222" {
		t.Fatalf("expected pid filter pushed to stack, got %+v", m.filterStack)
	}
	if !stopped {
		t.Fatalf("expected selected process filter to stop the active trace")
	}
	if !m.attaching {
		t.Fatalf("expected selected process filter to restart tracing")
	}
}

func TestGlobalFilterApplyPreservesActiveDashboardTab(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(Model)
	if m.dashboard.ActiveTab() != dashboardui.TabFiles {
		t.Fatalf("expected files tab active before filter apply")
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("log")[0], Text: string([]rune("log"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if m.dashboard.ActiveTab() != dashboardui.TabFiles {
		t.Fatalf("expected active tab preserved across filter restart")
	}
	if !m.attaching {
		t.Fatalf("expected apply to enter attaching state")
	}
}

func TestGlobalFilterApplyResetsAggregatesAndFlameToPostRestartSources(t *testing.T) {
	m := NewModelWithConfig(flags.Config{PidFilter: -1, TidFilter: -1, TUIExportEnable: true}, -1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.width = 140
	m.height = 36

	oldSnap := aggregateTestSnapshot("write", "/tmp/old.log", "oldproc", "old-lat", "old-gap")
	newSnap := aggregateTestSnapshot("read", "/tmp/new.log", "newproc", "new-lat", "new-gap")
	oldTrie := aggregateTestTrie("oldsvc", "/srv/old")
	newTrie := aggregateTestTrie("newsvc", "/srv/new")

	m.runtime.SetDashboardSnapshotSource(fakeDashboardSource{snap: oldSnap})
	m.runtime.SetLiveTrie(oldTrie)

	next, _ := m.Update(TracingStartedMsg{})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{Snap: oldSnap})
	m = next.(Model)

	if label := advanceFlameSelection(t, &m); !strings.Contains(label, "oldsvc") {
		t.Fatalf("expected old flame data before filter apply, got %q", label)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'f'}[0], Text: string([]rune{'f'})})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: []rune("read")[0], Text: string([]rune("read"))})
	m = next.(Model)
	next, _ = m.Update(tea.KeyPressMsg{Code: tea.KeyEsc})
	m = next.(Model)

	if got := m.dashboard.LatestSnapshot(); got != nil {
		t.Fatalf("expected aggregate snapshot cleared during restart, got %+v", got)
	}
	if !m.attaching {
		t.Fatalf("expected filter apply to restart tracing")
	}

	m.runtime.SetDashboardSnapshotSource(fakeDashboardSource{snap: newSnap})
	m.runtime.SetLiveTrie(newTrie)

	next, _ = m.Update(TracingStartedMsg{})
	m = next.(Model)
	next, _ = m.Update(messages.StatsTickMsg{Snap: newSnap})
	m = next.(Model)

	if label := advanceFlameSelection(t, &m); !strings.Contains(label, "newsvc") || strings.Contains(label, "oldsvc") {
		t.Fatalf("expected flamegraph to reflect only new trie data, got %q", label)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	m = next.(Model)
	overview := m.View().Content
	for _, want := range []string{"read(1)", "/tmp/new.log(2)", "newproc/42(1)", "new-lat", "new-gap"} {
		if !strings.Contains(overview, want) {
			t.Fatalf("expected overview to contain %q, got %q", want, overview)
		}
	}
	for _, unwanted := range []string{"write", "/tmp/old.log", "oldproc", "old-lat", "old-gap"} {
		if strings.Contains(overview, unwanted) {
			t.Fatalf("expected overview to drop pre-filter data %q, got %q", unwanted, overview)
		}
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'3'}[0], Text: string([]rune{'3'})})
	m = next.(Model)
	if view := m.View().Content; !strings.Contains(view, "read") || strings.Contains(view, "write") {
		t.Fatalf("expected syscalls view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'4'}[0], Text: string([]rune{'4'})})
	m = next.(Model)
	if view := m.View().Content; !strings.Contains(view, "/tmp/new.log") || strings.Contains(view, "/tmp/old.log") {
		t.Fatalf("expected files view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'5'}[0], Text: string([]rune{'5'})})
	m = next.(Model)
	if view := m.View().Content; !strings.Contains(view, "newproc") || strings.Contains(view, "oldproc") {
		t.Fatalf("expected processes view to reflect post-filter snapshot only, got %q", view)
	}

	next, _ = m.Update(tea.KeyPressMsg{Code: []rune{'6'}[0], Text: string([]rune{'6'})})
	m = next.(Model)
	if view := m.View().Content; !strings.Contains(view, "new-lat") || !strings.Contains(view, "new-gap") || strings.Contains(view, "old-lat") || strings.Contains(view, "old-gap") {
		t.Fatalf("expected latency view to reflect post-filter histogram only, got %q", view)
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

func aggregateTestSnapshot(syscall, path, comm, latencyLabel, gapLabel string) *statsengine.Snapshot {
	snap := statsengine.NewSnapshot(
		[]float64{111},
		[]float64{222},
		[]float64{333},
		[]statsengine.SyscallSnapshot{{Name: syscall, Count: 1}},
		[]statsengine.FileSnapshot{{Path: path, Accesses: 2}},
		[]statsengine.ProcessSnapshot{{PID: 42, Comm: comm, Syscalls: 1}},
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{{Label: latencyLabel, Count: 1}}),
		statsengine.NewHistogramSnapshot(1, []statsengine.HistogramBucketSnapshot{{Label: gapLabel, Count: 1}}),
	)
	snap.TotalSyscalls = 1
	snap.TotalBytes = 64
	snap.LatencyMeanNs = 111
	snap.GapMeanNs = 222
	return &snap
}

func aggregateTestTrie(comm, path string) *coreflamegraph.LiveTrie {
	trie := coreflamegraph.NewLiveTrie([]string{"comm", "tracepoint", "path"}, "count")
	trie.AddRecord(coreflamegraph.IterRecord{
		Comm:    comm,
		Path:    path,
		Pid:     42,
		Tid:     42,
		TraceID: types.SYS_ENTER_READ,
		Cnt: coreflamegraph.Counter{
			Count:          5,
			Duration:       5_000,
			DurationToPrev: 500,
			Bytes:          128,
		},
	})
	return trie
}

func selectedFlameLabel(view string) string {
	re := regexp.MustCompile(`sel:[0-9]+/[0-9]+ ([^|]+) \|`)
	match := re.FindStringSubmatch(view)
	if len(match) != 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func advanceFlameSelection(t *testing.T, m *Model) string {
	t.Helper()

	before := selectedFlameLabel(m.View().Content)
	for i := 0; i < 8; i++ {
		next, _ := m.Update(tea.KeyPressMsg{Code: tea.KeyRight})
		*m = next.(Model)
		after := selectedFlameLabel(m.View().Content)
		if after != "" && after != before && after != "root" {
			return after
		}
	}
	return selectedFlameLabel(m.View().Content)
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
	if strings.Contains(out, "e stream export") {
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
	if !strings.Contains(out, "Flame: waiting for data") {
		t.Fatalf("expected flame waiting view by default")
	}

	next, _ := m.Update(tea.KeyPressMsg{Code: []rune{'2'}[0], Text: string([]rune{'2'})})
	updated := next.(Model)
	out = updated.View().Content
	if !strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected overview waiting view after pressing 2")
	}

	next, _ = updated.Update(tea.KeyPressMsg{Code: tea.KeyTab})
	updated = next.(Model)
	out = updated.View().Content
	if !strings.Contains(out, "Syscalls: waiting for stats") {
		t.Fatalf("expected syscalls waiting view after tab")
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
	if strings.Contains(out, "Flame: waiting for data") || strings.Contains(out, "Overview: waiting for stats") {
		t.Fatalf("expected probe modal to render as standalone view, got stacked dashboard content")
	}
}

func TestBlurPausesDashboardRefreshAndFocusResumesIt(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	m.screen = ScreenDashboard
	m.attaching = false
	m.dashboard = dashboardui.NewModelWithConfig(nil, nil, 1, m.keys)
	m.focused = true

	next, _ := m.Update(tea.BlurMsg{})
	m = next.(Model)
	if m.focused {
		t.Fatalf("expected focused=false after blur")
	}

	tickMsg := m.dashboard.Init()()
	next, tickCmd := m.Update(tickMsg)
	m = next.(Model)
	if tickCmd != nil {
		t.Fatalf("expected no follow-up tick command while blurred")
	}

	next, focusCmd := m.Update(tea.FocusMsg{})
	m = next.(Model)
	if !m.focused {
		t.Fatalf("expected focused=true after focus")
	}
	if focusCmd == nil {
		t.Fatalf("expected focus to resume refresh with a command batch")
	}
	if _, ok := focusCmd().(tea.BatchMsg); !ok {
		t.Fatalf("expected focus command to be a batch")
	}
}

func TestKeyboardEnhancementsMsgHandledGracefully(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	next, cmd := m.Update(tea.KeyboardEnhancementsMsg{Flags: 1})
	if cmd != nil {
		t.Fatalf("expected no command when handling keyboard enhancements msg")
	}

	updated := next.(Model)
	if !updated.keyboardEnhancementsKnown {
		t.Fatalf("expected keyboard enhancements to be marked as known")
	}
	if !updated.keyboardEnhancements.SupportsKeyDisambiguation() {
		t.Fatalf("expected non-zero flags to report key disambiguation support")
	}
}

func TestViewSetsDynamicWindowTitle(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })

	m.screen = ScreenPIDPicker
	view := m.View()
	if view.WindowTitle != "ior - select process" {
		t.Fatalf("unexpected picker window title: %q", view.WindowTitle)
	}

	m.screen = ScreenDashboard
	m.pidFilter = 1234
	view = m.View()
	if view.WindowTitle != "ior - tracing PID 1234" {
		t.Fatalf("unexpected tracing window title: %q", view.WindowTitle)
	}

	m.pidFilter = -1
	view = m.View()
	if view.WindowTitle != "ior - I/O Riot" {
		t.Fatalf("unexpected default window title: %q", view.WindowTitle)
	}
}

func TestAltScreenViewEnablesMouseCellMotion(t *testing.T) {
	view := altScreenView("test", "ior")
	if view.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("expected mouse mode cell motion, got %v", view.MouseMode)
	}
}

func TestRenderHelpOverlayUsesWideViewport(t *testing.T) {
	groups := [][]key.Binding{{key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help"))}}
	out := renderHelpOverlay(160, 40, groups)

	maxWidth := 0
	for _, line := range strings.Split(out, "\n") {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}

	if maxWidth <= 110 {
		t.Fatalf("expected wide help overlay to exceed previous 110-col cap, got %d", maxWidth)
	}
}

func TestGlobalHelpOverlayFitsStandardTerminal(t *testing.T) {
	m := NewModel(-1, func(context.Context) error { return nil })
	out := renderGlobalHelpOverlay(80, 24, m.helpSections())

	lines := strings.Split(out, "\n")
	if len(lines) > 24 {
		t.Fatalf("expected help overlay to fit within 24 lines, got %d", len(lines))
	}

	maxWidth := 0
	for _, line := range lines {
		if w := lipgloss.Width(line); w > maxWidth {
			maxWidth = w
		}
	}
	if maxWidth > 80 {
		t.Fatalf("expected help overlay width <= 80, got %d", maxWidth)
	}
	if !strings.Contains(out, "Dashboard Tabs") {
		t.Fatalf("expected overlay to include dashboard help section")
	}
	if !strings.Contains(out, "v bubbles") || !strings.Contains(out, "b metric") {
		t.Fatalf("expected overlay to include bubble dashboard hotkeys")
	}
}
