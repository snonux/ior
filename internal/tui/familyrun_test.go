package tui

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	dashboardui "ior/internal/tui/dashboard"
	"ior/internal/tui/probes"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// newSessionModel returns a dashboard model with a running trace session
// (its starter is never run) that has published manager - as in production,
// where a probe manager only exists within a session and a family batch runs
// on that session's context. The live-filter setter is published again,
// since beginning the session dropped it.
func newSessionModel(t *testing.T, manager *selectionProbeManager) *Model {
	t.Helper()
	m, recorder := newLiveSwapModel(t)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	m.runtime.setLiveFilterSetter(recorder.set)
	m.runtime.setProbeManager(manager)
	return m
}

// runCmdFor runs cmd - flattening tea.Batch - and returns the first message
// of type T it yields.
func runCmdFor[T tea.Msg](t *testing.T, cmd tea.Cmd) T {
	t.Helper()
	var zero T
	if cmd == nil {
		t.Fatalf("no command, want one yielding %T", zero)
	}
	switch msg := cmd().(type) {
	case T:
		return msg
	case tea.BatchMsg:
		for _, sub := range msg {
			if sub == nil {
				continue
			}
			if found, ok := sub().(T); ok {
				return found
			}
		}
	}
	t.Fatalf("command yielded no %T", zero)
	return zero
}

// finishFamilyBatch feeds the batch chain started by cmd through Update until
// the model has handled its FamilyToggledMsg.
func finishFamilyBatch(t *testing.T, m *Model, cmd tea.Cmd) *Model {
	t.Helper()
	for range 100 {
		if cmd == nil {
			t.Fatal("family batch chain ended without a result")
		}
		msg := cmd()
		next, nextCmd := m.Update(msg)
		m = next.(*Model)
		if _, done := msg.(probes.FamilyToggledMsg); done {
			return m
		}
		cmd = nextCmd
	}
	t.Fatal("family batch did not finish")
	return m
}

func pressKey(m *Model, key tea.KeyPressMsg) (*Model, tea.Cmd) {
	next, cmd := m.Update(key)
	return next.(*Model), cmd
}

// TestFollowingTheFamilyHintAttachesThatFamily is the review regression: the
// hint says "press O, tab, space", and the modal used to open with the
// Families cursor on the first family (Network), so following it attached
// Network instead of the scoped family. Time is not the first family.
//
// The test follows the hint literally from the Flame tab, the tab users land
// on: there lowercase o is the flamegraph's frame-order key, which is why the
// hint names capital O (see TestFamilyHintKeyOpensProbesOnEveryTab).
func TestFollowingTheFamilyHintAttachesThatFamily(t *testing.T) {
	m := newSessionModel(t, newSelectionManager())
	m = cycleTo(t, m, "Time")
	if !strings.Contains(m.View().Content, "Time not traced: press O, tab, space") {
		t.Fatal("precondition: expected the Time hint")
	}

	if m.dashboard.ActiveTab() != dashboardui.TabFlame {
		t.Fatalf("precondition: expected the Flame tab, got %v", m.dashboard.ActiveTab())
	}
	m, _ = pressKey(m, tea.KeyPressMsg{Code: 'O', Text: "O"}) // the hint's key, pressed on the Flame tab
	m, _ = pressKey(m, tea.KeyPressMsg{Code: tea.KeyTab})
	m, cmd := pressKey(m, tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	req := runCmdFor[probes.FamilyBatchRequestMsg](t, cmd)
	if req.Family != types.FamilyTime || !req.Attach {
		t.Fatalf("request = %+v, want attach Time", req)
	}

	next, cmd := m.Update(req)
	m = finishFamilyBatch(t, next.(*Model), cmd)
	if !slices.Contains(m.tracer.attachSyscalls, "nanosleep") {
		t.Fatalf("attachSyscalls = %v, want nanosleep attached", m.tracer.attachSyscalls)
	}
	if strings.Contains(m.View().Content, "not traced") {
		t.Fatal("hint still shown after attaching Time")
	}
}

// TestFamilyHintKeyOpensProbesOnEveryTab pins why the family hint says
// "press O": capital O opens the probes modal on all seven dashboard tabs,
// while lowercase o only does so off the Flame tab, where the flamegraph
// consumes it as its frame-order key. Were O ever shadowed by a tab, the hint
// would silently do nothing there again.
func TestFamilyHintKeyOpensProbesOnEveryTab(t *testing.T) {
	for _, tabKey := range "1234567" {
		for _, tc := range []struct {
			key      rune
			wantOpen bool
		}{
			{'O', true},
			{'o', tabKey != '1'}, // Flame (tab 1) keeps lowercase o for itself
		} {
			m := newSessionModel(t, newSelectionManager())
			m, _ = pressKey(m, tea.KeyPressMsg{Code: tabKey, Text: string(tabKey)})
			m, _ = pressKey(m, tea.KeyPressMsg{Code: tc.key, Text: string(tc.key)})
			if got := m.probeModal.Visible(); got != tc.wantOpen {
				t.Errorf("tab %c, key %q: probes modal visible = %v, want %v", tabKey, tc.key, got, tc.wantOpen)
			}
		}
	}
}

// TestCapitalOInTextInputsDoesNotOpenProbes: the probes binding matches the
// capital O, so typing it into the Flame search box or the filter modal (both
// text inputs) must stay text and must not pop the probes modal open.
func TestCapitalOInTextInputsDoesNotOpenProbes(t *testing.T) {
	t.Run("flame search", func(t *testing.T) {
		m := newSessionModel(t, newSelectionManager())
		m.width, m.height = 120, 30
		m, _ = pressKey(m, tea.KeyPressMsg{Code: '/', Text: "/"})
		if !strings.Contains(m.View().Content, "0/0 matches") {
			t.Fatal("precondition: flame search footer should be open")
		}
		m, _ = pressKey(m, tea.KeyPressMsg{Code: 'O', Text: "O"})
		if m.probeModal.Visible() {
			t.Fatal("O typed into the flame search opened the probes modal")
		}
		if !strings.Contains(m.View().Content, "0/0 matches") {
			t.Fatal("flame search closed after typing O")
		}
	})
	t.Run("filter modal", func(t *testing.T) {
		m := newSessionModel(t, newSelectionManager())
		m, _ = pressKey(m, tea.KeyPressMsg{Code: 'f', Text: "f"})
		if !m.filterModal.Visible() {
			t.Fatal("precondition: filter modal should be open")
		}
		m, _ = pressKey(m, tea.KeyPressMsg{Code: 'O', Text: "O"})
		if m.probeModal.Visible() {
			t.Fatal("O typed into the filter modal opened the probes modal")
		}
		if !m.filterModal.Visible() {
			t.Fatal("filter modal closed after typing O")
		}
	})
}

// TestFamilyBatchOverlappingARestartKeepsItsIntent: the batch works on the
// old session's manager while a restart starts the next session. The intended
// set is recorded when the batch starts, so the restart carries it, and the
// late result must not overwrite it with the new session's manager state.
func TestFamilyBatchOverlappingARestartKeepsItsIntent(t *testing.T) {
	requests := make(chan TraceRequest, 4)
	m := NewModel(-1, func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(m.tracer.stop)
	m.beginTraceCmd()()
	<-requests
	m.runtime.setProbeManager(newSelectionManager())
	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()

	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)
	want := []string{"connect", "read", "socket"}
	m.beginTraceCmd()() // restart before the batch reports back
	if req := <-requests; !slices.Equal(req.AttachSyscalls, want) {
		t.Fatalf("restart AttachSyscalls = %v, want the batch's intent %v", req.AttachSyscalls, want)
	}
	m.runtime.setProbeManager(newSelectionManager()) // new session: Network not attached (yet)

	m = finishFamilyBatch(t, m, cmd)
	if !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want the intent %v kept", m.tracer.attachSyscalls, want)
	}
	view := m.probeModal.View(100, 40)
	if !strings.Contains(view, "trace restarted") {
		t.Fatalf("outcome does not mention the restart:\n%s", view)
	}
	if strings.Contains(view, "context canceled") || !strings.Contains(view, "batch cancelled") {
		t.Fatalf("want the cancellation as a note, not an error:\n%s", view)
	}
}

// TestFamilyBatchFinishedBeforeRestartIsNotCalledCancelled: a batch that
// walked every probe just before its session ended was not cancelled, so its
// late outcome notes the restart but must not claim a cancellation.
func TestFamilyBatchFinishedBeforeRestartIsNotCalledCancelled(t *testing.T) {
	m := newSessionModel(t, newSelectionManager())
	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)
	msg := cmd()
	for {
		progress, ok := msg.(probes.FamilyBatchProgressMsg)
		if !ok {
			break
		}
		msg = progress.Next()()
	}
	result, ok := msg.(probes.FamilyToggledMsg)
	if !ok || result.Err != nil || result.Result.Changed != 2 {
		t.Fatalf("batch result = %#v, want a complete uncancelled attach", msg)
	}

	m.beginTraceCmd() // the session ends before the result is handled
	next, _ = m.Update(result)
	m = next.(*Model)
	view := m.probeModal.View(100, 40)
	if !strings.Contains(view, "trace restarted") || strings.Contains(view, "cancelled") {
		t.Fatalf("want the restart noted without a cancellation:\n%s", view)
	}
	if want := []string{"connect", "read", "socket"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want the intent %v", m.tracer.attachSyscalls, want)
	}
}

// TestFamilyBatchResultReadsBackTheManager is the non-restart counterpart:
// the selection becomes what the manager actually has attached.
func TestFamilyBatchResultReadsBackTheManager(t *testing.T) {
	m := newSessionModel(t, newSelectionManager())
	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyFS, Attach: false})
	m = finishFamilyBatch(t, next.(*Model), cmd)
	if m.tracer.attachSyscalls == nil || len(m.tracer.attachSyscalls) != 0 {
		t.Fatalf("attachSyscalls = %#v, want empty after detaching FS", m.tracer.attachSyscalls)
	}
}

// TestOnlyOneFamilyBatchRunsAcrossModalRebuilds: the guard and the progress
// live in the model, so reopening the modal (a fresh probes.Model) neither
// forgets the running batch nor allows a second one, and messages of any
// other run are ignored.
func TestOnlyOneFamilyBatchRunsAcrossModalRebuilds(t *testing.T) {
	m := newSessionModel(t, newSelectionManager())
	next, first := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)

	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	if view := m.probeModal.View(100, 40); !strings.Contains(view, "attaching Network") {
		t.Fatalf("rebuilt modal does not show the running batch:\n%s", view)
	}
	next, second := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyTime, Attach: true})
	m = next.(*Model)
	if second != nil {
		t.Fatal("a second family batch started while one was running")
	}
	if view := m.probeModal.View(100, 40); !strings.Contains(view, "already running") {
		t.Fatalf("refusal not shown:\n%s", view)
	}

	next, _ = m.Update(probes.FamilyToggledMsg{Run: m.familyRun.seq + 1})
	m = next.(*Model)
	if _, cmd := m.Update(probes.FamilyBatchProgressMsg{Run: m.familyRun.seq + 1}); !m.familyRun.active || cmd != nil {
		t.Fatal("a message of another run ended or continued the running batch")
	}

	m = finishFamilyBatch(t, m, first)
	if m.familyRun.active {
		t.Fatal("batch still in flight after its result")
	}
	if _, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyTime, Attach: true}); cmd == nil {
		t.Fatal("a new batch was refused after the previous one finished")
	}
}

// TestFamilyBatchWithoutManagerIsRefused: no manager published (the trace is
// still attaching) means no batch and no run left in flight.
func TestFamilyBatchWithoutManagerIsRefused(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyFS, Attach: true})
	m = next.(*Model)
	if cmd != nil || m.familyRun.active {
		t.Fatal("a batch started without a probe manager")
	}
	if !strings.Contains(m.probeModal.View(100, 40), "probe manager unavailable") {
		t.Fatal("missing manager not reported")
	}
}

// TestSingleToggleDuringFamilyBatchKeepsTheBatchIntent is the review 2
// regression: a probe change finishing while a family batch is half done
// used to read back the half-done set, so a restart then carried only part
// of the family. The batch's intent must be applied on top of the read-back.
// The modal now refuses new changes during a batch, but one already in flight
// when the batch started (an all-on/all-off walks every probe) still lands.
func TestSingleToggleDuringFamilyBatchKeepsTheBatchIntent(t *testing.T) {
	manager := newSelectionManager()
	manager.hold = make(chan struct{})
	m := newSessionModel(t, manager)

	next, batch := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)
	done := make(chan tea.Msg, 1)
	go func() { done <- batch() }() // starts the batch; blocks on hold after connect
	waitActive(t, manager, "connect")

	manager.setActive("nanosleep", true) // the single toggle, current session
	next, _ = m.Update(probes.ProbeToggledMsg{Syscall: "nanosleep", Session: m.tracer.session})
	m = next.(*Model)
	want := []string{"connect", "nanosleep", "read", "socket"}
	if !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want %v (batch intent plus the toggle)", m.tracer.attachSyscalls, want)
	}

	close(manager.hold)
	first := <-done
	m = finishFamilyBatch(t, m, func() tea.Msg { return first })
	if !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("after the batch attachSyscalls = %v, want %v", m.tracer.attachSyscalls, want)
	}
}

// TestSingleToggleResultAfterRestartKeepsItsIntent: a toggle whose result
// arrives after a restart toggled the old session's manager; reading back the
// new session's manager would lose it, so its intent is kept instead.
func TestSingleToggleResultAfterRestartKeepsItsIntent(t *testing.T) {
	requests := make(chan TraceRequest, 4)
	m := NewModel(-1, func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(m.tracer.stop)
	m.beginTraceCmd()()
	<-requests
	m.runtime.setProbeManager(newSelectionManager())

	// Toggle socket (4th row: connect, nanosleep, read, socket) in the modal.
	modal := m.newProbeModal().SetSize(100, 40).Open()
	for range 3 {
		modal, _ = modal.Update(tea.KeyPressMsg{Code: 'j', Text: "j"})
	}
	_, toggle := modal.Update(tea.KeyPressMsg{Code: tea.KeySpace, Text: " "})
	result := runCmdFor[probes.ProbeToggledMsg](t, toggle)

	m.beginTraceCmd()() // restart before the result is handled
	<-requests
	m.runtime.setProbeManager(newSelectionManager()) // new session: socket detached
	next, _ := m.Update(result)
	m = next.(*Model)
	if want := []string{"read", "socket"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want the toggle's intent %v", m.tracer.attachSyscalls, want)
	}
}

// waitActive waits until syscall is active in manager.
func waitActive(t *testing.T, manager *selectionProbeManager, syscall string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, state := range manager.States() {
			if state.Syscall == syscall && state.Active {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("%s never became active", syscall)
}

// TestProbeChangesRefusedWhileFamilyBatchRuns drives the TUI: while a batch
// is held half done, space, a and n in a freshly opened modal start no probe
// change and the modal says why.
func TestProbeChangesRefusedWhileFamilyBatchRuns(t *testing.T) {
	manager := newSelectionManager()
	manager.hold = make(chan struct{})
	m := newSessionModel(t, manager)
	next, batch := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)
	done := make(chan tea.Msg, 1)
	go func() { done <- batch() }()
	waitActive(t, manager, "connect")

	m, _ = pressKey(m, tea.KeyPressMsg{Code: '2', Text: "2"})
	m, _ = pressKey(m, tea.KeyPressMsg{Code: 'o', Text: "o"})
	before := manager.States()
	for _, key := range []tea.KeyPressMsg{{Code: tea.KeySpace, Text: " "}, {Code: 'a', Text: "a"}, {Code: 'n', Text: "n"}} {
		var cmd tea.Cmd
		m, cmd = pressKey(m, key)
		if cmd != nil {
			if _, toggled := cmd().(probes.ProbeToggledMsg); toggled {
				t.Fatalf("key %q changed probes during a family batch", key.String())
			}
		}
	}
	if !slices.Equal(manager.States(), before) {
		t.Fatalf("probe states changed during the batch: %v -> %v", before, manager.States())
	}
	if !strings.Contains(m.View().Content, "family batch running") {
		t.Fatalf("refusal not shown:\n%s", m.View().Content)
	}
	close(manager.hold)
	first := <-done
	finishFamilyBatch(t, m, func() tea.Msg { return first })
}

// TestStaleSingleToggleAppliesOnlyItsDelta: a single toggle whose result
// arrives after its session ended changes only its own probe in the recorded
// selection; its absolute intent (a snapshot of the old manager) must not
// clobber what was recorded since, e.g. a family batch's intent.
func TestStaleSingleToggleAppliesOnlyItsDelta(t *testing.T) {
	tests := []struct {
		name      string
		recorded  []string
		msg       probes.ProbeToggledMsg
		wantAfter []string
	}{
		{"attach adds", []string{"connect", "read", "socket"},
			probes.ProbeToggledMsg{Syscall: "nanosleep", Intent: []string{"nanosleep", "read"}},
			[]string{"connect", "nanosleep", "read", "socket"}},
		{"detach removes", []string{"connect", "read", "socket"},
			probes.ProbeToggledMsg{Syscall: "read", Intent: []string{}},
			[]string{"connect", "socket"}},
		{"nothing recorded takes the intent", nil,
			probes.ProbeToggledMsg{Syscall: "read", Intent: []string{"read"}},
			[]string{"read"}},
		{"bulk result changes nothing (its intent was recorded at the key press)", []string{"connect"},
			probes.ProbeToggledMsg{Intent: []string{}},
			[]string{"connect"}},
		{"toggle that never ran changes nothing", []string{"connect"},
			probes.ProbeToggledMsg{Syscall: "read"},
			[]string{"connect"}},
	}
	for _, tt := range tests {
		m, _ := newLiveSwapModel(t) // no session running: every result is stale
		m.tracer.setAttachSyscalls(tt.recorded)
		next, _ := m.Update(tt.msg)
		if got := next.(*Model).tracer.attachSyscalls; !slices.Equal(got, tt.wantAfter) || (got == nil) != (tt.wantAfter == nil) {
			t.Errorf("%s: selection = %#v, want %#v", tt.name, got, tt.wantAfter)
		}
	}
}

// startHeldBatch starts attaching Network through m with manager held after
// its first probe (connect), and returns the channel that yields the batch
// command's first message.
func startHeldBatch(t *testing.T, m *Model, manager *selectionProbeManager) (*Model, <-chan tea.Msg) {
	t.Helper()
	next, batch := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	done := make(chan tea.Msg, 1)
	go func() { done <- batch() }()
	waitActive(t, manager, "connect")
	return next.(*Model), done
}

// receiveWithin returns the next message of ch, failing after a second.
func receiveWithin(t *testing.T, ch <-chan tea.Msg) tea.Msg {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(time.Second):
		t.Fatal("the family batch did not stop promptly")
		return nil
	}
}

// TestRestartCancelsTheFamilyBatch is the lp2 regression: a batch held half
// done on the old session's manager used to keep going (here: stay blocked)
// until it had walked the whole family. Restarting the trace cancels it, so
// it returns at once, leaves the rest of the family on the dying manager
// alone, and its goroutine is gone. The intent recorded at start is kept.
func TestRestartCancelsTheFamilyBatch(t *testing.T) {
	old := newSelectionManager()
	old.hold = make(chan struct{}) // never closed: only cancellation ends the hold
	m := newSessionModel(t, old)
	m, done := startHeldBatch(t, m, old)

	m.beginTraceCmd() // restart
	msg := receiveWithin(t, done)
	if old.inFlight.Load() != 0 {
		t.Fatal("the cancelled batch is still running")
	}
	for _, state := range old.States() {
		if state.Syscall == "socket" && state.Active {
			t.Fatal("the cancelled batch attached socket after the restart")
		}
	}
	m = finishFamilyBatch(t, m, func() tea.Msg { return msg })
	if want := []string{"connect", "read", "socket"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want the intent %v", m.tracer.attachSyscalls, want)
	}
	if m.familyRun.active {
		t.Fatal("the cancelled run is still in flight after its result")
	}
}

// TestNewSessionStartsAFamilyBatchBeforeTheStaleResult: the stale run must
// not hold up the next session, neither the family batch guard nor the
// Syscalls view; its late result is then ignored and does not disturb the
// new run or the recorded intent.
func TestNewSessionStartsAFamilyBatchBeforeTheStaleResult(t *testing.T) {
	old := newSelectionManager()
	old.hold = make(chan struct{})
	m := newSessionModel(t, old)
	m, done := startHeldBatch(t, m, old)

	m.beginTraceCmd() // restart; the stale result is not handled yet
	current := newSelectionManager()
	current.setActive("connect", true) // the new session attached the intent
	current.setActive("socket", true)
	m.runtime.setProbeManager(current)
	if view := m.newProbeModal().SetSize(100, 40).Open().View(100, 40); strings.Contains(view, "attaching Network") {
		t.Fatalf("the new session's modal replays the stale run:\n%s", view)
	}
	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyTime, Attach: true})
	m = next.(*Model)
	if cmd == nil {
		t.Fatal("the new session's family batch was refused")
	}
	want := []string{"connect", "nanosleep", "read", "socket"} // Network intent + Time
	if !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("attachSyscalls = %v, want %v", m.tracer.attachSyscalls, want)
	}

	stale := receiveWithin(t, done) // the stale run's first message, then its result
	for range 10 {
		next, staleCmd := m.Update(stale)
		m = next.(*Model)
		if _, isResult := stale.(probes.FamilyToggledMsg); isResult || staleCmd == nil {
			break
		}
		stale = staleCmd()
	}
	if !m.familyBatchRunning() {
		t.Fatal("the stale result ended the new session's batch")
	}
	m = finishFamilyBatch(t, m, cmd)
	if !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("after the new batch attachSyscalls = %v, want %v", m.tracer.attachSyscalls, want)
	}
	if old.inFlight.Load() != 0 {
		t.Fatal("the stale batch is still running")
	}
}

// TestFamilyBatchWithoutRunningSessionChangesNothing: with no session (never
// the case in production, where no manager is published then) a batch has no
// session context to run on and must not touch the manager.
func TestFamilyBatchWithoutRunningSessionChangesNothing(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	manager := newSelectionManager()
	m.runtime.setProbeManager(manager)
	before := manager.States()
	next, cmd := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	finishFamilyBatch(t, next.(*Model), cmd)
	if !slices.Equal(manager.States(), before) {
		t.Fatalf("probe states changed without a session: %v -> %v", before, manager.States())
	}
}
