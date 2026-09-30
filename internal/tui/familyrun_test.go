package tui

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"ior/internal/tui/probes"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

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
// hint says "press o, tab, space", and the modal used to open with the
// Families cursor on the first family (Network), so following it attached
// Network instead of the scoped family. Time is not the first family.
func TestFollowingTheFamilyHintAttachesThatFamily(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	manager := newSelectionManager()
	m.runtime.setProbeManager(manager)
	m = cycleTo(t, m, "Time")
	if !strings.Contains(m.View().Content, "Time not traced: press o, tab, space") {
		t.Fatal("precondition: expected the Time hint")
	}

	m, _ = pressKey(m, tea.KeyPressMsg{Code: '2', Text: "2"}) // leave the flame tab, where o orders frames
	m, _ = pressKey(m, tea.KeyPressMsg{Code: 'o', Text: "o"})
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
	if !strings.Contains(m.probeModal.View(100, 40), "trace restarted") {
		t.Fatalf("outcome does not mention the restart:\n%s", m.probeModal.View(100, 40))
	}
}

// TestFamilyBatchResultReadsBackTheManager is the non-restart counterpart:
// the selection becomes what the manager actually has attached.
func TestFamilyBatchResultReadsBackTheManager(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	manager := newSelectionManager()
	m.runtime.setProbeManager(manager)
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
	m, _ := newLiveSwapModel(t)
	m.runtime.setProbeManager(newSelectionManager())
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
	m, _ := newLiveSwapModel(t)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	manager := newSelectionManager()
	manager.hold = make(chan struct{})
	m.runtime.setProbeManager(manager)

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
	m, _ := newLiveSwapModel(t)
	m.tracer.beginCmd(m.runtime, m.filters.current())
	t.Cleanup(m.tracer.stop)
	manager := newSelectionManager()
	manager.hold = make(chan struct{})
	m.runtime.setProbeManager(manager)
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
		{"bulk is absolute", []string{"connect"},
			probes.ProbeToggledMsg{Intent: []string{}},
			[]string{}},
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
