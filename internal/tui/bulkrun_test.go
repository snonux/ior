package tui

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ior/internal/tui/probes"
	"ior/internal/types"

	tea "charm.land/bubbletea/v2"
)

// gatedBulkManager is a selectionProbeManager whose Attach and Detach announce
// the syscall on entered and then wait until release is closed, so a test can
// restart the trace while an all-on/all-off walk is half done.
type gatedBulkManager struct {
	*selectionProbeManager
	entered chan string
	release chan struct{}
}

func newGatedBulkManager() *gatedBulkManager {
	return &gatedBulkManager{
		selectionProbeManager: newSelectionManager(),
		entered:               make(chan string, 16),
		release:               make(chan struct{}),
	}
}

func (g *gatedBulkManager) Attach(syscall string) error {
	g.entered <- syscall
	<-g.release
	return g.selectionProbeManager.Attach(syscall)
}

func (g *gatedBulkManager) Detach(syscall string) error {
	g.entered <- syscall
	<-g.release
	return g.selectionProbeManager.Detach(syscall)
}

// pressBulkKey opens the probes modal on m and presses key (a or n) in it,
// then feeds the modal's request through Update like the program would. It
// returns the model and the command that runs the walk (nil if refused).
func pressBulkKey(t *testing.T, m *Model, key rune) (*Model, tea.Cmd) {
	t.Helper()
	if !m.probeModal.Visible() {
		m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	}
	var cmd tea.Cmd
	m, cmd = pressKey(m, tea.KeyPressMsg{Code: key, Text: string(key)})
	request := runCmdFor[probes.SetAllRequestMsg](t, cmd)
	next, walk := m.Update(request)
	return next.(*Model), walk
}

// runAsync runs cmd on its own goroutine and returns the channel of its
// result, for a walk that blocks on a gated manager.
func runAsync(cmd tea.Cmd) <-chan tea.Msg {
	done := make(chan tea.Msg, 1)
	go func() { done <- cmd() }()
	return done
}

// TestBulkIntentIsRecordedAtKeyPress is the wp2 regression for the late
// intent: 'n' walks every probe (seconds on a real manager), and a restart
// meanwhile used to start the next session with the old selection, recording
// the intent only when the result arrived - so a later restart attached
// nothing without any user action in between. The intent now counts from the
// key press, and the late result changes nothing.
func TestBulkIntentIsRecordedAtKeyPress(t *testing.T) {
	old := newGatedBulkManager()
	m := newSessionModel(t, old.selectionProbeManager) // plain manager for the setup
	m.runtime.setProbeManager(old)
	m.tracer.setAttachSyscalls([]string{"connect", "read", "socket"})

	m, walk := pressBulkKey(t, m, 'n')
	if m.tracer.attachSyscalls == nil || len(m.tracer.attachSyscalls) != 0 {
		t.Fatalf("selection at key press = %#v, want the all-off intent []", m.tracer.attachSyscalls)
	}
	done := runAsync(walk)
	<-old.entered // the walk is on its first probe

	m.beginTraceCmd() // restart: the next session starts with the intent
	if got := m.tracer.attachSyscalls; got == nil || len(got) != 0 {
		t.Fatalf("restart selection = %#v, want the all-off intent", got)
	}
	m.runtime.setProbeManager(newSelectionManager())
	m.tracer.setAttachSyscalls([]string{"read"}) // what the user picked in the new session

	close(old.release)
	stale := receiveWithin(t, done)
	next, _ := m.Update(stale)
	m = next.(*Model)
	if want := []string{"read"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("the stale walk result changed the selection to %v, want %v", m.tracer.attachSyscalls, want)
	}
}

// TestBulkAllOnIntentSurvivesARestart: the same for 'a', checked through the
// TraceRequest the restart actually sends, which used to carry the old
// selection (nil: the startup -trace-* flags).
func TestBulkAllOnIntentSurvivesARestart(t *testing.T) {
	requests := make(chan TraceRequest, 4)
	m := NewModel(-1, func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(m.tracer.stop)
	m.beginTraceCmd()()
	<-requests
	old := newGatedBulkManager()
	m.runtime.setProbeManager(old)

	m, walk := pressBulkKey(t, m, 'a')
	done := runAsync(walk)
	<-old.entered

	m.beginTraceCmd()() // restart before the walk finishes
	want := []string{"connect", "nanosleep", "read", "socket"}
	if req := <-requests; !slices.Equal(req.AttachSyscalls, want) {
		t.Fatalf("restart AttachSyscalls = %v, want every probe %v", req.AttachSyscalls, want)
	}
	close(old.release)
	receiveWithin(t, done)
}

// TestBulkWalkStopsWhenItsSessionEnds is the wp2 regression for the dying
// manager: the walk used to go on attaching every remaining probe to the
// manager of the session that had just ended. It runs on the session's
// context now, so after the restart it finishes the probe it is on and stops.
func TestBulkWalkStopsWhenItsSessionEnds(t *testing.T) {
	old := newGatedBulkManager()
	m := newSessionModel(t, old.selectionProbeManager)
	m.runtime.setProbeManager(old)

	m, walk := pressBulkKey(t, m, 'a')
	done := runAsync(walk)
	if first := <-old.entered; first != "connect" {
		t.Fatalf("walk started with %q, want connect", first)
	}
	m.beginTraceCmd() // the session ends while connect is being attached
	close(old.release)

	toggled, ok := receiveWithin(t, done).(probes.ProbeToggledMsg)
	if !ok || !errors.Is(toggled.Err, context.Canceled) {
		t.Fatalf("walk result = %#v, want the cancellation", toggled)
	}
	for _, state := range old.States() {
		if (state.Syscall == "nanosleep" || state.Syscall == "socket") && state.Active {
			t.Fatalf("%s was attached to the old manager after the restart", state.Syscall)
		}
	}
	if len(old.entered) != 0 {
		t.Fatalf("the walk went on to another probe: %d more", len(old.entered))
	}
}

// TestStaleToggleErrorStaysOutOfTheNewSessionsModal is the wp2 regression for
// the stale error: a result of the ended session ("probe manager is closed")
// used to be forwarded to the probes modal before the session check, showing
// the dead manager's error in the new session's modal. Single and bulk alike.
func TestStaleToggleErrorStaysOutOfTheNewSessionsModal(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  func(old uint64) probes.ProbeToggledMsg
	}{
		{"single", func(old uint64) probes.ProbeToggledMsg {
			return probes.ProbeToggledMsg{Syscall: "read", Session: old, Err: errors.New("probe manager is closed")}
		}},
		{"bulk", func(old uint64) probes.ProbeToggledMsg {
			return probes.ProbeToggledMsg{Session: old, Err: errors.New("probe manager is closed")}
		}},
	} {
		m := newSessionModel(t, newSelectionManager())
		stale := tc.msg(m.tracer.session)
		m.beginTraceCmd() // restart
		m.runtime.setProbeManager(newSelectionManager())
		m.probeModal = m.newProbeModal().SetSize(100, 40).Open()

		next, _ := m.Update(stale)
		m = next.(*Model)
		if view := m.probeModal.View(100, 40); strings.Contains(view, "Error") || strings.Contains(view, "closed") {
			t.Errorf("%s: the stale error reached the new session's modal:\n%s", tc.name, view)
		}
	}
}

// TestCurrentBulkResultShowsItsErrorAndReadsBack: within the session the
// result is shown and the selection becomes what the manager really has.
func TestCurrentBulkResultShowsItsErrorAndReadsBack(t *testing.T) {
	manager := newSelectionManager()
	m := newSessionModel(t, manager)
	m, walk := pressBulkKey(t, m, 'a')
	result := runCmdFor[probes.ProbeToggledMsg](t, walk)
	if result.Session != m.tracer.session {
		t.Fatalf("result session = %d, want %d", result.Session, m.tracer.session)
	}
	manager.setActive("socket", false) // e.g. its tracepoint turned out missing
	result.Err = errors.New("socket: no such tracepoint")

	next, _ := m.Update(result)
	m = next.(*Model)
	if want := []string{"connect", "nanosleep", "read"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("selection = %v, want the read-back %v", m.tracer.attachSyscalls, want)
	}
	if view := m.probeModal.View(100, 40); !strings.Contains(view, "no such tracepoint") {
		t.Fatalf("the current result's error is not shown:\n%s", view)
	}
	if m.bulkRunning() {
		t.Fatal("the walk is still in flight after its result")
	}
}

// TestBulkRefusedWhileAnotherChangeRuns: one walk per session at a time, and
// neither a walk during a family batch nor a batch during a walk (the manager
// is half done, so the intent of the second could not be derived). A new
// session is not held up by the old walk.
func TestBulkRefusedWhileAnotherChangeRuns(t *testing.T) {
	old := newGatedBulkManager()
	m := newSessionModel(t, old.selectionProbeManager)
	m.runtime.setProbeManager(old)

	m, walk := pressBulkKey(t, m, 'a')
	done := runAsync(walk)
	<-old.entered

	if _, second := m.Update(probes.SetAllRequestMsg{Active: false}); second != nil {
		t.Fatal("a second walk started while one was running")
	}
	if view := m.probeModal.View(100, 40); !strings.Contains(view, "all-on/all-off running") {
		t.Fatalf("refusal not shown:\n%s", view)
	}
	if _, batch := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyTime, Attach: true}); batch != nil {
		t.Fatal("a family batch started during a walk")
	}
	if want := []string{"connect", "nanosleep", "read", "socket"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("a refused request changed the selection to %v", m.tracer.attachSyscalls)
	}

	m.beginTraceCmd() // restart: the old walk no longer holds anything up
	m.runtime.setProbeManager(newSelectionManager())
	if _, fresh := m.Update(probes.SetAllRequestMsg{Active: false}); fresh == nil {
		t.Fatal("the new session's walk was refused")
	}
	close(old.release)
	receiveWithin(t, done)
}

// TestBulkRefusedWhileFamilyBatchRunsAtTheModel: the model refuses a walk
// request during a family batch of the session even when the modal let the
// key through (a modal rebuilt from a stale request).
func TestBulkRefusedWhileFamilyBatchRunsAtTheModel(t *testing.T) {
	m := newSessionModel(t, newSelectionManager())
	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	next, _ := m.Update(probes.FamilyBatchRequestMsg{Family: types.FamilyNetwork, Attach: true})
	m = next.(*Model)
	before := slices.Clone(m.tracer.attachSyscalls)

	next, cmd := m.Update(probes.SetAllRequestMsg{Active: false})
	m = next.(*Model)
	if cmd != nil || m.bulkRunning() || !slices.Equal(m.tracer.attachSyscalls, before) {
		t.Fatal("a walk started during a family batch")
	}
}

// TestBulkWithoutManagerIsRefused: no probe manager (attaching, or the session
// just ended) means no walk and an error in the modal, as before.
func TestBulkWithoutManagerIsRefused(t *testing.T) {
	m, _ := newLiveSwapModel(t)
	m.probeModal = m.newProbeModal().SetSize(100, 40).Open()
	m.tracer.setAttachSyscalls([]string{"read"})
	next, cmd := m.Update(probes.SetAllRequestMsg{Active: true})
	m = next.(*Model)
	if cmd != nil || m.bulkRunning() {
		t.Fatal("a walk started without a probe manager")
	}
	if !strings.Contains(m.probeModal.View(100, 40), "probe manager unavailable") {
		t.Fatal("missing manager not reported")
	}
	if want := []string{"read"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("selection = %v, want it untouched", m.tracer.attachSyscalls)
	}
}

// TestSingleToggleDuringBulkKeepsTheWalksIntent: a single toggle that lands
// while an all-on walk is half done would read back the half-done manager; a
// restart then would carry only part of the walk. The walk's intent wins.
func TestSingleToggleDuringBulkKeepsTheWalksIntent(t *testing.T) {
	old := newGatedBulkManager()
	m := newSessionModel(t, old.selectionProbeManager)
	m.runtime.setProbeManager(old)
	m, walk := pressBulkKey(t, m, 'a')
	done := runAsync(walk)
	<-old.entered

	old.setActive("read", false) // a single toggle finishing meanwhile
	next, _ := m.Update(probes.ProbeToggledMsg{Syscall: "read", Session: m.tracer.session})
	m = next.(*Model)
	if want := []string{"connect", "nanosleep", "read", "socket"}; !slices.Equal(m.tracer.attachSyscalls, want) {
		t.Fatalf("selection = %v, want the walk's intent %v", m.tracer.attachSyscalls, want)
	}
	close(old.release)
	finished := receiveWithin(t, done)
	next, _ = m.Update(finished)
	m = next.(*Model)
	if m.bulkRunning() {
		t.Fatal("walk still in flight after its result")
	}
}

// TestStaleBulkResultDoesNotReplayOverNewerChanges: after the session ended a
// late result records nothing, whatever it carries.
func TestStaleBulkResultDoesNotReplayOverNewerChanges(t *testing.T) {
	m, _ := newLiveSwapModel(t) // no session running: every result is stale
	m.tracer.setAttachSyscalls([]string{"connect"})
	next, _ := m.Update(probes.ProbeToggledMsg{Intent: []string{}})
	if got := next.(*Model).tracer.attachSyscalls; !slices.Equal(got, []string{"connect"}) {
		t.Fatalf("selection = %v, want it untouched", got)
	}
}
