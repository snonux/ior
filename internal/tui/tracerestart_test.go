package tui

import (
	"context"
	"testing"
	"time"

	"ior/internal/globalfilter"

	tea "charm.land/bubbletea/v2"
)

// traceRestartWait bounds every wait for a trace session to start or be
// cancelled. The sessions here never touch BPF, so a second is generous.
const traceRestartWait = time.Second

// recordingStarter is a TraceStarter that publishes each session's context and
// then blocks until that context is cancelled, like a real trace does while
// its BPF probes stay attached. Every session it hands out is therefore
// observable: started via sessions, still live until ctx.Done fires.
type recordingStarter struct {
	sessions chan context.Context
	// requests receives each session's TraceRequest, in the same order as
	// sessions, so a test can check what the model handed the starter.
	requests chan TraceRequest
}

func newRecordingStarter() *recordingStarter {
	return &recordingStarter{
		sessions: make(chan context.Context, 8),
		requests: make(chan TraceRequest, 8),
	}
}

func (r *recordingStarter) start(ctx context.Context, req TraceRequest) error {
	r.requests <- req
	r.sessions <- ctx
	<-ctx.Done()
	return ctx.Err()
}

// nextRequest returns the request of the next session the starter ran. Call
// it after next, which is what waits for the session to begin.
func (r *recordingStarter) nextRequest(t *testing.T) TraceRequest {
	t.Helper()
	select {
	case req := <-r.requests:
		return req
	case <-time.After(traceRestartWait):
		t.Fatal("trace starter recorded no request")
		return TraceRequest{}
	}
}

// next waits for the next trace session the starter was asked to run.
func (r *recordingStarter) next(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-r.sessions:
		return ctx
	case <-time.After(traceRestartWait):
		t.Fatal("trace starter was not invoked")
		return nil
	}
}

// initTraceCmd drives a picker-skipping startup the way Bubble Tea does: it
// runs Init, requires its batch to request the startup trace, hands that
// request to Update and returns the start command Update produced.
func initTraceCmd(t *testing.T, m *Model) tea.Cmd {
	t.Helper()
	if !cmdEmits[initialTraceStartMsg](m.Init()) {
		t.Fatal("Init did not request the startup trace")
	}
	_, cmd := m.Update(initialTraceStartMsg{})
	if cmd == nil {
		t.Fatal("Update did not start the requested startup trace")
	}
	return cmd
}

// cmdEmits reports whether cmd, or any command of the batch it returns,
// produces a message of type T. Every command Init returns is immediate, so
// running them synchronously is safe.
func cmdEmits[T tea.Msg](cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	msg := cmd()
	if _, ok := msg.(T); ok {
		return true
	}
	batch, ok := msg.(tea.BatchMsg)
	if !ok {
		return false
	}
	for _, sub := range batch {
		if sub == nil {
			continue
		}
		if _, ok := sub().(T); ok {
			return true
		}
	}
	return false
}

// runCmdAsync executes cmd the way Bubble Tea would, fanning a batch out to
// one goroutine per command. The trace command blocks for the lifetime of its
// session, so nothing here waits for results; the commands exit once their
// session is cancelled.
func runCmdAsync(cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	go func() {
		batch, ok := cmd().(tea.BatchMsg)
		if !ok {
			return
		}
		for _, sub := range batch {
			if sub != nil {
				go sub()
			}
		}
	}()
}

func requireCancelled(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(traceRestartWait):
		t.Fatalf("%s: trace context was never cancelled; its BPF session would stay attached", what)
	}
}

func requireLive(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s: trace context cancelled (%v), want the session still running", what, err)
	}
}

// TestInitTraceIsCancelledByEveryRestartPath is the regression test for the
// lost Init cancel: the startup trace Model.Init requests (the `ior -pid N`
// and test-flames startup path) must be the one the next restart cancels. When
// Init stored the cancel func on a discarded copy of the model, every later
// stop() was a no-op for that first trace, and each restart path below
// started a second BPF session while the first stayed attached.
func TestInitTraceIsCancelledByEveryRestartPath(t *testing.T) {
	const initialPID = 4242

	cases := []struct {
		name    string
		restart func(m *Model) tea.Cmd
	}{
		{
			name: "pid reselect then select",
			restart: func(m *Model) tea.Cmd {
				_, _ = m.reselectPID()
				_, cmd := m.Update(PidSelectedMsg{Pid: 77})
				return cmd
			},
		},
		{
			name: "tid reselect then select",
			restart: func(m *Model) tea.Cmd {
				_, _ = m.reselectTID()
				_, cmd := m.Update(TidSelectedMsg{Pid: initialPID, Tid: 5})
				return cmd
			},
		},
		{
			name: "pid reselect then picker cancel",
			restart: func(m *Model) tea.Cmd {
				_, _ = m.reselectPID()
				_, cmd := m.cancelPickerToDashboard()
				return cmd
			},
		},
		{
			// No live filter setter is registered (the starter never
			// registers one), so the filter change takes the full-restart
			// fallback rather than the in-place swap.
			name: "filter change restart",
			restart: func(m *Model) tea.Cmd {
				_, cmd := m.reapplyActiveFilter(true)
				return cmd
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			starter := newRecordingStarter()
			m := NewModel(initialPID, starter.start)
			t.Cleanup(m.tracer.stop)
			if m.router.current() != ScreenDashboard || !m.attaching {
				t.Fatalf("startup state = screen %v attaching %v, want dashboard attaching", m.router.current(), m.attaching)
			}

			runCmdAsync(initTraceCmd(t, m))
			first := starter.next(t)
			if m.tracer.traceStop == nil {
				t.Fatal("the startup trace started but its cancel func did not reach the model")
			}
			requireLive(t, first, "after Init")

			runCmdAsync(tc.restart(m))
			requireCancelled(t, first, "Init trace after restart")
			second := starter.next(t)
			requireLive(t, second, "restarted trace")

			m.tracer.stop()
			requireCancelled(t, second, "restarted trace after stop")
		})
	}
}

// TestBeginCmdCancelsPreviousSession pins that beginCmd itself enforces the
// one-live-session invariant, so a caller that forgets stop() before a
// restart cannot leave the previous BPF session attached.
func TestBeginCmdCancelsPreviousSession(t *testing.T) {
	starter := newRecordingStarter()
	lifecycle := newTraceLifecycle(starter.start)
	t.Cleanup(lifecycle.stop)
	bindings := newRuntimeBindings()

	runCmdAsync(lifecycle.beginCmd(bindings, globalfilter.Filter{}))
	first := starter.next(t)
	requireLive(t, first, "first session")

	runCmdAsync(lifecycle.beginCmd(bindings, globalfilter.Filter{}))
	requireCancelled(t, first, "first session after second beginCmd")
	second := starter.next(t)
	requireLive(t, second, "second session")
}

// TestInitOnPickerScreenStartsNoTrace is the negative case: without an
// initial PID the model opens the picker, so Init must not arm a trace, and
// stopping the idle lifecycle (twice, as quit-from-picker paths can) is a
// no-op rather than a panic.
func TestInitOnPickerScreenStartsNoTrace(t *testing.T) {
	m := NewModel(-1, newRecordingStarter().start)

	if cmd := m.Init(); cmd == nil {
		t.Fatal("Init on the picker screen returned no command")
	}
	if m.router.current() != ScreenPIDPicker || m.attaching {
		t.Fatalf("startup state = screen %v attaching %v, want picker idle", m.router.current(), m.attaching)
	}
	if m.tracer.traceStop != nil || m.tracer.shutdownReporter != nil {
		t.Fatal("Init on the picker screen armed a trace session")
	}
	m.tracer.stop()
	m.tracer.stop()
}

// TestFilterChangeRestartHandsStarterTheNewFilter pins the filter restart
// path end to end: with no live filter setter registered, a filter change
// restarts the trace, and the restarted session must receive the new filter,
// the same runtime bindings and a fresh shutdown reporter explicitly in its
// TraceRequest. Before the request existed these rode on the context, where a
// missing value silently meant "start without the TUI's filter".
func TestFilterChangeRestartHandsStarterTheNewFilter(t *testing.T) {
	const initialPID = 4242
	starter := newRecordingStarter()
	m := NewModel(initialPID, starter.start)
	t.Cleanup(m.tracer.stop)

	runCmdAsync(initTraceCmd(t, m))
	first := starter.next(t)
	firstReq := starter.nextRequest(t)
	if firstReq.Bindings != TraceRuntimeBindings(m.runtime) {
		t.Fatal("initial session did not receive the model's runtime bindings")
	}
	if firstReq.Filter == nil || firstReq.Filter.PID == nil || firstReq.Filter.PID.Value != initialPID {
		t.Fatalf("initial session filter = %+v, want the startup PID %d", firstReq.Filter, initialPID)
	}

	changed := m.filters.current()
	changed.Comm = &globalfilter.StringFilter{Pattern: "nginx"}
	_, cmd := m.applyGlobalFilter(changed, "comm")
	if !m.attaching {
		t.Fatal("filter change without a live setter did not take the restart path")
	}
	runCmdAsync(cmd)
	requireCancelled(t, first, "initial session after filter restart")
	second := starter.next(t)
	requireLive(t, second, "restarted session")
	secondReq := starter.nextRequest(t)

	if secondReq.Filter == nil || secondReq.Filter.Comm == nil || secondReq.Filter.Comm.Pattern != "nginx" {
		t.Fatalf("restarted session filter = %+v, want the new comm filter", secondReq.Filter)
	}
	if secondReq.Filter.PID == nil || secondReq.Filter.PID.Value != initialPID {
		t.Fatalf("restarted session filter = %+v, want the PID scope kept", secondReq.Filter)
	}
	if firstReq.Filter.Comm != nil {
		t.Fatalf("the restart mutated the previous session's filter: %+v", firstReq.Filter.Comm)
	}
	if secondReq.Bindings != firstReq.Bindings {
		t.Fatal("restarted session received different runtime bindings")
	}
	if secondReq.ShutdownReporter == nil || secondReq.ShutdownReporter == firstReq.ShutdownReporter {
		t.Fatal("restarted session did not receive its own shutdown reporter")
	}
}
