package tui

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/streamrow"
	"ior/internal/tui/eventstream"
	"ior/internal/types"
)

// sessionProbeManager is a distinguishable probe manager per session.
type sessionProbeManager struct{ name string }

func (sessionProbeManager) States() []probemanager.ProbeState { return nil }
func (sessionProbeManager) Toggle(string) error               { return nil }
func (sessionProbeManager) Attach(string) error               { return nil }
func (sessionProbeManager) Detach(string) error               { return nil }
func (sessionProbeManager) ActiveCount() (int, int)           { return 0, 0 }
func (sessionProbeManager) AttachFamily(context.Context, types.SyscallFamily, func(int, int)) (probemanager.BatchResult, error) {
	return probemanager.BatchResult{}, nil
}
func (sessionProbeManager) DetachFamily(context.Context, types.SyscallFamily, func(int, int)) (probemanager.BatchResult, error) {
	return probemanager.BatchResult{}, nil
}

// fakeSession is what one trace session publishes through its bindings view
// and how it releases it again, mirroring setupBPFModule (probe manager) and
// makeTUIEventLoopConfigurer (live-filter setter).
type fakeSession struct {
	view       runtime.TraceRuntimeBindings
	manager    sessionProbeManager
	calls      int
	unregister func()
}

func (s *fakeSession) publish() {
	s.view.SetProbeManager(s.manager)
	s.unregister = s.view.SetLiveFilterSetter(func(globalfilter.Filter) { s.calls++ })
}

func (s *fakeSession) release() {
	s.unregister()
	s.view.SetProbeManager(nil)
}

// overlapCase is one interleaving of two overlapping sessions A and B, in
// which B (the newer session) must end up owning the bindings.
type overlapCase struct {
	name  string
	steps func(r *runtimeBindings, a, b *fakeSession)
}

// overlappingSessionCases lists the interleavings of A's late setup/teardown
// with B's start that the bindings must survive.
func overlappingSessionCases() []overlapCase {
	return []overlapCase{
		{
			// Restart during "Attaching...": A finishes setup after B.
			name: "A publishes late, then releases late",
			steps: func(r *runtimeBindings, a, b *fakeSession) {
				a.view = r.beginSession()
				b.view = r.beginSession()
				b.publish()
				a.publish()
				a.release()
			},
		},
		{
			// A was running; its slow detach ends after B published.
			name: "A publishes first, releases after B published",
			steps: func(r *runtimeBindings, a, b *fakeSession) {
				a.view = r.beginSession()
				a.publish()
				b.view = r.beginSession()
				b.publish()
				a.release()
			},
		},
		{
			// A's slow detach ends while B is still attaching.
			name: "A releases before B publishes",
			steps: func(r *runtimeBindings, a, b *fakeSession) {
				a.view = r.beginSession()
				a.publish()
				b.view = r.beginSession()
				a.release()
				b.publish()
			},
		},
	}
}

// requireSessionBOwnsBindings checks that B, not A, owns the probe manager and
// the live-filter setter, then that B's own release clears both.
func requireSessionBOwnsBindings(t *testing.T, r *runtimeBindings, a, b *fakeSession) {
	t.Helper()
	if got := r.currentProbeManager(); got != runtime.ProbeManager(b.manager) {
		t.Fatalf("probe manager = %v, want session B's", got)
	}
	if !r.applyLiveFilter(globalfilter.Filter{}) {
		t.Fatal("session B's live-filter setter was cleared")
	}
	if a.calls != 0 || b.calls != 1 {
		t.Fatalf("setter calls A=%d B=%d, want A=0 B=1", a.calls, b.calls)
	}

	// B is still the owner, so its own release must clear both.
	b.release()
	if got := r.currentProbeManager(); got != nil {
		t.Fatalf("probe manager after B's release = %v, want nil", got)
	}
	if r.applyLiveFilter(globalfilter.Filter{}) {
		t.Fatal("B's release left its live-filter setter registered")
	}
}

// TestOverlappingTraceSessionsKeepNewestSessionBindings drives the
// interleavings of a restart that does not wait for the old session: A's
// late setup or late teardown must never replace or clear what B published.
func TestOverlappingTraceSessionsKeepNewestSessionBindings(t *testing.T) {
	for _, tc := range overlappingSessionCases() {
		t.Run(tc.name, func(t *testing.T) {
			r := newRuntimeBindings()
			a := &fakeSession{manager: sessionProbeManager{name: "A"}}
			b := &fakeSession{manager: sessionProbeManager{name: "B"}}
			tc.steps(r, a, b)
			requireSessionBOwnsBindings(t, r, a, b)
		})
	}
}

// TestBeginSessionDropsPreviousSessionControls pins that starting a session
// drops the probe manager and live-filter setter of the one being cancelled,
// while the dashboard sources stay until the new session publishes its own.
func TestBeginSessionDropsPreviousSessionControls(t *testing.T) {
	r := newRuntimeBindings()
	a := &fakeSession{view: r.beginSession(), manager: sessionProbeManager{name: "A"}}
	a.publish()
	source := r.eventStreamSource()

	r.beginSession()

	if got := r.currentProbeManager(); got != nil {
		t.Fatalf("probe manager after a new session began = %v, want nil", got)
	}
	if r.applyLiveFilter(globalfilter.Filter{}) {
		t.Fatal("a new session kept the cancelled session's live-filter setter")
	}
	if r.eventStreamSource() != source {
		t.Fatal("beginning a session must not drop the stream source")
	}
}

// sentinelSnapshotSource and sentinelLiveTrie are distinguishable non-nil
// dashboard sources, so a test can tell whose publish won.
type sentinelSnapshotSource struct {
	runtime.ResettableSnapshotSource
	name string
}

type sentinelLiveTrie struct {
	runtime.LiveTrieSource
	name string
}

type sentinelStreamSource struct {
	runtime.StreamSource
	name string
}

// TestStaleSessionCannotPublishDashboardSources covers the other per-session
// publishes: a superseded session's stats engine, stream source and trie must
// not replace the newer session's.
func TestStaleSessionCannotPublishDashboardSources(t *testing.T) {
	r := newRuntimeBindings()
	stale := r.beginSession()
	current := r.beginSession()
	currentSnap := sentinelSnapshotSource{name: "current"}
	currentTrie := sentinelLiveTrie{name: "current"}
	currentStream := sentinelStreamSource{name: "current"}
	current.SetDashboardSnapshotSource(currentSnap)
	current.SetLiveTrie(currentTrie)
	current.SetEventStreamSource(currentStream)

	stale.SetDashboardSnapshotSource(sentinelSnapshotSource{name: "stale"})
	stale.SetLiveTrie(sentinelLiveTrie{name: "stale"})
	stale.SetEventStreamSource(sentinelStreamSource{name: "stale"})

	if got := r.dashboardSnapshotSource(); got != runtime.ResettableSnapshotSource(currentSnap) {
		t.Fatalf("snapshot source = %v, want the current session's", got)
	}
	if got := r.liveTrie(); got != runtime.LiveTrieSource(currentTrie) {
		t.Fatalf("live trie = %v, want the current session's", got)
	}
	if got := r.eventStreamSource(); got != runtime.StreamSource(currentStream) {
		t.Fatalf("stream source = %v, want the current session's", got)
	}
	// The stale unregister is a no-op and must not panic.
	stale.SetLiveFilterSetter(func(globalfilter.Filter) {})()
	if r.applyLiveFilter(globalfilter.Filter{}) {
		t.Fatal("a stale session registered a live-filter setter")
	}
}

// TestConcurrentSessionPublishesKeepNewestSession races a superseded
// session's publishes, clears and event output against the current
// session's (run with -race). Whatever the interleaving, the current
// session's state must win and none of the stale rows may reach the stream.
func TestConcurrentSessionPublishesKeepNewestSession(t *testing.T) {
	r := newRuntimeBindings()
	stale := r.beginSession()
	current := r.beginSession()
	currentManager := sessionProbeManager{name: "current"}
	current.SetProbeManager(currentManager)
	currentSetterCalls := 0
	current.SetLiveFilterSetter(func(globalfilter.Filter) { currentSetterCalls++ })

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				stale.SetProbeManager(sessionProbeManager{name: "stale"})
				stale.SetProbeManager(nil)
				stale.SetLiveFilterSetter(func(globalfilter.Filter) {})()
				stale.StreamBuffer().Push(streamrow.Row{})
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				current.SetProbeManager(currentManager)
				_ = r.currentProbeManager()
				_ = current.StreamBuffer().Len()
			}
		}()
	}
	wg.Wait()

	if got := r.currentProbeManager(); got != runtime.ProbeManager(currentManager) {
		t.Fatalf("probe manager = %v, want the current session's", got)
	}
	if !r.applyLiveFilter(globalfilter.Filter{}) || currentSetterCalls != 1 {
		t.Fatalf("current live-filter setter lost (calls = %d)", currentSetterCalls)
	}
	if n := r.StreamBuffer().Len(); n != 0 {
		t.Fatalf("stream holds %d rows of a stale session, want 0", n)
	}
}

// countingRecorder counts the rows it gets; the other controller methods go
// to an idle real recorder, so the model can poll its status.
type countingRecorder struct {
	runtime.RecordingController
	rows   int
	epochs []uint64
}

func (c *countingRecorder) Record(_ streamrow.Row, epoch uint64) error {
	c.rows++
	c.epochs = append(c.epochs, epoch)
	return nil
}

// TestStoppedSessionOutputDoesNotReachStreamOrRecorder is the regression test
// for a stopped session's late events: once the lifecycle stopped it, its
// rows must neither land in the stream the next session starts from (reset
// by selectProcess) nor be recorded. The current session's output still
// flows (negative case).
func TestStoppedSessionOutputDoesNotReachStreamOrRecorder(t *testing.T) {
	requests := make(chan TraceRequest, 2)
	lifecycle := newTraceLifecycle(func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(lifecycle.stop)
	r := newRuntimeBindings()
	recorder := &countingRecorder{RecordingController: parquet.NewRecorder(parquet.RecorderConfig{})}
	r.recorder = recorder

	lifecycle.beginCmd(r, globalfilter.Filter{})()
	reqA := <-requests
	sinkA, recorderA := reqA.Bindings.StreamBuffer(), reqA.Bindings.Recorder()
	sinkA.Push(streamrow.Row{})
	if err := recorderA.Record(streamrow.Row{}, 0); err != nil {
		t.Fatalf("current session Record() error = %v", err)
	}
	if sinkA.Len() != 1 || recorder.rows != 1 {
		t.Fatalf("current session output: stream %d rows, recorder %d rows, want 1 and 1", sinkA.Len(), recorder.rows)
	}

	// selectProcess: stop, reset the stream, start the next session.
	lifecycle.stop()
	r.resetStreamBuffer()
	lifecycle.beginCmd(r, globalfilter.Filter{})()
	<-requests

	sinkA.Push(streamrow.Row{})
	if err := recorderA.Record(streamrow.Row{}, 0); !errors.Is(err, parquet.ErrRecorderNotActive) {
		t.Fatalf("stopped session Record() error = %v, want ErrRecorderNotActive", err)
	}
	if n := r.StreamBuffer().Len(); n != 0 {
		t.Fatalf("stream holds %d rows of the stopped session, want 0", n)
	}
	if recorder.rows != 1 {
		t.Fatalf("recorder got %d rows, want only the one recorded while current", recorder.rows)
	}
}

// TestFilterRestartDoesNotStampOldSessionRowsWithNewEpoch drives the filter
// fallback (no live setter): the old session is stopped before the epoch
// advances, so none of its rows can be recorded under the new epoch.
func TestFilterRestartDoesNotStampOldSessionRowsWithNewEpoch(t *testing.T) {
	starter := newRecordingStarter()
	m := NewModel(4242, starter.start)
	t.Cleanup(m.tracer.stop)
	recorder := &countingRecorder{RecordingController: parquet.NewRecorder(parquet.RecorderConfig{})}
	m.runtime.recorder = recorder

	runCmdAsync(initTraceCmd(t, m))
	starter.next(t)
	recorderA := starter.nextRequest(t).Bindings.Recorder()

	changed := m.filters.current()
	changed.Comm = &globalfilter.StringFilter{Pattern: "nginx"}
	m.applyGlobalFilter(changed, "comm")
	if got := m.runtime.FilterEpoch(); got != 1 {
		t.Fatalf("filter epoch = %d, want 1", got)
	}
	// The old session's event loop reads the epoch and records late.
	if err := recorderA.Record(streamrow.Row{}, m.runtime.FilterEpoch()); !errors.Is(err, parquet.ErrRecorderNotActive) {
		t.Fatalf("old session Record() error = %v, want ErrRecorderNotActive", err)
	}
	if recorder.rows != 0 {
		t.Fatalf("recorder got %d rows of the old session stamped with epochs %v", recorder.rows, recorder.epochs)
	}
}

// TestRuntimeBindingsAreNotAPublisher pins the design rule that trace
// sessions can publish only through a session view: were *runtimeBindings a
// RuntimePublisher again, handing it to a starter would compile and silently
// bring back the overlapping-session clobbering.
func TestRuntimeBindingsAreNotAPublisher(t *testing.T) {
	if _, ok := any(newRuntimeBindings()).(runtime.RuntimePublisher); ok {
		t.Fatal("*runtimeBindings implements runtime.RuntimePublisher; publish only through traceSessionBindings")
	}
}

// TestSessionViewDelegatesTUIOwnedState is the negative case for the gate:
// reads of TUI-owned state are not per session and must work for any view.
func TestSessionViewDelegatesTUIOwnedState(t *testing.T) {
	r := newRuntimeBindings()
	stale := r.beginSession()
	r.beginSession()
	r.advanceFilterEpoch()

	if stale.StreamBuffer() == nil || stale.StreamSequencer() == nil || stale.Recorder() == nil {
		t.Fatal("a session view must expose the TUI-owned stream buffer, sequencer and recorder")
	}
	if stale.FilterEpoch() != 1 {
		t.Fatalf("FilterEpoch() = %d, want 1", stale.FilterEpoch())
	}
}

// TestRestartKeepsNewSessionProbeManagerAgainstLateOldSession runs the race
// through the real lifecycle: session A is cancelled by a restart, then A's
// starter publishes and releases late. Session B's manager must survive.
func TestRestartKeepsNewSessionProbeManagerAgainstLateOldSession(t *testing.T) {
	requests := make(chan TraceRequest, 2)
	lifecycle := newTraceLifecycle(func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	t.Cleanup(lifecycle.stop)
	r := newRuntimeBindings()

	lifecycle.beginCmd(r, globalfilter.Filter{})()
	reqA := <-requests
	lifecycle.beginCmd(r, globalfilter.Filter{})()
	reqB := <-requests

	mgrB := sessionProbeManager{name: "B"}
	reqB.Bindings.SetProbeManager(mgrB)
	reqA.Bindings.SetProbeManager(sessionProbeManager{name: "A"})
	reqA.Bindings.SetProbeManager(nil)

	if got := r.currentProbeManager(); got != runtime.ProbeManager(mgrB) {
		t.Fatalf("probe manager = %v, want session B's", got)
	}
}

// TestStaleSessionResultsAreIgnored pins that the model applies a start
// result only while its session is the running one: a superseded session's
// late TracingStartedMsg must not end the new session's attaching state, and
// its late error must not be shown against the new session. The current
// session's results still apply (negative case), and after a stop even the
// last session's results are stale.
func TestStaleSessionResultsAreIgnored(t *testing.T) {
	m := NewModel(4242, func(ctx context.Context, _ TraceRequest) error {
		<-ctx.Done()
		return ctx.Err()
	})
	t.Cleanup(m.tracer.stop)
	m.beginTraceCmd()
	stale := m.tracer.session
	m.restartTrace()
	current := m.tracer.session

	m.Update(traceSessionResultMsg{session: stale, result: TracingStartedMsg{}})
	if !m.attaching {
		t.Fatal("a stale TracingStartedMsg ended the new session's attaching state")
	}
	m.Update(traceSessionResultMsg{session: stale, result: TracingErrorMsg{Err: errors.New("old")}})
	if m.lastErr != nil {
		t.Fatalf("a stale TracingErrorMsg surfaced %v against the new session", m.lastErr)
	}

	m.Update(traceSessionResultMsg{session: current, result: TracingStartedMsg{}})
	if m.attaching {
		t.Fatal("the current session's TracingStartedMsg was ignored")
	}

	m.tracer.stop()
	m.Update(traceSessionResultMsg{session: current, result: TracingErrorMsg{Err: errors.New("late")}})
	if m.lastErr != nil {
		t.Fatalf("a stopped session's error surfaced %v", m.lastErr)
	}
}

// TestStoppedSessionStartReportsNothing covers the start command itself: a
// session whose context was cancelled reports nothing, neither the success
// that raced the stop nor a startup timeout of a starter stuck after it (for
// example in BPFLoadObject). An uncancelled session still times out.
func TestStoppedSessionStartReportsNothing(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	succeed := func(context.Context, TraceRequest) error { return nil }
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	hang := func(context.Context, TraceRequest) error {
		<-release
		return nil
	}

	if msg := startTraceCmdWithTimeout(cancelled, succeed, TraceRequest{}, time.Minute)(); msg != nil {
		t.Fatalf("cancelled session success = %#v, want nil", msg)
	}
	if msg := startTraceCmdWithTimeout(cancelled, hang, TraceRequest{}, time.Millisecond)(); msg != nil {
		t.Fatalf("cancelled session timeout = %#v, want nil", msg)
	}
	msg := startTraceCmdWithTimeout(context.Background(), hang, TraceRequest{}, time.Millisecond)()
	if _, ok := msg.(TracingErrorMsg); !ok {
		t.Fatalf("live session timeout = %#v, want TracingErrorMsg", msg)
	}
}

// TestBeginCmdWithoutBindingsSendsNone is the negative case of the session
// view: without TUI bindings the request carries none and stop has no view to
// retire.
func TestBeginCmdWithoutBindingsSendsNone(t *testing.T) {
	requests := make(chan TraceRequest, 1)
	lifecycle := newTraceLifecycle(func(_ context.Context, req TraceRequest) error {
		requests <- req
		return nil
	})
	lifecycle.beginCmd(nil, globalfilter.Filter{})()
	if req := <-requests; req.Bindings != nil {
		t.Fatalf("request bindings = %#v, want nil", req.Bindings)
	}
	lifecycle.stop()
}

// streamSnapshotAppender mirrors eventstream's unexported snapshotAppender:
// the optional fast path the stream tab uses to refresh without allocating.
type streamSnapshotAppender interface {
	AppendSnapshot(dst []streamrow.Row) []streamrow.Row
}

// TestSessionStreamSourceKeepsAppendSnapshotFastPath is the regression test
// for the session sink hiding the ring buffer's AppendSnapshot: the core
// publishes the sink it got from StreamBuffer as the stream source, and the
// stream tab then fell back to Snapshot and allocated a full copy of up to
// 10k rows on every refresh.
func TestSessionStreamSourceKeepsAppendSnapshotFastPath(t *testing.T) {
	r := newRuntimeBindings()
	view := r.beginSession()
	sink := view.StreamBuffer()
	view.SetEventStreamSource(sink) // what the core's wireRuntimeBindings does
	source := r.eventStreamSource()

	appender, ok := source.(streamSnapshotAppender)
	if !ok {
		t.Fatalf("published stream source %T has no AppendSnapshot", source)
	}
	for i := range streamrow.RingBufferCapacity {
		sink.Push(streamrow.Row{Seq: uint64(i + 1)})
	}
	got := appender.AppendSnapshot(nil)
	if len(got) != sink.Len() {
		t.Fatalf("AppendSnapshot returned %d rows, want %d", len(got), sink.Len())
	}
	if got[0].Seq != 1 {
		t.Fatalf("AppendSnapshot first row seq = %d, want 1", got[0].Seq)
	}

	stream := eventstream.NewModel(source)
	stream.SetViewport(160, 40)
	stream.Refresh()
	if allocs := testing.AllocsPerRun(10, stream.Refresh); allocs > 2 {
		t.Fatalf("stream refresh through the session source allocated %.0f times, want <= 2", allocs)
	}
}
