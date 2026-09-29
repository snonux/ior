package tui

import (
	"context"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/runtime"
)

// sessionProbeManager is a distinguishable probe manager per session.
type sessionProbeManager struct{ name string }

func (sessionProbeManager) States() []probemanager.ProbeState { return nil }
func (sessionProbeManager) Toggle(string) error               { return nil }
func (sessionProbeManager) ActiveCount() (int, int)           { return 0, 0 }

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

// TestOverlappingTraceSessionsKeepNewestSessionBindings drives the
// interleavings of a restart that does not wait for the old session: A's
// late setup or late teardown must never replace or clear what B published.
func TestOverlappingTraceSessionsKeepNewestSessionBindings(t *testing.T) {
	tests := []struct {
		name  string
		steps func(r *runtimeBindings, a, b *fakeSession)
	}{
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
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRuntimeBindings()
			a := &fakeSession{manager: sessionProbeManager{name: "A"}}
			b := &fakeSession{manager: sessionProbeManager{name: "B"}}
			tc.steps(r, a, b)

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

// TestStaleSessionCannotPublishDashboardSources covers the other per-session
// publishes: a superseded session's stats engine, stream source and trie must
// not replace the newer session's.
func TestStaleSessionCannotPublishDashboardSources(t *testing.T) {
	r := newRuntimeBindings()
	stale := r.beginSession()
	current := r.beginSession()
	currentSource := r.eventStreamSource()
	current.SetEventStreamSource(currentSource)

	stale.SetEventStreamSource(nil)
	stale.SetDashboardSnapshotSource(nil)
	stale.SetLiveTrie(nil)

	if r.eventStreamSource() != currentSource {
		t.Fatal("a stale session replaced the current stream source")
	}
	// The stale unregister is a no-op and must not panic.
	stale.SetLiveFilterSetter(func(globalfilter.Filter) {})()
	if r.applyLiveFilter(globalfilter.Filter{}) {
		t.Fatal("a stale session registered a live-filter setter")
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
