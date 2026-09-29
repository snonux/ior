package tui

import (
	"ior/internal/globalfilter"
	"ior/internal/runtime"
)

// traceSessionBindings is the view of the TUI runtime bindings that one trace
// session receives in its TraceRequest.
//
// A restart cancels the running session and starts the next one without
// waiting for the old one to finish (traceLifecycle.beginCmd), so two
// sessions can overlap: the old one may still be loading or attaching, or
// still detaching its probes, while the new one publishes its state. Every
// write through this view is therefore gated on the session still being the
// newest one (runtimeBindings.updateIfCurrent). A superseded session's late
// publish - its probe manager, live-filter setter, stats engine, stream source
// or flamegraph trie - is dropped instead of replacing the newer session's,
// and its late release (SetProbeManager(nil), the live-filter unregister) is
// dropped instead of clearing it.
//
// Reads are not gated: the stream buffer, sequencer, recorder and filter epoch
// are TUI-owned state that outlives every session.
type traceSessionBindings struct {
	bindings *runtimeBindings
	session  uint64
}

// traceSessionBindings is what a TraceRequest carries, so it must satisfy the
// full runtime contract.
var _ runtime.TraceRuntimeBindings = traceSessionBindings{}

// beginSession starts a new trace session generation and returns its bindings
// view, superseding every earlier view. It also drops the probe manager and
// live-filter setter of the previous session, which is being cancelled: the
// probes modal must not toggle probes on a manager that is about to close, and
// a filter edit made while the new session attaches must take the restart
// path (so the new session picks it up) rather than go to the dying event
// loop. The dashboard sources are kept so the screen keeps its last data until
// the new session publishes its own.
func (r *runtimeBindings) beginSession() traceSessionBindings {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session++
	r.probeManager = nil
	r.liveFilterSetter = nil
	r.liveFilterRegistration = nil
	return traceSessionBindings{bindings: r, session: r.session}
}

// updateIfCurrent runs update under the write lock if session is still the
// newest session, and reports whether it ran.
func (r *runtimeBindings) updateIfCurrent(session uint64, update func()) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session != session {
		return false
	}
	update()
	return true
}

// SetDashboardSnapshotSource publishes the session's stats engine while the
// session is current.
func (s traceSessionBindings) SetDashboardSnapshotSource(source runtime.ResettableSnapshotSource) {
	s.bindings.updateIfCurrent(s.session, func() { s.bindings.snapshotSource = source })
}

// SetEventStreamSource publishes the session's stream source while the session
// is current.
func (s traceSessionBindings) SetEventStreamSource(source runtime.StreamSource) {
	s.bindings.updateIfCurrent(s.session, func() { s.bindings.streamSource = source })
}

// SetLiveTrie publishes the session's flamegraph trie while the session is
// current.
func (s traceSessionBindings) SetLiveTrie(liveTrie runtime.LiveTrieSource) {
	s.bindings.updateIfCurrent(s.session, func() { s.bindings.liveTrieSource = liveTrie })
}

// SetProbeManager publishes (or, with nil, clears) the session's probe
// manager while the session is current. Trace setup clears it on release; a
// superseded session's clear is dropped, so it never erases the manager a
// newer session published.
func (s traceSessionBindings) SetProbeManager(manager runtime.ProbeManager) {
	s.bindings.updateIfCurrent(s.session, func() { s.bindings.probeManager = manager })
}

// SetLiveFilterSetter registers the session's live-filter setter while the
// session is current. The returned unregister func is ownership-aware (it
// clears only this registration); a superseded session registers nothing and
// gets a no-op.
func (s traceSessionBindings) SetLiveFilterSetter(setter func(globalfilter.Filter)) func() {
	var registration *liveFilterRegistration
	installed := s.bindings.updateIfCurrent(s.session, func() {
		registration = s.bindings.installLiveFilterSetterLocked(setter)
	})
	if !installed {
		return func() {}
	}
	return s.bindings.liveFilterUnregisterer(registration)
}

// StreamBuffer returns the TUI-owned stream buffer.
func (s traceSessionBindings) StreamBuffer() runtime.EventSink {
	return s.bindings.StreamBuffer()
}

// Recorder returns the TUI-owned parquet recorder.
func (s traceSessionBindings) Recorder() runtime.RecordingController {
	return s.bindings.Recorder()
}

// StreamSequencer returns the TUI-owned stream row sequencer.
func (s traceSessionBindings) StreamSequencer() runtime.Sequencer {
	return s.bindings.StreamSequencer()
}

// FilterEpoch returns the current filter epoch.
func (s traceSessionBindings) FilterEpoch() uint64 {
	return s.bindings.FilterEpoch()
}
