package tui

import (
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/streamrow"
	"ior/internal/tui/eventstream"
)

// traceSessionBindings is the view of the TUI runtime bindings that one trace
// session receives in its TraceRequest. It is the only implementation of the
// runtime publisher contract in this package: *runtimeBindings deliberately
// has no exported setters, so every trace session has to go through a view.
//
// A restart cancels the running session and starts the next one without
// waiting for the old one to finish (traceLifecycle.beginCmd), so two
// sessions can overlap: the old one may still be loading or attaching, still
// delivering its last events, or still detaching its probes, while the new
// one publishes its state. Every write through this view is therefore gated
// on the session still being the current one: it stops being current when
// the lifecycle stops it (end) or a newer session begins (beginSession).
//
//   - Publishes - probe manager, live-filter setter, stats engine, stream
//     source, flamegraph trie - and their late releases (SetProbeManager(nil),
//     the live-filter unregister) of a superseded session are dropped instead
//     of replacing or clearing the newer session's.
//   - Event output is gated too: StreamBuffer and Recorder return wrappers
//     whose Push/Record drop what a superseded session still emits, so its
//     rows can neither land in the next session's freshly reset stream nor be
//     recorded with the next session's filter epoch. The trace core's hot
//     path uses RowEmitter instead: one gate per event for the push, the
//     record and the recorder warning together (task yp2).
//
// Plain reads (stream length/snapshot, sequencer, filter epoch, recorder
// status) are not gated: that is TUI-owned state outliving every session.
type traceSessionBindings struct {
	bindings *runtimeBindings
	session  uint64
}

// sessionEventSink is the stream buffer as one session sees it: Push is
// dropped once the session is no longer current, reads go straight through.
// The trace core also publishes it as the TUI's stream source, so it forwards
// the ring buffer's AppendSnapshot fast path as well (see AppendSnapshot).
type sessionEventSink struct {
	view traceSessionBindings
}

// sessionRecorder is the recorder as one session sees it: Record is dropped
// (reported as ErrRecorderNotActive, which callers treat as "not news") once
// the session is no longer current, and TakeFailure claims nothing then, so a
// retired session cannot consume a failure it can no longer show. The other
// controller methods go straight through: they are the TUI's own calls, not
// the session's. RecordWarning (runtime.WarningRecorder) is the session's way
// to report what Record returned: it publishes the warning under the same
// gate that claimed the failure.
type sessionRecorder struct {
	runtime.RecordingController
	view traceSessionBindings
}

// sessionRowEmitter is the per-event output of one session: the stream push,
// the recording and the recorder warning of a row under a single session gate
// (see EmitRow).
type sessionRowEmitter struct {
	view traceSessionBindings
}

// traceSessionBindings is what a TraceRequest carries, so it must satisfy the
// full runtime contract; its wrappers must satisfy the sink and recorder ones.
var (
	_ runtime.TraceRuntimeBindings = traceSessionBindings{}
	_ runtime.RowEmitterSource     = traceSessionBindings{}
	_ runtime.RowEmitter           = sessionRowEmitter{}
	_ runtime.EventSink            = sessionEventSink{}
	_ runtime.RecordingController  = sessionRecorder{}
	_ runtime.WarningRecorder      = sessionRecorder{}
)

// beginSession starts a new trace session generation and returns its bindings
// view, superseding every earlier view. It also drops the previous session's
// controls (see endSessionLocked).
func (r *runtimeBindings) beginSession() traceSessionBindings {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endSessionLocked()
	return traceSessionBindings{bindings: r, session: r.session}
}

// endSession retires session if it is still the current one, so that
// nothing it publishes or emits from now on reaches the TUI. Retiring an
// already superseded session is a no-op: it must not disturb the newer one.
func (r *runtimeBindings) endSession(session uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session == session {
		r.endSessionLocked()
	}
}

// endSessionLocked advances the generation, so no existing view is current any
// more, and drops the probe manager and live-filter setter of the session
// that is going away: the probes modal must not toggle probes on a manager
// that is about to close, and a filter edit made before the next session is up
// must take the restart path (so that session picks it up) rather than go to
// the dying event loop. The dashboard sources are kept so the screen keeps its
// last data until the next session publishes its own. The caller must hold
// r.mu for writing.
func (r *runtimeBindings) endSessionLocked() {
	r.session++
	r.probeManager = nil
	r.liveFilterSetter = nil
	r.liveFilterRegistration = nil
}

// updateIfCurrent runs update under the write lock if session is still the
// current session, and reports whether it ran.
func (r *runtimeBindings) updateIfCurrent(session uint64, update func()) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.session != session {
		return false
	}
	update()
	return true
}

// emitIfCurrent runs emit under the read lock if session is still current.
// Holding the lock across emit is what makes endSession a barrier: once it
// returns, no emit of the retired session is still in flight, so the caller
// can reset the stream (selectProcess) or advance the filter epoch knowing no
// stale row can land afterwards. emit must not take r.mu itself.
func (r *runtimeBindings) emitIfCurrent(session uint64, emit func()) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.session != session {
		return false
	}
	emit()
	return true
}

// ringBuffer returns the TUI-owned stream ring buffer (nil if absent).
func (r *runtimeBindings) ringBuffer() *eventstream.RingBuffer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.streamBuffer
}

// end retires this session (see runtimeBindings.endSession).
func (s traceSessionBindings) end() {
	s.bindings.endSession(s.session)
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

// StreamBuffer returns the TUI-owned stream buffer behind this session's gate,
// or nil when the bindings have no buffer. The core pushes rows into the
// returned sink and also publishes it back as the stream source, so besides
// the gated Push it offers every read the stream tab uses, including the
// AppendSnapshot fast path.
func (s traceSessionBindings) StreamBuffer() runtime.EventSink {
	if s.bindings.StreamBuffer() == nil {
		return nil
	}
	return sessionEventSink{view: s}
}

// Recorder returns the TUI-owned parquet recorder behind this session's gate,
// or nil when the bindings have no recorder.
func (s traceSessionBindings) Recorder() runtime.RecordingController {
	recorder := s.bindings.Recorder()
	if recorder == nil {
		return nil
	}
	return sessionRecorder{RecordingController: recorder, view: s}
}

// RowEmitter returns the session's single-gate event output (see
// runtime.RowEmitterSource).
func (s traceSessionBindings) RowEmitter() runtime.RowEmitter {
	return sessionRowEmitter{view: s}
}

// StreamSequencer returns the TUI-owned stream row sequencer.
func (s traceSessionBindings) StreamSequencer() runtime.Sequencer {
	return s.bindings.StreamSequencer()
}

// FilterEpoch returns the current filter epoch.
func (s traceSessionBindings) FilterEpoch() uint64 {
	return s.bindings.FilterEpoch()
}

// Push appends row to the TUI stream while the session is current.
func (k sessionEventSink) Push(row streamrow.Row) {
	r := k.view.bindings
	r.emitIfCurrent(k.view.session, func() {
		if r.streamBuffer != nil {
			r.streamBuffer.Push(row)
		}
	})
}

// Len returns the number of buffered stream rows.
func (k sessionEventSink) Len() int {
	if buffer := k.view.bindings.ringBuffer(); buffer != nil {
		return buffer.Len()
	}
	return 0
}

// Snapshot returns the buffered stream rows.
func (k sessionEventSink) Snapshot() []streamrow.Row {
	if buffer := k.view.bindings.ringBuffer(); buffer != nil {
		return buffer.Snapshot()
	}
	return nil
}

// AppendSnapshot appends the buffered stream rows to dst (ungated, like every
// read). The trace core publishes this sink as the TUI's stream source, and
// the stream tab refreshes several times a second: without this forward the
// view would miss the ring buffer's allocation-free snapshot path and copy up
// to the full ring into a fresh slice on every refresh.
func (k sessionEventSink) AppendSnapshot(dst []streamrow.Row) []streamrow.Row {
	if buffer := k.view.bindings.ringBuffer(); buffer != nil {
		return buffer.AppendSnapshot(dst)
	}
	return dst
}

// Record records row while the session is current. A superseded session's
// row is dropped and reported as parquet.ErrRecorderNotActive, the result the
// trace core already treats as "nothing to report".
func (k sessionRecorder) Record(row streamrow.Row, filterEpoch uint64) error {
	err := parquet.ErrRecorderNotActive
	k.view.bindings.emitIfCurrent(k.view.session, func() {
		err = k.RecordingController.Record(row, filterEpoch)
	})
	return err
}

// TakeFailure claims the last recording's failure while the session is current.
// A retired session gets nil and leaves the failure untaken: TakeFailure marks
// it reported, and this session's warning row would be dropped, so claiming it
// would lose the failure for everyone (the next session and the record modal
// would both see nothing). The record modal reads the TUI-owned recorder
// directly, ungated, so it still claims what a retired session left.
func (k sessionRecorder) TakeFailure() error {
	var failure error
	k.view.bindings.emitIfCurrent(k.view.session, func() {
		failure = k.RecordingController.TakeFailure()
	})
	return failure
}

// RecordWarning records row while the session is current and publishes the
// warning describe derives from the result, all under one session gate (see
// runtime.WarningRecorder for why the claim and the push must not be separate
// steps). The row's closure captures only what Record's already does and never
// escapes emitIfCurrent, so the per-event cost matches Record.
func (k sessionRecorder) RecordWarning(row streamrow.Row, filterEpoch uint64, describe func(rec runtime.RowRecorder, result error) string) {
	r := k.view.bindings
	r.emitIfCurrent(k.view.session, func() {
		r.recordAndWarnLocked(k.RecordingController, row, filterEpoch, describe)
	})
}

// EmitRow delivers one event's row while the session is current: it pushes the
// row to the stream, records it and publishes the recorder warning, all under
// one read-lock hold. The lock discipline is emitIfCurrent's - holding the
// lock across the whole delivery is what makes endSession a barrier, so once
// it returns no row of the retired session is still in flight - but it is
// spelled out here instead of calling emitIfCurrent: the closure (and the
// second lock round trip the separate Push and RecordWarning each paid) was a
// measurable part of the per-event cost.
//
// The recorder and stream buffer are read from the bindings under the lock,
// like every gated emit, so a swapped-in buffer is honoured. The filter epoch
// is read inside the gate too, as late as possible: the stamp then reflects
// the epoch current at delivery, not at the moment the caller started waiting
// for the gate (an in-place live-filter swap advances the epoch while the
// session runs, and rows delivered after it carry the new epoch). This is
// freshness, not a safety property: an epoch read before the gate could only
// be older, and a restart-style filter change retires the session (which this
// gate then drops) before it advances the epoch either way.
//
// The row is a value on purpose: through an interface a pointer would make
// the caller's per-event row escape to the heap (see runtime.RowEmitter).
func (e sessionRowEmitter) EmitRow(row streamrow.Row) {
	r := e.view.bindings
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.session != e.view.session {
		return
	}
	if r.streamBuffer != nil {
		r.streamBuffer.Push(row)
	}
	if r.recorder != nil {
		r.recordAndWarnLocked(r.recorder, row, r.filterEpoch.Load(), runtime.RecorderWarningText)
	}
}

// recordAndWarnLocked records row through rec and publishes the warning that
// describe derives from the result - the one step shared by the gated
// recorder view (RecordWarning) and the session's single-gate emitter
// (EmitRow). The caller must hold r.mu and know the session is current.
func (r *runtimeBindings) recordAndWarnLocked(rec runtime.RowRecorder, row streamrow.Row, filterEpoch uint64, describe func(rec runtime.RowRecorder, result error) string) {
	result := rec.Record(row, filterEpoch)
	// describe claims a failure (TakeFailure marks it reported), so only ask
	// when the warning can be delivered; otherwise the failure stays
	// available to the record modal and the quit path.
	if !r.canPushWarningLocked() {
		return
	}
	if message := describe(rec, result); message != "" {
		r.pushWarningLocked(message)
	}
}

// canPushWarningLocked reports whether a warning row has somewhere to go: the
// stream buffer and its sequencer both exist. The caller must hold r.mu.
func (r *runtimeBindings) canPushWarningLocked() bool {
	return r.streamBuffer != nil && r.streamSeq != nil
}

// pushWarningLocked appends a warning row to the stream buffer. The caller is
// inside emitIfCurrent, so the session is known to be current and the gated
// sink must not be used here: it would take the read lock a second time, which
// deadlocks when endSession is waiting for the write lock in between. The
// sequence number comes from the same sequencer the trace core's warning
// callback uses, so rows stay strictly ordered.
func (r *runtimeBindings) pushWarningLocked(message string) {
	if !r.canPushWarningLocked() {
		return
	}
	r.streamBuffer.Push(streamrow.NewWarning(r.streamSeq.Next(), message))
}
