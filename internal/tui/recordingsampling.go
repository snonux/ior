package tui

import (
	"ior/internal/runtime"
	"ior/internal/sampling"
)

// The TUI side of marking an R recording as sampled (task qs2). A recording
// gets the footer keys a sampled raw-mode file gets (parquet.KeySampling,
// parquet.KeySamplingTotals) with these semantics:
//
//   - Rates: the sampled syscalls of the trace (effective rate other than 1,
//     including the aggregate-only defaults futex*, clock_gettime, ...) whose
//     probe is attached when the recording starts. With the default
//     -trace-families (FS only) none of those defaults is attached, so a
//     default recording carries neither key; they appear once their probes
//     are (-trace-families IPC,Time, the probes modal). The rates themselves
//     never change while ior runs - they come from the command line and are
//     loaded into the BPF program once per session with the same values - so
//     there is nothing to flag for a mid-recording rate change. The attached
//     probes can change (the probes modal); a sampled syscall attached later
//     still appears in the totals, with its rate, once it was invoked.
//   - Totals: the recording's own window only. Each recording starts a fresh
//     sampling.Tally; rows are counted as the recorder writes them and kernel
//     counts and ring-buffer drops are added only while it is active, with
//     the drain loop and the drop monitor flushed at the start, at the stop
//     and before a session retires (a filter restart during the recording),
//     so a second recording never inherits the first's counts or drops and no
//     poll period is lost or borrowed at the edges.
//   - Totals are "unavailable" when the kernel counts of the window are
//     incomplete (a filter they cannot honour, a failed drain - including
//     the one right before the start, which could leak pre-start counts into
//     the window), and a lower bound when events were lost (ring-buffer drops,
//     rows shed by the recorder's full queue, or a session retired while its
//     event loop may still deliver rows, which the session gate then drops).
//
// The stats engine is deliberately not the source: it is reset every 30s by
// default and on every live filter swap, and replaced by every trace restart.

// recordingSampler is what recorderStart/recorderStop need for that marking;
// *runtimeBindings implements it. Nil means "no marking" (tests, no runtime).
type recordingSampler interface {
	// beginRecordingSampling flushes the kernel counters and the drop counter
	// (so earlier counts and drops go to no recording) and returns a fresh
	// tally for the new recording, nil when the trace samples nothing.
	beginRecordingSampling() *sampling.Tally
	// flushRecordingCounters drains the kernel counters and the drop counter
	// into the active recording right before it stops.
	flushRecordingCounters()
}

var _ recordingSampler = (*runtimeBindings)(nil)

// flushRecordingSampling is flushRecordingCounters for an optional sampler.
func flushRecordingSampling(sampler recordingSampler) {
	if sampler != nil {
		sampler.flushRecordingCounters()
	}
}

// drainFailedReason is the unavailable reason of a recording whose kernel
// counts could not be read, the words the trace core uses for a failed drain
// during a recording (forwardAggregatesToRecording).
const drainFailedReason = "reading the kernel counters failed"

// beginRecordingSampling implements recordingSampler. The tally restricts the
// announced rates to the probes attached now (as the raw modes do); without a
// probe manager (between sessions) every sampled syscall is announced.
//
// The flush runs before the recording starts, so a drain failure it reports
// reaches no recording through the trace core; it is put on the new tally
// instead: the deltas the failed drain did not reach are still in the kernel
// map and the first successful drain would add them to this window.
func (r *runtimeBindings) beginRecordingSampling() *sampling.Tally {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	entries := r.sampledSyscalls
	source := r.recordingSampling
	manager := r.probeManager
	r.mu.RUnlock()
	if len(entries) == 0 {
		return nil
	}
	complete := source == nil || source.FlushCounters()
	tally := sampling.NewTally(entries, attachedProbes(manager))
	if !complete {
		tally.MarkUnavailable(drainFailedReason)
	}
	return tally
}

// flushRecordingCounters implements recordingSampler. A failed drain needs no
// handling here: the recording is active, so the trace core marks it.
func (r *runtimeBindings) flushRecordingCounters() {
	if r == nil {
		return
	}
	r.mu.RLock()
	source := r.recordingSampling
	r.mu.RUnlock()
	if source != nil {
		source.FlushCounters()
	}
}

// flushSessionForRecording drains session's kernel counters and drop counter
// into the active recording while session is still current, just before it is
// retired. It must run without r.mu held: the drained counts reach the
// recorder through the session gate, which takes the read lock.
//
// A session whose event loop may still run (its live-filter setter is still
// registered: the trace core registers it before the loop starts and removes
// it only after the loop returned, i.e. after its last row, drain and drop
// read) can deliver rows, kernel counts and drops after the flush, which the
// retired session's gate then drops: invocations of the window that are in
// neither the file nor the totals. The restart does not wait for the old
// session (traceLifecycle.beginCmd), so instead of draining that backlog the
// recording's totals become a lower bound. A session whose loop has returned
// (or never started) delivered everything while it was current, and its
// recording stays exact.
func (r *runtimeBindings) flushSessionForRecording(session uint64) {
	r.mu.RLock()
	current := r.session == session
	source := r.recordingSampling
	recorder := r.recorder
	loopMayRun := r.liveFilterSetter != nil
	r.mu.RUnlock()
	if !current || source == nil || !recorderActive(recorder) {
		return
	}
	source.FlushCounters()
	if !loopMayRun {
		return
	}
	if counter, ok := recorder.(runtime.RecordingSamplingCounter); ok {
		counter.MarkSamplingLowerBound()
	}
}

// attachedProbes turns the probe manager's states into the attached-probe
// predicate of sampling.NewTally; nil (all attached) without a manager.
func attachedProbes(manager runtime.ProbeManager) func(string) bool {
	if manager == nil {
		return nil
	}
	active := make(map[string]bool)
	for _, state := range manager.States() {
		if state.Active {
			active[state.Syscall] = true
		}
	}
	return func(syscall string) bool { return active[syscall] }
}

// SetRecordingSampling publishes the session's sampling description and
// drain flush while the session is current (see recordingSampler).
func (s traceSessionBindings) SetRecordingSampling(source runtime.RecordingSampling) {
	s.bindings.updateIfCurrent(s.session, func() {
		s.bindings.recordingSampling = source
		s.bindings.sampledSyscalls = source.SampledSyscalls()
	})
}

// samplingCounter returns the TUI recorder's sampling side, or nil when the
// recorder does not keep sampling totals (a test fake).
func (k sessionRecorder) samplingCounter() runtime.RecordingSamplingCounter {
	counter, _ := k.RecordingController.(runtime.RecordingSamplingCounter)
	return counter
}

// CountKernelOnly forwards kernel counts to the recorder while the session is
// current: a retired session's late drain must not reach a recording.
func (k sessionRecorder) CountKernelOnly(syscall string, n uint64) {
	if counter := k.samplingCounter(); counter != nil {
		k.view.bindings.emitIfCurrent(k.view.session, func() { counter.CountKernelOnly(syscall, n) })
	}
}

// MarkSamplingLowerBound forwards a loss while the session is current.
func (k sessionRecorder) MarkSamplingLowerBound() {
	if counter := k.samplingCounter(); counter != nil {
		k.view.bindings.emitIfCurrent(k.view.session, counter.MarkSamplingLowerBound)
	}
}

// MarkSamplingUnavailable forwards incomplete kernel counts while the session
// is current.
func (k sessionRecorder) MarkSamplingUnavailable(reason string) {
	if counter := k.samplingCounter(); counter != nil {
		k.view.bindings.emitIfCurrent(k.view.session, func() { counter.MarkSamplingUnavailable(reason) })
	}
}
