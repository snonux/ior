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
//     probe is attached when the recording starts. The rates themselves never
//     change while ior runs - they come from the command line and are loaded
//     into the BPF program once per session with the same values - so there
//     is nothing to flag for a mid-recording rate change. The attached probes
//     can change (the probes modal); a sampled syscall attached later still
//     appears in the totals, with its rate, once it was invoked.
//   - Totals: the recording's own window only. Each recording starts a fresh
//     sampling.Tally; rows are counted as the recorder writes them and kernel
//     counts are added only while it is active, with the drain loop flushed at
//     the start, at the stop and before a session retires (a filter restart
//     during the recording), so a second recording never inherits the first's
//     counts and no drain period is lost or borrowed at the edges.
//   - Totals are "unavailable" when the kernel counts of the window are
//     incomplete (a filter they cannot honour, a failed drain), and a lower
//     bound when events were lost (ring-buffer drops, rows shed by the
//     recorder's full queue).
//
// The stats engine is deliberately not the source: it is reset every 30s by
// default and on every live filter swap, and replaced by every trace restart.

// recordingSampler is what recorderStart/recorderStop need for that marking;
// *runtimeBindings implements it. Nil means "no marking" (tests, no runtime).
type recordingSampler interface {
	// beginRecordingSampling flushes the kernel counters (so earlier counts go
	// to no recording) and returns a fresh tally for the new recording, nil
	// when the trace samples nothing.
	beginRecordingSampling() *sampling.Tally
	// flushRecordingAggregates drains the kernel counters into the active
	// recording right before it stops.
	flushRecordingAggregates()
}

var _ recordingSampler = (*runtimeBindings)(nil)

// flushRecordingSampling is flushRecordingAggregates for an optional sampler.
func flushRecordingSampling(sampler recordingSampler) {
	if sampler != nil {
		sampler.flushRecordingAggregates()
	}
}

// beginRecordingSampling implements recordingSampler. The tally restricts the
// announced rates to the probes attached now (as the raw modes do); without a
// probe manager (between sessions) every sampled syscall is announced.
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
	if source != nil {
		source.FlushAggregates()
	}
	return sampling.NewTally(entries, attachedProbes(manager))
}

// flushRecordingAggregates implements recordingSampler.
func (r *runtimeBindings) flushRecordingAggregates() {
	if r == nil {
		return
	}
	r.mu.RLock()
	source := r.recordingSampling
	r.mu.RUnlock()
	if source != nil {
		source.FlushAggregates()
	}
}

// flushSessionForRecording drains session's kernel counters into the active
// recording while session is still current, just before it is retired. It
// must run without r.mu held: the drained counts reach the recorder through
// the session gate, which takes the read lock.
func (r *runtimeBindings) flushSessionForRecording(session uint64) {
	r.mu.RLock()
	current := r.session == session
	source := r.recordingSampling
	recorder := r.recorder
	r.mu.RUnlock()
	if !current || source == nil || !recorderActive(recorder) {
		return
	}
	source.FlushAggregates()
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
