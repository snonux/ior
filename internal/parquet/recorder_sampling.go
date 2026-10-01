package parquet

import "ior/internal/sampling"

// The sampling side of a recording that counts its own totals
// (StartOptions.SamplingTally, used by the TUI's R recordings). Its rows are
// counted where they are written (bufferRecord); everything else reaches the
// tally through the methods below, which act on the active recording only: a
// count that arrives while no recording runs belongs to no recording and is
// dropped, which is what makes each recording's totals its own delta.

// CountKernelOnly adds n invocations of syscall that the kernel counted
// without emitting a row (a drained syscall_aggregate_map delta) to the active
// recording's sampling tally. A no-op without an active recording or tally.
func (r *Recorder) CountKernelOnly(syscall string, n uint64) {
	r.activeTally().CountUntraced(syscall, n)
}

// MarkSamplingLowerBound records that events were lost while the active
// recording ran (ring-buffer drops), so its sampling totals are only a lower
// bound. A no-op without an active recording or tally.
func (r *Recorder) MarkSamplingLowerBound() {
	r.activeTally().MarkLowerBound()
}

// MarkSamplingUnavailable records that the active recording's kernel counts
// are incomplete, and why (a filter the syscall-keyed counters cannot honour, a
// failed drain); its footer then says "unavailable" instead of totals. A no-op
// without an active recording or tally.
func (r *Recorder) MarkSamplingUnavailable(reason string) {
	r.activeTally().MarkUnavailable(reason)
}

// activeTally returns the active recording's tally, or nil (whose methods are
// no-ops) when no recording runs or it keeps no tally.
func (r *Recorder) activeTally() *sampling.Tally {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	session := r.active
	r.mu.RUnlock()
	if session == nil {
		return nil
	}
	return session.tally
}

// finishSamplingTally renders the session's tally into the footer's
// KeySamplingTotals, once its last row is counted. Rows shed by a full queue
// were emitted but are neither in the file nor in the kernel count, so any shed
// row makes the totals a lower bound. A session without a tally, or whose tally
// sampled nothing, adds no key.
func (s *recordingSession) finishSamplingTally() {
	if s.tally == nil {
		return
	}
	if s.dropped.Load() > 0 {
		s.tally.MarkLowerBound()
	}
	totals := s.tally.Summary().Totals()
	if totals == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.footer == nil {
		s.footer = make(map[string]string)
	}
	s.footer[KeySamplingTotals] = totals
}
