package statsengine

import "ior/internal/types"

// SyscallAggregate is the kernel-side aggregate for one sys_enter trace ID.
type SyscallAggregate struct {
	TraceID            types.TraceId
	Count              uint64
	Errors             uint64
	TotalLatencyNs     uint64
	MinLatencyNs       uint64
	MaxLatencyNs       uint64
	LatencyHistogramNs [8]uint64
	// UntimedCount is the part of Count that has no latency: invocations the
	// kernel counted without a start timestamp because its per-tid enter
	// state could not be recorded (ior_count_untimed_syscall in
	// internal/c/filter.c). They add to Count but not to TotalLatencyNs, the
	// histogram or Min/MaxLatencyNs, and a row made only of them carries no
	// latency extrema at all. Zero means every counted invocation is timed.
	// Latency means (per syscall and overall) therefore divide by the timed
	// count only, so they stay right when the kernel falls back to them.
	UntimedCount uint64
}

// timedCount returns the invocations of row that carry a latency.
func (row SyscallAggregate) timedCount() uint64 {
	return timedCount(row.Count, row.UntimedCount)
}

// IngestSyscallAggregates folds kernel aggregate rows into the engine.
func (e *Engine) IngestSyscallAggregates(rows []SyscallAggregate) {
	if e == nil || len(rows) == 0 {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	var batchLatency uint64
	var batchCount uint64
	for _, row := range rows {
		if row.Count == 0 {
			continue
		}

		e.totalSyscalls += row.Count
		e.totalUntimed += row.Count - row.timedCount()
		e.totalErrors += row.Errors
		e.totalLatency += row.TotalLatencyNs
		e.syscalls.AddAggregate(row)
		e.latencyHist.AddBucketCounts(row.LatencyHistogramNs)

		// The latency series is an average over timed invocations only;
		// untimed ones contribute no latency and would drag it down.
		batchLatency += row.TotalLatencyNs
		batchCount += row.timedCount()
	}
	if batchCount > 0 {
		e.latencySeries.Add(float64(batchLatency)/float64(batchCount), now)
	}
}
