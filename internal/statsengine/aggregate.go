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
		e.totalErrors += row.Errors
		e.totalLatency += row.TotalLatencyNs
		e.syscalls.AddAggregate(row)
		e.families.AddAggregate(row)
		e.latencyHist.AddBucketCounts(row.LatencyHistogramNs)

		batchLatency += row.TotalLatencyNs
		batchCount += row.Count
	}
	if batchCount > 0 {
		e.latencySeries.Add(float64(batchLatency)/float64(batchCount), now)
	}
}
