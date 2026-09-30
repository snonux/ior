package statsengine

import (
	"time"

	"ior/internal/types"
)

// defaultAggregateDrainPeriod is the aggregate drain period assumed until the
// event loop reports its own via SetAggregateDrainPeriod. It equals
// defaultAggregateDrainEvery in package internal.
const defaultAggregateDrainPeriod = time.Second

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
//
// Aggregate rows carry no inter-syscall gap (the kernel sums only counts and
// latencies), so they add to totalSyscalls but not to totalGap or the gap
// histogram and series, nor to the gap mean's sample count: the gap mean is
// one between traced calls, whose gaps span the untraced ones (see
// tracedGapMean).
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
	// Weight the batch by its timed invocations and spread it over the time
	// it accrued in, so it counts like the per-event pairs it stands for
	// (see AddSpread). A batch without timed invocations adds nothing.
	e.latencySeries.AddSpread(float64(batchLatency), batchCount, e.aggregateSpanStart(now), now)
	e.lastAggregateAt = now
}

// SetAggregateDrainPeriod tells the engine how often the event loop drains the
// kernel aggregates, which bounds how far back a batch is spread in the
// latency series. A non-positive period restores the default.
func (e *Engine) SetAggregateDrainPeriod(period time.Duration) {
	if e == nil {
		return
	}
	if period <= 0 {
		period = defaultAggregateDrainPeriod
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.aggregateSpan = period
}

// aggregateSpanStart returns when the batch ingested at now began to accrue:
// the previous batch's ingestion, but no earlier than one drain period
// before now and no earlier than the engine's start. The period cap matters
// because the drainer forwards no empty batches, so after an idle stretch
// the previous batch can be much older than what the kernel map covers.
func (e *Engine) aggregateSpanStart(now time.Time) time.Time {
	from := now.Add(-e.aggregateSpan)
	if e.lastAggregateAt.After(from) {
		from = e.lastAggregateAt
	}
	if e.startedAt.After(from) {
		from = e.startedAt
	}
	return from
}
