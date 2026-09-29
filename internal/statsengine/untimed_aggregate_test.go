package statsengine

import (
	"testing"
	"time"

	"ior/internal/types"
)

// Untimed aggregate counts come from the kernel fallback for a full
// syscall_enter_state_map (ior_count_untimed_syscall in internal/c/filter.c):
// they are real invocations without a latency. These tests pin that they add
// to the counts but never seed, lower or dilute the latency extrema and the
// latency series.

func untimedRow(traceID types.TraceId, count uint64) SyscallAggregate {
	return SyscallAggregate{TraceID: traceID, Count: count, UntimedCount: count}
}

func timedRow(traceID types.TraceId, minNs, maxNs uint64) SyscallAggregate {
	return SyscallAggregate{
		TraceID:            traceID,
		Count:              2,
		TotalLatencyNs:     minNs + maxNs,
		MinLatencyNs:       minNs,
		MaxLatencyNs:       maxNs,
		LatencyHistogramNs: [8]uint64{0, 0, 2},
	}
}

func futexStats(t *testing.T, acc *syscallAccumulator) *syscallStats {
	t.Helper()
	stats := acc.byID[types.SYS_ENTER_FUTEX]
	if stats == nil {
		t.Fatal("no futex stats")
	}
	return stats
}

// An untimed-only first row used to seed the minimum with its 0, which no
// later timed row could raise again: min stayed 0 for the whole session.
func TestAddAggregateUntimedFirstRowDoesNotSeedMinimum(t *testing.T) {
	acc := newSyscallAccumulator()
	acc.AddAggregate(untimedRow(types.SYS_ENTER_FUTEX, 3))
	acc.AddAggregate(timedRow(types.SYS_ENTER_FUTEX, 20_000, 40_000))

	stats := futexStats(t, acc)
	if stats.count != 5 {
		t.Fatalf("count = %d, want 5 (3 untimed + 2 timed)", stats.count)
	}
	if stats.minLatency != 20_000 || stats.maxLatency != 40_000 {
		t.Fatalf("min/max = %d/%d, want 20000/40000", stats.minLatency, stats.maxLatency)
	}
}

func TestAddAggregateUntimedRowDoesNotLowerMinimum(t *testing.T) {
	acc := newSyscallAccumulator()
	acc.AddAggregate(timedRow(types.SYS_ENTER_FUTEX, 20_000, 40_000))
	acc.AddAggregate(untimedRow(types.SYS_ENTER_FUTEX, 4))

	stats := futexStats(t, acc)
	if stats.count != 6 || stats.untimedCount != 4 {
		t.Fatalf("count/untimed = %d/%d, want 6/4", stats.count, stats.untimedCount)
	}
	if stats.minLatency != 20_000 || stats.maxLatency != 40_000 {
		t.Fatalf("min/max = %d/%d, want 20000/40000", stats.minLatency, stats.maxLatency)
	}
}

// The first per-event pair after untimed aggregate counts must seed the
// minimum as well: updateMinMax keys on the timed count, not on count == 1.
func TestAddPairAfterUntimedAggregateSeedsMinimum(t *testing.T) {
	acc := newSyscallAccumulator()
	acc.AddAggregate(untimedRow(types.SYS_ENTER_FUTEX, 2))
	acc.Add(newPair(types.SYS_ENTER_FUTEX, 7_000, 0, 0))

	stats := futexStats(t, acc)
	if stats.count != 3 {
		t.Fatalf("count = %d, want 3", stats.count)
	}
	if stats.minLatency != 7_000 || stats.maxLatency != 7_000 {
		t.Fatalf("min/max = %d/%d, want 7000/7000", stats.minLatency, stats.maxLatency)
	}
}

// A malformed row claiming more untimed than counted invocations is treated
// as fully untimed rather than underflowing the timed count.
func TestAddAggregateClampsOversizedUntimedCount(t *testing.T) {
	acc := newSyscallAccumulator()
	acc.AddAggregate(SyscallAggregate{
		TraceID: types.SYS_ENTER_FUTEX, Count: 2, UntimedCount: 9, MinLatencyNs: 1, MaxLatencyNs: 5,
	})
	acc.AddAggregate(timedRow(types.SYS_ENTER_FUTEX, 30_000, 60_000))

	stats := futexStats(t, acc)
	if got := stats.timedCount(); got != 2 {
		t.Fatalf("timed count = %d, want 2", got)
	}
	if stats.minLatency != 30_000 || stats.maxLatency != 60_000 {
		t.Fatalf("min/max = %d/%d, want 30000/60000", stats.minLatency, stats.maxLatency)
	}
}

func TestIngestSyscallAggregatesLatencySeriesIgnoresUntimedCounts(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.IngestSyscallAggregates([]SyscallAggregate{
		timedRow(types.SYS_ENTER_FUTEX, 40, 60),
		untimedRow(types.SYS_ENTER_CLOCK_GETTIME, 8),
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 10 {
		t.Fatalf("TotalSyscalls = %d, want 10", snap.TotalSyscalls)
	}
	series := snap.LatencySeriesNs()
	if len(series) == 0 || series[len(series)-1] != 50 {
		t.Fatalf("latency series = %v, want last point 50 (mean of the 2 timed calls)", series)
	}
}

// A batch of untimed counts only has no latency to report, so it must not
// add a 0ns point to the latency sparkline: in the same time slot as a timed
// batch with mean 50 it would halve the slot's average to 25.
func TestIngestSyscallAggregatesUntimedOnlyBatchAddsNoLatencyPoint(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	engine := newEngineWithClock(DefaultTopN, func() time.Time { return now })
	engine.IngestSyscallAggregates([]SyscallAggregate{timedRow(types.SYS_ENTER_FUTEX, 40, 60)})
	engine.IngestSyscallAggregates([]SyscallAggregate{untimedRow(types.SYS_ENTER_FUTEX, 5)})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 7 {
		t.Fatalf("TotalSyscalls = %d, want 7", snap.TotalSyscalls)
	}
	series := snap.LatencySeriesNs()
	if len(series) == 0 || series[len(series)-1] != 50 {
		t.Fatalf("latency series = %v, want last point 50", series)
	}
}
