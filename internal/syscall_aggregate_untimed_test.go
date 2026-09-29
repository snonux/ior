package internal

import (
	"testing"

	"ior/internal/statsengine"
	"ior/internal/types"
)

// Untimed counts are invocations the kernel counted without a duration
// because their syscall_enter_state_map write failed
// (ior_count_untimed_syscall in internal/c/filter.c). Such a per-CPU slot
// bumps Count only, so its min = max = 0 are not latencies.

// A slot with only untimed counts used to pull the merged minimum down to 0
// whenever it was merged into a slot with real latencies.
func TestDecodeRawSyscallAggregatePerCPUIgnoresUntimedSlotExtrema(t *testing.T) {
	timed := rawSyscallAggregate{
		Count:         2,
		TotalDuration: 30_000,
		MinDuration:   10_000,
		MaxDuration:   20_000,
		Histogram:     [8]uint64{0, 1, 1},
	}
	untimed := rawSyscallAggregate{Count: 3}

	for name, slots := range map[string][]rawSyscallAggregate{
		"untimed slot first": {untimed, timed},
		"untimed slot last":  {timed, untimed},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeRawSyscallAggregatePerCPU(encodeRawAggregates(t, slots...))
			if err != nil {
				t.Fatalf("decodeRawSyscallAggregatePerCPU error: %v", err)
			}
			want := rawSyscallAggregate{
				Count:         5,
				TotalDuration: 30_000,
				MinDuration:   10_000,
				MaxDuration:   20_000,
				Histogram:     [8]uint64{0, 1, 1},
			}
			if got != want {
				t.Fatalf("merged aggregate = %+v, want %+v", got, want)
			}
			if got.untimedCount() != 3 {
				t.Fatalf("untimedCount = %d, want 3", got.untimedCount())
			}
		})
	}
}

func TestRawSyscallAggregateUntimedCountSaturates(t *testing.T) {
	// Count below the histogram total cannot come from the kernel, but a
	// corrupt value must not wrap into a huge untimed count.
	r := rawSyscallAggregate{Count: 1, Histogram: [8]uint64{2}}
	if got := r.untimedCount(); got != 0 {
		t.Fatalf("untimedCount = %d, want 0", got)
	}
}

// Drain must report the untimed part of each delta so the stats engine keeps
// it out of the latency extrema.
func TestSyscallAggregateConsumerDrainReportsUntimedCount(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	fakeMap := newFakeSyscallAggregateMap(traceID, encodeRawAggregates(t,
		rawSyscallAggregate{Count: 4},
	))
	consumer := &syscallAggregateConsumer{
		aggregateMap: fakeMap,
		last:         make(map[types.TraceId]rawSyscallAggregate),
	}

	rows, err := consumer.Drain()
	if err != nil {
		t.Fatalf("first Drain error: %v", err)
	}
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID:      types.TraceId(traceID),
		Count:        4,
		UntimedCount: 4,
	})

	fakeMap.values[traceID] = encodeRawAggregates(t, rawSyscallAggregate{
		Count:         7,
		TotalDuration: 5_000,
		MinDuration:   2_000,
		MaxDuration:   3_000,
		Histogram:     [8]uint64{0, 2},
	})
	rows, err = consumer.Drain()
	if err != nil {
		t.Fatalf("second Drain error: %v", err)
	}
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID:            types.TraceId(traceID),
		Count:              3,
		UntimedCount:       1,
		TotalLatencyNs:     5_000,
		MinLatencyNs:       2_000,
		MaxLatencyNs:       3_000,
		LatencyHistogramNs: [8]uint64{0, 2},
	})

	// End to end: the engine keeps the untimed counts in the totals but out
	// of the latency extrema.
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	engine.IngestSyscallAggregates([]statsengine.SyscallAggregate{{
		TraceID: types.TraceId(traceID), Count: 4, UntimedCount: 4,
	}})
	engine.IngestSyscallAggregates(rows)
	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	for _, row := range snap.Syscalls() {
		if row.TraceID != types.TraceId(traceID) {
			continue
		}
		if row.Count != 7 || row.LatencyMinNs != 2_000 || row.LatencyMaxNs != 3_000 {
			t.Fatalf("futex row count/min/max = %d/%d/%d, want 7/2000/3000",
				row.Count, row.LatencyMinNs, row.LatencyMaxNs)
		}
		return
	}
	t.Fatal("no futex row in snapshot")
}

// drainOne sets the fake map's single value and drains it.
func drainOne(t *testing.T, consumer *syscallAggregateConsumer, fakeMap *fakeSyscallAggregateMap, traceID uint32, value rawSyscallAggregate) []statsengine.SyscallAggregate {
	t.Helper()
	fakeMap.values[traceID] = encodeRawAggregates(t, value)
	rows, err := consumer.Drain()
	if err != nil {
		t.Fatalf("Drain error: %v", err)
	}
	return rows
}

func newTestAggregateConsumer(traceID uint32) (*syscallAggregateConsumer, *fakeSyscallAggregateMap) {
	fakeMap := newFakeSyscallAggregateMap(traceID, nil)
	return &syscallAggregateConsumer{
		aggregateMap: fakeMap,
		last:         make(map[types.TraceId]rawSyscallAggregate),
	}, fakeMap
}

// A slot read while the kernel had bumped the histogram but not yet count
// (count is stored last) holds a completed timed invocation.
func TestDecodeRawSyscallAggregateSlotRaisesCountToHistogramTotal(t *testing.T) {
	got, err := decodeRawSyscallAggregateSlot(encodeRawAggregates(t, rawSyscallAggregate{
		Count: 2, TotalDuration: 3_000, MinDuration: 500, MaxDuration: 1_500, Histogram: [8]uint64{3},
	}))
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got.Count != 3 || got.untimedCount() != 0 {
		t.Fatalf("count/untimed = %d/%d, want 3/0", got.Count, got.untimedCount())
	}
}

// Torn read with count ahead of the histogram (possible on weakly ordered
// CPUs): the invocation is booked untimed once, but its latency, seen on a
// later read that shows no new count, must not be lost when the baseline
// moves on - it is reported with the next row instead.
func TestSyscallAggregateConsumerKeepsLatencyOfTornRead(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 2, TotalDuration: 2_000, MinDuration: 1_000, MaxDuration: 1_000, Histogram: [8]uint64{0, 2},
	})

	rows := drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 3, TotalDuration: 2_000, MinDuration: 1_000, MaxDuration: 1_000, Histogram: [8]uint64{0, 2},
	})
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID: types.TraceId(traceID), Count: 1, UntimedCount: 1, MinLatencyNs: 1_000, MaxLatencyNs: 1_000,
	})

	// The histogram and latency of that invocation land, but no new count.
	rows = drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 3, TotalDuration: 5_000, MinDuration: 1_000, MaxDuration: 3_000, Histogram: [8]uint64{0, 3},
	})
	if len(rows) != 0 {
		t.Fatalf("rows without a new count = %+v, want none", rows)
	}

	rows = drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 4, TotalDuration: 9_000, MinDuration: 1_000, MaxDuration: 4_000, Histogram: [8]uint64{0, 4},
	})
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want one", rows)
	}
	row := rows[0]
	if row.Count != 1 || row.UntimedCount != 0 || row.TotalLatencyNs != 7_000 || row.LatencyHistogramNs[1] != 2 {
		t.Fatalf("row = %+v, want count 1, untimed 0, latency 7000 (3000 held back + 4000), 2 histogram samples", row)
	}
}

// Torn read with the histogram ahead of count: the invocation counts as
// timed right away and the consistent read that follows adds nothing.
func TestSyscallAggregateConsumerHistogramAheadIsTimed(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 1, TotalDuration: 1_000, MinDuration: 1_000, MaxDuration: 1_000, Histogram: [8]uint64{0, 1},
	})
	rows := drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 1, TotalDuration: 3_000, MinDuration: 1_000, MaxDuration: 2_000, Histogram: [8]uint64{0, 2},
	})
	if len(rows) != 1 || rows[0].Count != 1 || rows[0].UntimedCount != 0 || rows[0].TotalLatencyNs != 2_000 {
		t.Fatalf("rows = %+v, want one timed invocation of 2000ns", rows)
	}
	rows = drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{
		Count: 2, TotalDuration: 3_000, MinDuration: 1_000, MaxDuration: 2_000, Histogram: [8]uint64{0, 2},
	})
	if len(rows) != 0 {
		t.Fatalf("rows after the count caught up = %+v, want none", rows)
	}
}

// A kernel row that went backwards was recreated; its untimed invocations
// are new and must be reported again.
func TestSyscallAggregateConsumerRestartsUntimedTallyOnReset(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{Count: 5})
	rows := drainOne(t, consumer, fakeMap, traceID, rawSyscallAggregate{Count: 2})
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID: types.TraceId(traceID), Count: 2, UntimedCount: 2,
	})
}
