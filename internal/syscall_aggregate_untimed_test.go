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
