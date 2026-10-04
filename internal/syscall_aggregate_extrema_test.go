package internal

import (
	"testing"

	"ior/internal/statsengine"
	"ior/internal/types"
)

// A drain whose cumulative extrema did not move estimates the delta's extrema
// from histogram bucket bounds. Those bounds must be clamped to the cumulative
// range, or bucket 0 (0..999ns) reports a minimum of 0 and a maximum of 999
// that the stats engine keeps for good.

// timedSlot is a settled slot holding the given latencies, all in the
// histogram bucket given by bucket.
func timedSlot(bucket int, latencies ...uint64) rawSyscallAggregate {
	slot := rawSyscallAggregate{Count: uint64(len(latencies))}
	for i, latency := range latencies {
		slot.TotalDuration += latency
		if i == 0 || latency < slot.MinDuration {
			slot.MinDuration = latency
		}
		slot.MaxDuration = max(slot.MaxDuration, latency)
	}
	slot.Histogram[bucket] = uint64(len(latencies))
	return slot
}

// drainSlots publishes one per-CPU value made of slots and drains it.
func drainSlots(t *testing.T, consumer *syscallAggregateConsumer, fakeMap *fakeSyscallAggregateMap, traceID uint32, slots ...rawSyscallAggregate) []statsengine.SyscallAggregate {
	t.Helper()
	fakeMap.values[traceID] = encodeRawAggregates(t, slots...)
	rows, err := consumer.Drain()
	if err != nil {
		t.Fatalf("Drain error: %v", err)
	}
	return rows
}

// assertRowExtrema checks the single row's min/max.
func assertRowExtrema(t *testing.T, rows []statsengine.SyscallAggregate, wantMin, wantMax uint64) {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want exactly one", rows)
	}
	if rows[0].MinLatencyNs != wantMin || rows[0].MaxLatencyNs != wantMax {
		t.Fatalf("row min/max = %d/%d, want %d/%d", rows[0].MinLatencyNs, rows[0].MaxLatencyNs, wantMin, wantMax)
	}
}

// engineExtrema feeds all rows into a fresh stats engine and returns the
// snapshot's min/max for traceID.
func engineExtrema(t *testing.T, traceID uint32, rows []statsengine.SyscallAggregate) (uint64, uint64) {
	t.Helper()
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	engine.IngestSyscallAggregates(rows)
	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	for _, row := range snap.Syscalls() {
		if row.TraceID == types.TraceId(traceID) {
			return row.LatencyMinNs, row.LatencyMaxNs
		}
	}
	t.Fatalf("no snapshot row for trace id %d", traceID)
	return 0, 0
}

// The reviewer's probe: 500ns, then 800ns, then 600ns, all in bucket 0. The
// later rows used to report min 0 / max 800 and min 0 / max 999, and the
// engine then showed min 0 / max 999 although only 500..800ns happened.
func TestSyscallAggregateConsumerClampsBucketZeroExtrema(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_CLOCK_GETTIME)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	var all []statsengine.SyscallAggregate

	rows := drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 500))
	assertRowExtrema(t, rows, 500, 500)
	all = append(all, rows...)

	rows = drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 500, 800))
	assertRowExtrema(t, rows, 500, 800)
	all = append(all, rows...)

	rows = drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 500, 800, 600))
	assertRowExtrema(t, rows, 500, 800)
	all = append(all, rows...)

	if gotMin, gotMax := engineExtrema(t, traceID, all); gotMin != 500 || gotMax != 800 {
		t.Fatalf("engine min/max = %d/%d, want 500/800", gotMin, gotMax)
	}
}

// A 1ns cumulative minimum (the kernel's floor for a completed invocation)
// keeps a bucket-0 delta at 1ns rather than 0.
func TestSyscallAggregateConsumerNeverReportsZeroMinimum(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_CLOCK_GETTIME)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 1, 40))
	rows := drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 1, 40, 20))
	assertRowExtrema(t, rows, 1, 40)
}

// Multi-CPU merge: a new bucket-0 sample on a CPU whose own slot is far
// slower moves neither merged extremum. The estimate is clamped to the
// merged range (300..5000), not to the slot's own, and the bucket bounds
// still cap the maximum below that range's top.
func TestSyscallAggregateConsumerClampsMergedPerCPUExtrema(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	fast := timedSlot(0, 300, 400)
	var all []statsengine.SyscallAggregate
	all = append(all, drainSlots(t, consumer, fakeMap, traceID, fast, timedSlot(1, 2_000, 5_000))...)

	slow := timedSlot(1, 2_000, 5_000)
	slow.Count++
	slow.TotalDuration += 700
	slow.MinDuration = 700
	slow.Histogram[0] = 1
	rows := drainSlots(t, consumer, fakeMap, traceID, fast, slow)
	assertRowExtrema(t, rows, 300, 999)
	all = append(all, rows...)

	if gotMin, gotMax := engineExtrema(t, traceID, all); gotMin != 300 || gotMax != 5_000 {
		t.Fatalf("engine min/max = %d/%d, want 300/5000", gotMin, gotMax)
	}
}

// An untimed-only drain between timed ones changes no extrema in the engine,
// and the timed bucket-0 drain after it is still clamped.
func TestSyscallAggregateConsumerClampsAfterUntimedDrain(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_CLOCK_GETTIME)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	var all []statsengine.SyscallAggregate
	all = append(all, drainOne(t, consumer, fakeMap, traceID, timedSlot(0, 500, 800))...)

	withUntimed := timedSlot(0, 500, 800)
	withUntimed.Count += 2
	rows := drainOne(t, consumer, fakeMap, traceID, withUntimed)
	if len(rows) != 1 || rows[0].UntimedCount != 2 {
		t.Fatalf("rows = %+v, want one row of 2 untimed invocations", rows)
	}
	all = append(all, rows...)

	next := timedSlot(0, 500, 800, 600)
	next.Count += 2
	rows = drainOne(t, consumer, fakeMap, traceID, next)
	assertRowExtrema(t, rows, 500, 800)
	all = append(all, rows...)

	if gotMin, gotMax := engineExtrema(t, traceID, all); gotMin != 500 || gotMax != 800 {
		t.Fatalf("engine min/max = %d/%d, want 500/800", gotMin, gotMax)
	}
}

// Torn-slot deferral: CPU 1's first sample is read mid-update, so
// normalizeTornSlot defers it and no row is emitted. Once settled, it raises
// the merged maximum (exact) while the minimum comes from the clamped bucket
// estimate, not bucket 0's lower bound.
func TestSyscallAggregateConsumerClampsAfterTornSlotDeferral(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	consumer, fakeMap := newTestAggregateConsumer(traceID)
	cpu0 := timedSlot(0, 500)
	drainSlots(t, consumer, fakeMap, traceID, cpu0)

	torn := rawSyscallAggregate{TotalDuration: 600, Histogram: [8]uint64{1}}
	if rows := drainSlots(t, consumer, fakeMap, traceID, cpu0, torn); len(rows) != 0 {
		t.Fatalf("rows for the torn read = %+v, want none", rows)
	}

	rows := drainSlots(t, consumer, fakeMap, traceID, cpu0, timedSlot(0, 600))
	assertRowExtrema(t, rows, 500, 600)
}

func TestClampToCumulativeExtrema(t *testing.T) {
	cumulative := timedSlot(0, 500, 800)
	tests := []struct {
		name             string
		r                rawSyscallAggregate
		inMin, inMax     uint64
		wantMin, wantMax uint64
	}{
		{name: "bucket bounds outside range", r: cumulative, inMin: 0, inMax: 999, wantMin: 500, wantMax: 800},
		{name: "values inside range kept", r: cumulative, inMin: 600, inMax: 700, wantMin: 600, wantMax: 700},
		{name: "both below range", r: cumulative, inMin: 0, inMax: 10, wantMin: 500, wantMax: 500},
		{name: "both above range", r: cumulative, inMin: 900, inMax: 999, wantMin: 800, wantMax: 800},
		{name: "untimed cumulative passes through", r: rawSyscallAggregate{Count: 3}, inMin: 0, inMax: 999, wantMin: 0, wantMax: 999},
		{name: "zero cumulative min passes through", r: rawSyscallAggregate{Count: 1, MaxDuration: 5, Histogram: [8]uint64{1}}, inMin: 0, inMax: 999, wantMin: 0, wantMax: 999},
		{name: "inverted cumulative passes through", r: rawSyscallAggregate{Count: 1, MinDuration: 9, MaxDuration: 5, Histogram: [8]uint64{1}}, inMin: 0, inMax: 999, wantMin: 0, wantMax: 999},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMin, gotMax := tt.r.clampToCumulativeExtrema(tt.inMin, tt.inMax)
			if gotMin != tt.wantMin || gotMax != tt.wantMax {
				t.Fatalf("clamp(%d, %d) = %d/%d, want %d/%d", tt.inMin, tt.inMax, gotMin, gotMax, tt.wantMin, tt.wantMax)
			}
		})
	}
}
