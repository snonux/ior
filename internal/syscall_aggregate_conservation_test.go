package internal

import (
	"context"
	"testing"
	"time"

	"ior/internal/statsengine"
	"ior/internal/types"
)

// Replays copies made in address order while the kernel is updating a slot:
// count/errors/total were read before the update, the histogram after it.
// Stop's settled read must finish the accounting even if no third call occurs.
func TestAggregateFinalFlushConservesTornRead(t *testing.T) {
	for _, tc := range []struct {
		name          string
		untimed       uint64
		otherCPU      bool
		otherProgress bool
		latencyReady  bool
	}{
		{name: "late latency and error"},
		{name: "late error only", latencyReady: true},
		{name: "prior untimed calls", untimed: 3},
		{name: "another CPU", otherCPU: true},
		{name: "another CPU progresses", otherCPU: true, otherProgress: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const id = types.SYS_ENTER_FUTEX
			consumer, fakeMap := newTestAggregateConsumer(uint32(id))
			first := timedSlot(0, 100)
			first.Count += tc.untimed
			torn := first
			torn.Histogram[0]++
			if tc.latencyReady {
				torn.TotalDuration += 100
			}
			settled := timedSlot(0, 100, 100)
			settled.Count += tc.untimed
			settled.Errors = 1
			other := timedSlot(0, 100)
			publish := func(slot rawSyscallAggregate, progressed bool) {
				slots := []rawSyscallAggregate{slot}
				if tc.otherCPU {
					cpu := other
					if progressed && tc.otherProgress {
						cpu = timedSlot(0, 100, 100)
					}
					slots = append(slots, cpu)
				}
				fakeMap.values[uint32(id)] = encodeRawAggregates(t, slots...)
			}
			engine := statsengine.NewEngine(statsengine.DefaultTopN)
			tally := newSamplingTally(map[types.TraceId]uint32{id: 0}, nil)
			var total statsengine.SyscallAggregate
			drainer := newAggregateDrainer(consumer, map[types.TraceId]struct{}{id: {}}, kernelProcessScope{}, nil)
			stop := drainer.Start(context.Background(), time.Hour, func(result aggregateDrainResult) {
				if result.warning != "" {
					t.Errorf("drain warning: %s", result.warning)
				}
				engine.IngestSyscallAggregates(result.rows)
				tally.IngestSyscallAggregates(result.rows)
				for _, row := range result.rows {
					total.Count += row.Count
					total.Errors += row.Errors
					total.TotalLatencyNs += row.TotalLatencyNs
					total.UntimedCount += row.UntimedCount
					for i, n := range row.LatencyHistogramNs {
						total.LatencyHistogramNs[i] += n
					}
				}
			})
			defer func() { stop() }()
			publish(first, false)
			if !drainer.Flush() {
				t.Fatal("first flush failed")
			}
			publish(torn, true)
			if !drainer.Flush() {
				t.Fatal("torn flush failed")
			}
			publish(settled, true)
			// Exercise the real stop-time poll cycle, not a helper-only diff.
			stop()
			stop = func() {}

			wantTimed := uint64(2)
			if tc.otherCPU {
				wantTimed++
			}
			if tc.otherProgress {
				wantTimed++
			}
			wantCount := wantTimed + tc.untimed
			if total.Count != wantCount || total.Errors != 1 || total.TotalLatencyNs != wantTimed*100 || total.UntimedCount != tc.untimed || total.LatencyHistogramNs != [8]uint64{wantTimed} {
				t.Fatalf("emitted totals = %+v, want count %d, errors 1, latency %d, untimed %d, histogram [%d]", total, wantCount, wantTimed*100, tc.untimed, wantTimed)
			}
			snap, err := engine.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if snap.TotalSyscalls != wantCount || snap.TotalErrors != 1 || snap.LatencyHistogram.Total != wantTimed {
				t.Fatalf("snapshot count/errors/histogram = %d/%d/%d, want %d/1/%d", snap.TotalSyscalls, snap.TotalErrors, snap.LatencyHistogram.Total, wantCount, wantTimed)
			}
			row := findSyscallSnapshot(t, snap.Syscalls(), id)
			if row.Count != wantCount || row.Errors != 1 || row.TotalLatencyNs != wantTimed*100 || row.LatencyMeanNs != 100 || row.LatencyMinNs != 100 || row.LatencyMaxNs != 100 {
				t.Fatalf("final stats = %+v", row)
			}
			if tally.counted[id] != wantCount {
				t.Fatalf("recording tally = %d, want %d", tally.counted[id], wantCount)
			}
			if rows, err := consumer.Drain(); err != nil || len(rows) != 0 {
				t.Fatalf("unchanged settled read = %+v, %v; want no rows", rows, err)
			}
		})
	}
}
