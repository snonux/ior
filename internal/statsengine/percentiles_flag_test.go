package statsengine

import (
	"testing"

	"ior/internal/types"
)

// TestSnapshotNoPercentilesMarksRowsWithoutSamples (task 003): a syscall that
// is aggregate-only (sampling rate 0, e.g. futex) has a timed mean/min/max from
// the kernel aggregate but no per-invocation latency in the percentile
// reservoir, so its P50/P95/P99 are 0 placeholders and the snapshot says so.
// A syscall with at least one streamed, timed pair has percentiles; a mix of
// both (rate N: streamed pairs plus aggregate rows) has them too.
func TestSnapshotNoPercentilesMarksRowsWithoutSamples(t *testing.T) {
	e := NewEngine(10)
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 10, types.READ_CLASSIFIED, "proc", 4300, "/f", 10, 0, 1000, 0))
	e.IngestSyscallAggregates([]SyscallAggregate{
		timedRow(types.SYS_ENTER_FUTEX, 40, 60),
		timedRow(types.SYS_ENTER_READ, 40, 60),
		{TraceID: types.SYS_ENTER_EXIT, Count: 3, UntimedCount: 3},
	})
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct{ noLatency, noPercentiles, noData bool }{
		"futex": {false, true, true},   // timed aggregate, no samples
		"read":  {false, false, false}, // a streamed pair plus an aggregate row
		"exit":  {true, true, true},    // nothing timed at all
	} {
		row := findSyscall(t, snap.Syscalls(), name)
		if row.NoLatency != want.noLatency || row.NoPercentiles != want.noPercentiles || row.NoPercentileData() != want.noData {
			t.Errorf("%s: NoLatency=%v NoPercentiles=%v NoPercentileData=%v, want %+v (row %+v)",
				name, row.NoLatency, row.NoPercentiles, row.NoPercentileData(), want, row)
		}
	}
	if futex := findSyscall(t, snap.Syscalls(), "futex"); futex.LatencyMeanNs == 0 || futex.LatencyMaxNs == 0 {
		t.Errorf("the aggregate-only row must keep its timed mean/max: %+v", futex)
	}
}
