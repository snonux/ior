package statsengine

import (
	"math"
	"testing"
	"time"

	"ior/internal/types"
)

func TestIngestSyscallAggregatesUpdatesSnapshot(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{
			TraceID:        types.SYS_ENTER_FUTEX,
			Count:          3,
			Errors:         1,
			TotalLatencyNs: 90,
			MinLatencyNs:   10,
			MaxLatencyNs:   50,
			LatencyHistogramNs: [8]uint64{
				1, 1, 1, 0, 0, 0, 0, 0,
			},
		},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 3 {
		t.Fatalf("TotalSyscalls = %d, want 3", snap.TotalSyscalls)
	}
	if snap.TotalErrors != 1 {
		t.Fatalf("TotalErrors = %d, want 1", snap.TotalErrors)
	}
	if snap.LatencyHistogram.Total != 3 {
		t.Fatalf("LatencyHistogram.Total = %d, want 3", snap.LatencyHistogram.Total)
	}

	syscalls := snap.Syscalls()
	var futexRow *SyscallSnapshot
	for i := range syscalls {
		row := &syscalls[i]
		if row.TraceID == types.SYS_ENTER_FUTEX {
			futexRow = row
			break
		}
	}
	if futexRow == nil {
		t.Fatal("expected futex syscall row")
	}
	if futexRow.Count != 3 || futexRow.Errors != 1 {
		t.Fatalf("futex row = %+v, want count=3 errors=1", *futexRow)
	}
	if futexRow.LatencyMinNs != 10 || futexRow.LatencyMaxNs != 50 {
		t.Fatalf("futex min/max = %d/%d, want 10/50", futexRow.LatencyMinNs, futexRow.LatencyMaxNs)
	}
}

// Aggregate rows carry no gap data, so they must not enter the gap mean's
// denominator: 2 pairs with gaps 4/8ns plus 1000 aggregated calls still have
// a gap mean of 6ns, not 12/1002.
func TestGapMeanIgnoresAggregateRows(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 4))
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 8))
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{TraceID: types.SYS_ENTER_FUTEX, Count: 1000, TotalLatencyNs: 10_000},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 1002 {
		t.Fatalf("TotalSyscalls = %d, want 1002", snap.TotalSyscalls)
	}
	if snap.GapMeanNs != 6 {
		t.Fatalf("GapMeanNs = %v, want 6", snap.GapMeanNs)
	}
}

// With only aggregate rows there is no gap sample at all: the mean is 0, not
// a division by zero or a value diluted by the aggregated count.
func TestGapMeanWithOnlyAggregateRowsIsZero(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.IngestSyscallAggregates([]SyscallAggregate{
		{TraceID: types.SYS_ENTER_FUTEX, Count: 5, TotalLatencyNs: 50},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.GapMeanNs != 0 || snap.GapHistogram.Total != 0 {
		t.Fatalf("gap mean/hist total = %v/%d, want 0/0", snap.GapMeanNs, snap.GapHistogram.Total)
	}
}

// Reset must forget the gap samples, or the next session's gap mean divides
// by pairs of the previous one.
func TestResetClearsGapSamples(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 100))
	engine.Reset()
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 10, 30))

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.GapMeanNs != 30 {
		t.Fatalf("GapMeanNs after reset = %v, want 30", snap.GapMeanNs)
	}
}

// An aggregate batch weighs its timed invocations in the latency series slot:
// one 1000ns pair next to a drain of 99 calls averaging 10ns gives a slot
// mean of (1000+990)/100 = 19.9, not the unweighted (1000+10)/2 = 505.
func TestLatencySeriesWeighsAggregateBatchByTimedCount(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	engine := newEngineWithClock(DefaultTopN, func() time.Time { return now })
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 0, types.UNCLASSIFIED, "p", 1, "", 0, 0, 1000, 1))
	engine.IngestSyscallAggregates([]SyscallAggregate{
		// 100 counted, 1 untimed: the 99 timed calls sum to 990ns.
		{TraceID: types.SYS_ENTER_FUTEX, Count: 100, UntimedCount: 1, TotalLatencyNs: 990},
	})

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	series := snap.LatencySeriesNs()
	if len(series) == 0 || math.Abs(series[len(series)-1]-19.9) > 1e-9 {
		t.Fatalf("latency series = %v, want last point 19.9", series)
	}
}
