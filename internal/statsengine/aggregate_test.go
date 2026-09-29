package statsengine

import (
	"testing"

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
