package statsengine

import (
	"sync"
	"testing"
	"time"

	"ior/internal/types"
)

func TestEngineResetClearsAccumulatedStats(t *testing.T) {
	e := NewEngine(8)
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "test", 1, "/tmp/a", 7, 512, 1000, 50))
	before, err := e.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if before.TotalSyscalls == 0 {
		t.Fatalf("expected non-zero totals before reset")
	}

	e.Reset()
	after, err := e.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error after reset: %v", err)
	}
	if after.TotalSyscalls != 0 || after.TotalBytes != 0 || after.TotalAddressSpaceBytes != 0 || after.TotalErrors != 0 {
		t.Fatalf("expected totals cleared after reset, got %+v", after)
	}
	if after.Elapsed > 2*time.Second {
		t.Fatalf("expected elapsed to restart near zero, got %s", after.Elapsed)
	}
}

// TestEngineResetConcurrentWithIngestAndSnapshot is the regression guard for
// audit finding M5 (AUDIT-REPORT.md section 3, evidence
// audit/domain-03-statsengine.md F2): Reset, Ingest and Snapshot all serialize
// on the engine mutex, so a baseline reset while events stream in must never
// expose a half-reset engine. The test hammers all three operations from
// concurrent goroutines (run under -race in the task verification) and asserts
// per-snapshot consistency plus deterministic behavior afterwards.
func TestEngineResetConcurrentWithIngestAndSnapshot(t *testing.T) {
	e := NewEngine(8)

	const (
		ingesters = 4
		ingests   = 400
		snapshots = 200
		resets    = 20
	)

	var wg sync.WaitGroup
	for g := 0; g < ingesters; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < ingests; i++ {
				// Alternate successful and failed calls so totals and error
				// counters are exercised together.
				ret := int64(7)
				if i%2 == 1 {
					ret = -5
				}
				e.Ingest(newEnginePair(types.SYS_ENTER_READ, ret, types.READ_CLASSIFIED, "reset-race", uint32(g+1), "/tmp/a", 512, 1000, 50, 0))
			}
		}(g)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < resets; i++ {
			e.Reset()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < snapshots; i++ {
			snap, err := e.Snapshot()
			if err != nil {
				t.Errorf("concurrent Snapshot() error: %v", err)
				return
			}
			// Every error is also a syscall, so a snapshot torn by a
			// concurrent reset would break this invariant.
			if snap.TotalErrors > snap.TotalSyscalls {
				t.Errorf("inconsistent snapshot: TotalErrors(%d) > TotalSyscalls(%d)", snap.TotalErrors, snap.TotalSyscalls)
				return
			}
		}
	}()

	wg.Wait()

	// After concurrent Reset+Ingest traffic, the engine must still behave
	// deterministically for a sequential caller: a final reset clears
	// everything and one ingest produces exactly one syscall.
	e.Reset()
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatalf("post-race Snapshot() error: %v", err)
	}
	if snap.TotalSyscalls != 0 || snap.TotalErrors != 0 || snap.TotalBytes != 0 {
		t.Fatalf("post-race Reset() left totals: %+v", snap)
	}

	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "reset-race", 1, "/tmp/a", 512, 1000, 50, 0))
	snap, err = e.Snapshot()
	if err != nil {
		t.Fatalf("post-race ingest Snapshot() error: %v", err)
	}
	if snap.TotalSyscalls != 1 {
		t.Fatalf("post-race ingest TotalSyscalls = %d, want 1", snap.TotalSyscalls)
	}
}
