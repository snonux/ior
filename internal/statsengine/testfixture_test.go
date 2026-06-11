package statsengine

import "testing"

func TestSeedTestStatsDataPopulatesSnapshot(t *testing.T) {
	engine := NewEngine(DefaultTopN)
	SeedTestStatsData(engine)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snap == nil {
		t.Fatalf("expected snapshot, got nil")
	}

	if snap.TotalSyscalls == 0 {
		t.Fatalf("expected non-zero total syscalls, got %d", snap.TotalSyscalls)
	}
	if snap.TotalErrors == 0 {
		t.Fatalf("expected at least one error return, got %d", snap.TotalErrors)
	}
	if snap.TotalBytes == 0 {
		t.Fatalf("expected non-zero total bytes, got %d", snap.TotalBytes)
	}

	if len(snap.Syscalls()) == 0 {
		t.Fatalf("expected syscall rows, got none")
	}
	if len(snap.Processes()) == 0 {
		t.Fatalf("expected process rows, got none")
	}
	if len(snap.Files()) == 0 {
		t.Fatalf("expected file rows, got none")
	}

	// Multiple comms should surface as distinct process rows.
	if got := len(snap.Processes()); got < 4 {
		t.Fatalf("expected at least 4 process rows (one per comm), got %d", got)
	}

	// Non-FS syscalls should produce at least one non-FS family row.
	var nonFS bool
	for _, fam := range snap.Families() {
		if fam.Name != "FS" {
			nonFS = true
			break
		}
	}
	if !nonFS {
		t.Fatalf("expected at least one non-FS family row for the Non-IO tab")
	}
}

func TestSeedTestStatsDataNilEngineNoPanic(t *testing.T) {
	// Must not panic when handed a nil engine.
	SeedTestStatsData(nil)
}
