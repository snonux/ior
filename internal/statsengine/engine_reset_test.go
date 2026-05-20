package statsengine

import (
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
