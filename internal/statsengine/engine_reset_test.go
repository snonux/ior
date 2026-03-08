package statsengine

import (
	"testing"
	"time"

	"ior/internal/types"
)

func TestEngineResetClearsAccumulatedStats(t *testing.T) {
	e := NewEngine(8)
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "test", 1, "/tmp/a", 7, 1000, 50))
	before := e.Snapshot()
	if before.TotalSyscalls == 0 {
		t.Fatalf("expected non-zero totals before reset")
	}

	e.Reset()
	after := e.Snapshot()
	if after.TotalSyscalls != 0 || after.TotalBytes != 0 || after.TotalErrors != 0 {
		t.Fatalf("expected totals cleared after reset, got %+v", after)
	}
	if after.Elapsed > 2*time.Second {
		t.Fatalf("expected elapsed to restart near zero, got %s", after.Elapsed)
	}
}
