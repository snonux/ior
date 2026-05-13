package statsengine

import (
	"math"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.now = c.now.Add(d)
}

func TestEngineIngestAndSnapshotIntegration(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine := newEngineWithClock(2, clock.Now)

	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 100, types.READ_CLASSIFIED, "proc-a", 1, "/tmp/a", 100, 10, 3))
	clock.Advance(500 * time.Millisecond)
	engine.Ingest(newEnginePair(types.SYS_ENTER_WRITE, -1, types.WRITE_CLASSIFIED, "proc-a", 1, "/tmp/a", 50, 20, 5))
	clock.Advance(500 * time.Millisecond)
	engine.Ingest(newEnginePair(types.SYS_ENTER_COPY_FILE_RANGE, 80, types.TRANSFER_CLASSIFIED, "proc-b", 2, "/tmp/b", 20, 40, 8))
	clock.Advance(1 * time.Second)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if snap == nil {
		t.Fatalf("expected snapshot")
	}

	if snap.TotalSyscalls != 3 || snap.TotalErrors != 1 || snap.TotalBytes != 170 {
		t.Fatalf("unexpected totals: syscalls=%d errors=%d bytes=%d", snap.TotalSyscalls, snap.TotalErrors, snap.TotalBytes)
	}
	if snap.LatencyMeanNs != (10+20+40)/3.0 {
		t.Fatalf("unexpected latency mean: %v", snap.LatencyMeanNs)
	}
	if snap.GapMeanNs != (3+5+8)/3.0 {
		t.Fatalf("unexpected gap mean: %v", snap.GapMeanNs)
	}

	if math.Abs(snap.SyscallRatePerSec-1.5) > 1e-9 {
		t.Fatalf("unexpected syscall rate: %v", snap.SyscallRatePerSec)
	}
	if math.Abs(snap.ErrorRatePerSec-0.5) > 1e-9 {
		t.Fatalf("unexpected error rate: %v", snap.ErrorRatePerSec)
	}
	if math.Abs(snap.ReadBytesPerSec-60.0) > 1e-9 {
		t.Fatalf("unexpected read bytes rate: %v", snap.ReadBytesPerSec)
	}
	if math.Abs(snap.WriteBytesPerSec-35.0) > 1e-9 {
		t.Fatalf("unexpected write bytes rate: %v", snap.WriteBytesPerSec)
	}

	if len(snap.Syscalls()) != 3 {
		t.Fatalf("expected 3 syscall rows, got %d", len(snap.Syscalls()))
	}
	if len(snap.Files()) != 2 {
		t.Fatalf("expected top 2 files due to topN=2, got %d", len(snap.Files()))
	}
	if len(snap.Processes()) != 2 {
		t.Fatalf("expected 2 process rows, got %d", len(snap.Processes()))
	}
	if snap.LatencyHistogram.Total != 3 || snap.GapHistogram.Total != 3 {
		t.Fatalf("unexpected histogram totals: latency=%d gap=%d", snap.LatencyHistogram.Total, snap.GapHistogram.Total)
	}
}

func TestEngineSnapshotWithNoEvents(t *testing.T) {
	clock := &fakeClock{now: time.Unix(2000, 0)}
	engine := newEngineWithClock(10, clock.Now)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if snap == nil {
		t.Fatalf("expected snapshot")
	}
	if snap.TotalSyscalls != 0 || snap.TotalErrors != 0 || snap.TotalBytes != 0 {
		t.Fatalf("expected zero totals, got %+v", snap)
	}
	if len(snap.Syscalls()) != 0 || len(snap.Files()) != 0 || len(snap.Processes()) != 0 {
		t.Fatalf("expected empty rows in zero snapshot")
	}
}

func TestEngineTrendDetection(t *testing.T) {
	if got := detectTrend(make([]float64, trendWindowSlots*2)); got.Direction != TrendStable {
		t.Fatalf("expected stable for flat data, got %+v", got)
	}

	series := make([]float64, trendWindowSlots*2)
	for i := 0; i < trendWindowSlots; i++ {
		series[i] = 10
	}
	for i := trendWindowSlots; i < trendWindowSlots*2; i++ {
		series[i] = 30
	}
	if got := detectTrend(series); got.Direction != TrendRising {
		t.Fatalf("expected rising trend, got %+v", got)
	}

	for i := 0; i < trendWindowSlots; i++ {
		series[i] = 40
	}
	for i := trendWindowSlots; i < trendWindowSlots*2; i++ {
		series[i] = 10
	}
	if got := detectTrend(series); got.Direction != TrendFalling {
		t.Fatalf("expected falling trend, got %+v", got)
	}
}

func newEnginePair(traceID types.TraceId, ret int64, retType uint32, comm string, pid uint32, path string, bytes uint64, duration uint64, gap uint64) *event.Pair {
	return &event.Pair{
		EnterEv:        &types.RetEvent{TraceId: traceID, Pid: pid},
		ExitEv:         &types.RetEvent{TraceId: traceID, Pid: pid, Ret: ret, RetType: retType},
		Comm:           comm,
		Duration:       duration,
		DurationToPrev: gap,
		Bytes:          bytes,
		File:           file.NewFd(3, path, -1),
	}
}
