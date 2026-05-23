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

	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 100, types.READ_CLASSIFIED, "proc-a", 1, "/tmp/a", 100, 0, 10, 3))
	clock.Advance(500 * time.Millisecond)
	engine.Ingest(newEnginePair(types.SYS_ENTER_WRITE, -1, types.WRITE_CLASSIFIED, "proc-a", 1, "/tmp/a", 50, 0, 20, 5))
	clock.Advance(500 * time.Millisecond)
	engine.Ingest(newEnginePair(types.SYS_ENTER_COPY_FILE_RANGE, 80, types.TRANSFER_CLASSIFIED, "proc-b", 2, "/tmp/b", 20, 0, 40, 8))
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
	if snap.TotalAddressSpaceBytes != 0 {
		t.Fatalf("unexpected address-space total: %d", snap.TotalAddressSpaceBytes)
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
	families := familyRowsByName(snap.Families())
	if len(families) != 1 {
		t.Fatalf("expected 1 family row, got %d", len(families))
	}
	if fs := families["FS"]; fs.Count != 3 || fs.Errors != 1 || fs.Bytes != 170 {
		t.Fatalf("FS family = %+v, want count=3 errors=1 bytes=170", fs)
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

func TestEngineAggregatesSyscallFamilies(t *testing.T) {
	clock := &fakeClock{now: time.Unix(3000, 0)}
	engine := newEngineWithClock(10, clock.Now)

	engine.Ingest(newEnginePair(types.SYS_ENTER_EPOLL_WAIT, 0, types.UNCLASSIFIED, "poller", 1, "", 0, 0, 100, 1))
	engine.Ingest(newEnginePair(types.SYS_ENTER_POLL, -1, types.UNCLASSIFIED, "poller", 1, "", 0, 0, 300, 2))
	engine.Ingest(newEnginePair(types.SYS_ENTER_GETPID, 0, types.UNCLASSIFIED, "proc", 2, "", 0, 0, 50, 3))
	engine.Ingest(newEnginePair(types.SYS_ENTER_READ, 4, types.READ_CLASSIFIED, "reader", 3, "/tmp/a", 4, 0, 25, 4))
	clock.Advance(time.Second)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}

	families := familyRowsByName(snap.Families())
	polling := families["Polling"]
	if polling.Count != 2 || polling.Errors != 1 || polling.LatencyMeanNs != 200 {
		t.Fatalf("Polling family = %+v, want count=2 errors=1 mean=200ns", polling)
	}
	if families["Process"].Count != 1 {
		t.Fatalf("Process family = %+v, want count=1", families["Process"])
	}
	if families["FS"].Count != 1 || families["FS"].Bytes != 4 {
		t.Fatalf("FS family = %+v, want count=1 bytes=4", families["FS"])
	}

	// Verify that non-FS families exist and FS is present in the full
	// family list — Non-IO filtering has moved to the dashboard package.
	if _, ok := families["Polling"]; !ok {
		t.Fatalf("Families missing Polling row: %+v", families)
	}
	if _, ok := families["Process"]; !ok {
		t.Fatalf("Families missing Process row: %+v", families)
	}
}

func familyRowsByName(rows []FamilySnapshot) map[string]FamilySnapshot {
	result := make(map[string]FamilySnapshot, len(rows))
	for _, row := range rows {
		result[row.Name] = row
	}
	return result
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

func TestEngineTracksAddressSpaceBytesSeparately(t *testing.T) {
	clock := &fakeClock{now: time.Unix(4000, 0)}
	engine := newEngineWithClock(10, clock.Now)

	engine.Ingest(newEnginePair(types.SYS_ENTER_MUNMAP, 0, types.UNCLASSIFIED, "proc", 1, "", 0, 4096, 10, 1))
	engine.Ingest(newEnginePair(types.SYS_ENTER_MREMAP, 0, types.UNCLASSIFIED, "proc", 1, "", 0, 8192, 20, 2))
	clock.Advance(2 * time.Second)

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snap.TotalBytes != 0 {
		t.Fatalf("TotalBytes = %d, want 0 for non-IO memory operations", snap.TotalBytes)
	}
	if snap.TotalAddressSpaceBytes != 12288 {
		t.Fatalf("TotalAddressSpaceBytes = %d, want 12288", snap.TotalAddressSpaceBytes)
	}
	if math.Abs(snap.AddressSpaceBytesPerSec-6144.0) > 1e-9 {
		t.Fatalf("AddressSpaceBytesPerSec = %v, want 6144", snap.AddressSpaceBytesPerSec)
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

func newEnginePair(traceID types.TraceId, ret int64, retType uint32, comm string, pid uint32, path string, bytes uint64, addressSpaceBytes uint64, duration uint64, gap uint64) *event.Pair {
	return &event.Pair{
		EnterEv:           &types.RetEvent{TraceId: traceID, Pid: pid},
		ExitEv:            &types.RetEvent{TraceId: traceID, Pid: pid, Ret: ret, RetType: retType},
		Comm:              comm,
		Duration:          duration,
		DurationToPrev:    gap,
		Bytes:             bytes,
		AddressSpaceBytes: addressSpaceBytes,
		File:              file.NewFd(3, path, -1),
	}
}
