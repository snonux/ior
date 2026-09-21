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

// TestEngineCountsErrorsForKindSpecificExits guards the ret-carrier fix at the
// aggregation layer: accept/pipe/socketpair/eventfd exits decode into their own
// event structs, not *types.RetEvent, so a failing call used to be invisible to
// both the global error total and the per-syscall Errors column.
func TestEngineCountsErrorsForKindSpecificExits(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine := newEngineWithClock(4, clock.Now)

	exits := []struct {
		traceID types.TraceId
		exit    event.Event
	}{
		{types.SYS_ENTER_ACCEPT, &types.AcceptEvent{TraceId: types.SYS_EXIT_ACCEPT, Ret: -11}},
		{types.SYS_ENTER_PIPE, &types.PipeEvent{TraceId: types.SYS_EXIT_PIPE, Ret: -24}},
		{types.SYS_ENTER_SOCKETPAIR, &types.SocketpairEvent{TraceId: types.SYS_EXIT_SOCKETPAIR, Ret: -93}},
		{types.SYS_ENTER_EVENTFD2, &types.EventfdEvent{TraceId: types.SYS_EXIT_EVENTFD2, Ret: -24}},
	}
	for _, tc := range exits {
		engine.Ingest(&event.Pair{
			EnterEv:  &types.NullEvent{TraceId: tc.traceID, Pid: 4242},
			ExitEv:   tc.exit,
			Comm:     "srv",
			Duration: 1000,
			File:     file.NewFd(3, "socket:accepted", -1),
		})
		clock.Advance(100 * time.Millisecond)
	}

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error: %v", err)
	}
	if snap.TotalErrors != uint64(len(exits)) {
		t.Fatalf("TotalErrors = %d, want %d", snap.TotalErrors, len(exits))
	}

	seen := make(map[types.TraceId]uint64, len(exits))
	for _, row := range snap.Syscalls() {
		seen[row.TraceID] = row.Errors
	}
	for _, tc := range exits {
		if got := seen[tc.traceID]; got != 1 {
			t.Errorf("syscall %s Errors = %d, want 1", tc.traceID.Name(), got)
		}
	}
}

func TestEngineCountsOnlyTheErrnoReturnWindowAsErrors(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	engine := newEngineWithClock(4, clock.Now)
	for _, ret := range []int64{-4096, -4095} {
		engine.Ingest(newEnginePair(types.SYS_ENTER_MMAP, ret, types.UNCLASSIFIED,
			"mapper", 1, "", 0, 0, 10, 0))
	}

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.TotalErrors != 1 {
		t.Fatalf("TotalErrors = %d, want 1", snap.TotalErrors)
	}
	rows := snap.Syscalls()
	if len(rows) != 1 || rows[0].Errors != 1 {
		t.Fatalf("syscall rows = %+v, want one mmap row with one error", rows)
	}
}
