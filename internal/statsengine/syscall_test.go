package statsengine

import (
	"ior/internal/event"
	"ior/internal/types"
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestSyscallAccumulatorBasicStats(t *testing.T) {
	acc := newSyscallAccumulatorWithConfig(10_000, rand.New(rand.NewSource(1)))
	traceID := types.SYS_ENTER_READ

	acc.Add(newPair(traceID, 10, 100, 0))
	acc.Add(newPair(traceID, 20, 50, -1))
	acc.Add(newPair(traceID, 30, 25, 5))

	snap := acc.Snapshot(2 * time.Second)
	if len(snap) != 1 {
		t.Fatalf("expected 1 syscall snapshot, got %d", len(snap))
	}
	got := snap[0]

	if got.TraceID != traceID {
		t.Fatalf("wrong trace id: got %v want %v", got.TraceID, traceID)
	}
	if got.Name != traceID.Name() {
		t.Fatalf("wrong name: got %q want %q", got.Name, traceID.Name())
	}
	if got.Count != 3 {
		t.Fatalf("wrong count: got %d want 3", got.Count)
	}
	if got.Errors != 1 {
		t.Fatalf("wrong errors: got %d want 1", got.Errors)
	}
	if got.Bytes != 175 {
		t.Fatalf("wrong bytes: got %d want 175", got.Bytes)
	}
	if got.LatencyMinNs != 10 || got.LatencyMaxNs != 30 {
		t.Fatalf("wrong min/max: got (%d,%d) want (10,30)", got.LatencyMinNs, got.LatencyMaxNs)
	}
	if got.LatencyMeanNs != 20 {
		t.Fatalf("wrong mean: got %v want 20", got.LatencyMeanNs)
	}
	if got.LatencyP50Ns != 20 || got.LatencyP95Ns != 30 || got.LatencyP99Ns != 30 {
		t.Fatalf("wrong percentiles: got p50=%d p95=%d p99=%d", got.LatencyP50Ns, got.LatencyP95Ns, got.LatencyP99Ns)
	}
	if math.Abs(got.RatePerSec-1.5) > 1e-9 {
		t.Fatalf("wrong rate: got %v want 1.5", got.RatePerSec)
	}
}

func TestSyscallAccumulatorSortsByCountThenName(t *testing.T) {
	acc := newSyscallAccumulatorWithConfig(10_000, rand.New(rand.NewSource(2)))

	idA := types.SYS_ENTER_OPENAT
	idB := types.SYS_ENTER_READ

	acc.Add(newPair(idA, 10, 0, 0))
	acc.Add(newPair(idA, 11, 0, 0))
	acc.Add(newPair(idB, 12, 0, 0))

	snap := acc.Snapshot(1 * time.Second)
	if len(snap) != 2 {
		t.Fatalf("expected 2 syscall snapshots, got %d", len(snap))
	}
	if snap[0].TraceID != idA {
		t.Fatalf("expected first id %v, got %v", idA, snap[0].TraceID)
	}
	if snap[1].TraceID != idB {
		t.Fatalf("expected second id %v, got %v", idB, snap[1].TraceID)
	}
}

func TestSyscallAccumulatorReservoirPercentilesAccuracy(t *testing.T) {
	acc := newSyscallAccumulatorWithConfig(100, rand.New(rand.NewSource(7)))
	traceID := types.SYS_ENTER_WRITE

	for d := uint64(1); d <= 10_000; d++ {
		acc.Add(newPair(traceID, d, 0, 0))
	}

	snap := acc.Snapshot(1 * time.Second)
	if len(snap) != 1 {
		t.Fatalf("expected 1 syscall snapshot, got %d", len(snap))
	}
	got := snap[0]

	assertNearPercentile(t, "p50", got.LatencyP50Ns, 5_000, 1_500)
	assertNearPercentile(t, "p95", got.LatencyP95Ns, 9_500, 800)
	assertNearPercentile(t, "p99", got.LatencyP99Ns, 9_900, 500)
}

func TestSyscallAccumulatorZeroElapsedRate(t *testing.T) {
	acc := newSyscallAccumulatorWithConfig(32, rand.New(rand.NewSource(9)))
	acc.Add(newPair(types.SYS_ENTER_READ, 9, 0, 0))

	snap := acc.Snapshot(0)
	if len(snap) != 1 {
		t.Fatalf("expected 1 syscall snapshot, got %d", len(snap))
	}
	if snap[0].RatePerSec != 0 {
		t.Fatalf("expected zero rate, got %v", snap[0].RatePerSec)
	}
}

func newPair(traceID types.TraceId, duration uint64, bytes uint64, ret int64) *event.Pair {
	return &event.Pair{
		EnterEv:  &types.RetEvent{TraceId: traceID},
		ExitEv:   &types.RetEvent{TraceId: traceID, Ret: ret},
		Duration: duration,
		Bytes:    bytes,
	}
}

func assertNearPercentile(t *testing.T, name string, got uint64, want uint64, tolerance uint64) {
	t.Helper()

	delta := absDiff(got, want)
	if delta > tolerance {
		t.Fatalf("%s too far from expected: got %d want %d (delta %d > %d)", name, got, want, delta, tolerance)
	}
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}
