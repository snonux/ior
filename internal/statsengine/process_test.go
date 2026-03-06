package statsengine

import (
	"math"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

func TestProcessAccumulatorBasicStats(t *testing.T) {
	acc := newProcessAccumulator()

	acc.Add(newProcessPair(2000, "proc-a", 10, 100))
	acc.Add(newProcessPair(2000, "proc-a", 30, 50))
	acc.Add(newProcessPair(3000, "proc-b", 20, 25))

	snap := acc.Snapshot(2 * time.Second)
	if len(snap) != 2 {
		t.Fatalf("expected 2 process snapshots, got %d", len(snap))
	}

	p0 := snap[0]
	if p0.PID != 2000 {
		t.Fatalf("expected pid 2000 first, got %d", p0.PID)
	}
	if p0.Comm != "proc-a" {
		t.Fatalf("unexpected comm: got %q", p0.Comm)
	}
	if p0.Syscalls != 2 || p0.Bytes != 150 {
		t.Fatalf("unexpected count/bytes: %+v", p0)
	}
	if p0.AvgLatencyNs != 20 {
		t.Fatalf("unexpected avg latency: got %v", p0.AvgLatencyNs)
	}
	if math.Abs(p0.RatePerSec-1.0) > 1e-9 {
		t.Fatalf("unexpected rate: got %v", p0.RatePerSec)
	}

	p1 := snap[1]
	if p1.PID != 3000 || p1.Comm != "proc-b" || p1.Syscalls != 1 {
		t.Fatalf("unexpected second row: %+v", p1)
	}
}

func TestProcessAccumulatorSortsBySyscallsBytesPid(t *testing.T) {
	acc := newProcessAccumulator()

	acc.Add(newProcessPair(20, "b", 10, 2))
	acc.Add(newProcessPair(10, "a", 10, 3))
	acc.Add(newProcessPair(10, "a", 10, 3))
	acc.Add(newProcessPair(20, "b", 10, 2))

	snap := acc.Snapshot(1 * time.Second)
	if len(snap) != 2 {
		t.Fatalf("expected 2 process snapshots, got %d", len(snap))
	}

	if snap[0].PID != 10 {
		t.Fatalf("expected pid 10 first by bytes tie-breaker, got %d", snap[0].PID)
	}
	if snap[1].PID != 20 {
		t.Fatalf("expected pid 20 second, got %d", snap[1].PID)
	}
}

func TestProcessAccumulatorCommUpdateAndZeroRate(t *testing.T) {
	acc := newProcessAccumulator()

	acc.Add(newProcessPair(7, "", 10, 1))
	acc.Add(newProcessPair(7, "worker", 20, 2))
	snap := acc.Snapshot(0)

	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot row, got %d", len(snap))
	}
	if snap[0].Comm != "worker" {
		t.Fatalf("expected comm to be updated, got %q", snap[0].Comm)
	}
	if snap[0].RatePerSec != 0 {
		t.Fatalf("expected zero rate on zero elapsed, got %v", snap[0].RatePerSec)
	}
}

func TestProcessAccumulatorResetsOnCommChangeForSamePID(t *testing.T) {
	acc := newProcessAccumulator()

	acc.Add(newProcessPair(42, "old", 100, 10))
	acc.Add(newProcessPair(42, "new", 200, 20))

	snap := acc.Snapshot(time.Second)
	if len(snap) != 1 {
		t.Fatalf("expected 1 snapshot row, got %d", len(snap))
	}
	if snap[0].Comm != "new" {
		t.Fatalf("expected new comm after reset, got %q", snap[0].Comm)
	}
	if snap[0].Syscalls != 1 || snap[0].Bytes != 20 || snap[0].AvgLatencyNs != 200 {
		t.Fatalf("expected counters to reset on comm change, got %+v", snap[0])
	}
}

func TestProcessAccumulatorNilInputs(t *testing.T) {
	var acc *processAccumulator
	acc.Add(nil)
	if got := acc.Snapshot(time.Second); got != nil {
		t.Fatalf("expected nil snapshot from nil accumulator, got %#v", got)
	}

	acc = newProcessAccumulator()
	acc.Add(nil)
	acc.Add(&event.Pair{})
	if got := acc.Snapshot(time.Second); len(got) != 0 {
		t.Fatalf("expected empty snapshot, got %#v", got)
	}
}

func TestProcessAccumulatorCompactsHighCardinality(t *testing.T) {
	acc := newProcessAccumulatorWithLimits(2, 4)

	for i := 0; i < 5; i++ {
		acc.Add(newProcessPair(10, "hot-a", 10, 1))
	}
	for i := 0; i < 4; i++ {
		acc.Add(newProcessPair(20, "hot-b", 10, 1))
	}
	acc.Add(newProcessPair(1, "cold-1", 10, 1))
	acc.Add(newProcessPair(2, "cold-2", 10, 1))
	acc.Add(newProcessPair(3, "cold-3", 10, 1))

	if got := len(acc.byPID); got != 2 {
		t.Fatalf("expected compaction to keep topN processes, got %d entries", got)
	}
	if acc.byPID[10] == nil || acc.byPID[20] == nil {
		t.Fatalf("expected hot pids to survive compaction")
	}

	snap := acc.Snapshot(time.Second)
	if len(snap) != 2 {
		t.Fatalf("expected 2 rows after compaction, got %d", len(snap))
	}
	if snap[0].PID != 10 || snap[1].PID != 20 {
		t.Fatalf("unexpected rank order after compaction: %+v", snap)
	}
}

func newProcessPair(pid uint32, comm string, duration uint64, bytes uint64) *event.Pair {
	return &event.Pair{
		EnterEv:  &types.RetEvent{Pid: pid},
		Comm:     comm,
		Duration: duration,
		Bytes:    bytes,
	}
}
