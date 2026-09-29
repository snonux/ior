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

// TestProcessAccumulatorKeepsCountingAcrossCommChanges is the regression test
// for task 0o2: pair.Comm is a per-thread name, so a comm change for a known
// PID (differently named threads, or an exec) must not reset the counters.
// The pairs carry tid 0, so the leader is never seen and the label falls back
// to the most recent non-empty thread comm (see
// TestProcessAccumulatorPrefersLeaderComm for the leader-preferred label).
func TestProcessAccumulatorKeepsCountingAcrossCommChanges(t *testing.T) {
	tests := []struct {
		name      string
		comms     []string
		wantCount uint64
		wantComm  string
	}{
		{name: "interleaved thread names", comms: repeatComms(100, "main", "worker-1"), wantCount: 200, wantComm: "worker-1"},
		{name: "exec renames process", comms: []string{"bash", "bash", "ls"}, wantCount: 3, wantComm: "ls"},
		{name: "empty comm keeps previous label", comms: []string{"old", "new", ""}, wantCount: 3, wantComm: "new"},
		{name: "only empty comms", comms: []string{"", ""}, wantCount: 2, wantComm: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := newProcessAccumulator()
			for _, comm := range tt.comms {
				acc.Add(newProcessPair(2000, comm, 100, 10))
			}
			snap := acc.Snapshot(time.Second)
			if len(snap) != 1 {
				t.Fatalf("expected 1 snapshot row, got %d: %+v", len(snap), snap)
			}
			got := snap[0]
			if got.Syscalls != tt.wantCount || got.Bytes != tt.wantCount*10 ||
				got.TotalLatencyNs != tt.wantCount*100 || got.AvgLatencyNs != 100 {
				t.Fatalf("expected %d accumulated syscalls, got %+v", tt.wantCount, got)
			}
			if got.Comm != tt.wantComm {
				t.Fatalf("expected comm %q, got %q", tt.wantComm, got.Comm)
			}
		})
	}
}

// TestProcessAccumulatorSameCommDifferentPIDsStaySeparate guards the other
// direction: the comm is not part of the key, and two PIDs sharing a name
// (e.g. several worker processes) must not be merged.
func TestProcessAccumulatorSameCommDifferentPIDsStaySeparate(t *testing.T) {
	acc := newProcessAccumulator()
	acc.Add(newProcessPair(1, "worker", 10, 1))
	acc.Add(newProcessPair(2, "worker", 10, 1))
	acc.Add(newProcessPair(2, "worker", 10, 1))

	snap := acc.Snapshot(time.Second)
	if len(snap) != 2 {
		t.Fatalf("expected 2 snapshot rows, got %d: %+v", len(snap), snap)
	}
	if snap[0].PID != 2 || snap[0].Syscalls != 2 || snap[1].PID != 1 || snap[1].Syscalls != 1 {
		t.Fatalf("unexpected per-PID counts: %+v", snap)
	}
}

// TestProcessAccumulatorPrefersLeaderComm checks that the label is the
// thread-group leader's comm (tid == pid) whatever order the threads arrive
// in, falls back to the latest thread comm until the leader is seen, and
// still follows an exec (which renames the leader).
func TestProcessAccumulatorPrefersLeaderComm(t *testing.T) {
	const pid = 2000
	leader := func(comm string) *event.Pair { return newThreadPair(pid, pid, comm) }
	gc := func(comm string) *event.Pair { return newThreadPair(pid, pid+1, comm) }
	tests := []struct {
		name     string
		pairs    []*event.Pair
		wantComm string
	}{
		{name: "leader first", pairs: []*event.Pair{leader("java"), gc("GC Thread#0"), leader("java"), gc("GC Thread#0")}, wantComm: "java"},
		{name: "thread first", pairs: []*event.Pair{gc("GC Thread#0"), leader("java"), gc("GC Thread#0")}, wantComm: "java"},
		{name: "leader never seen", pairs: []*event.Pair{gc("GC Thread#0"), gc("worker")}, wantComm: "worker"},
		{name: "exec relabels leader", pairs: []*event.Pair{leader("bash"), gc("helper"), leader("ls"), gc("helper")}, wantComm: "ls"},
		{name: "empty leader comm ignored", pairs: []*event.Pair{leader("java"), leader(""), gc("GC Thread#0")}, wantComm: "java"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acc := newProcessAccumulator()
			for _, pair := range tt.pairs {
				acc.Add(pair)
			}
			snap := acc.Snapshot(time.Second)
			if len(snap) != 1 {
				t.Fatalf("expected 1 snapshot row, got %d: %+v", len(snap), snap)
			}
			if snap[0].Comm != tt.wantComm {
				t.Fatalf("expected comm %q, got %q", tt.wantComm, snap[0].Comm)
			}
			if want := uint64(len(tt.pairs)); snap[0].Syscalls != want {
				t.Fatalf("expected %d syscalls, got %d", want, snap[0].Syscalls)
			}
		})
	}
}

// repeatComms returns n alternations of the given comm names, in order.
func repeatComms(n int, comms ...string) []string {
	out := make([]string, 0, n*len(comms))
	for i := 0; i < n; i++ {
		out = append(out, comms...)
	}
	return out
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

// newThreadPair is newProcessPair with an explicit thread id, for tests that
// distinguish the thread-group leader (tid == pid) from its other threads.
func newThreadPair(pid, tid uint32, comm string) *event.Pair {
	pair := newProcessPair(pid, comm, 100, 10)
	pair.EnterEv = &types.RetEvent{Pid: pid, Tid: tid}
	return pair
}
