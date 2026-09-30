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
// to the first non-empty thread comm (see
// TestProcessAccumulatorPrefersLeaderComm for the leader-preferred label).
func TestProcessAccumulatorKeepsCountingAcrossCommChanges(t *testing.T) {
	tests := []struct {
		name      string
		comms     []string
		wantCount uint64
		wantComm  string
	}{
		{name: "interleaved thread names", comms: repeatComms(100, "main", "worker-1"), wantCount: 200, wantComm: "main"},
		{name: "rename without leader keeps counting", comms: []string{"bash", "bash", "ls"}, wantCount: 3, wantComm: "bash"},
		{name: "leading empty comm skipped", comms: []string{"", "old", "new", ""}, wantCount: 4, wantComm: "old"},
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
// in, falls back to the first thread comm until the leader is seen, and
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
		{name: "leader never seen", pairs: []*event.Pair{gc("GC Thread#0"), gc("worker")}, wantComm: "GC Thread#0"},
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

// TestProcessAccumulatorFallbackLabelStableAcrossSnapshots covers a process
// whose leader never completes a traced syscall (e.g. a Java launcher parked
// in pthread_join): the label must stay identical across snapshots while the
// worker threads alternate, and switch to the leader's comm once it appears.
func TestProcessAccumulatorFallbackLabelStableAcrossSnapshots(t *testing.T) {
	const pid = 2000
	acc := newProcessAccumulator()
	threads := []string{"GC Thread#0", "C2 CompilerThre", "VM Thread"}
	for round := 0; round < 6; round++ {
		for i, comm := range threads {
			acc.Add(newThreadPair(pid, pid+1+uint32((round+i)%len(threads)), comm))
			snap := acc.Snapshot(time.Second)
			if len(snap) != 1 || snap[0].Comm != "GC Thread#0" {
				t.Fatalf("round %d thread %q: expected stable label %q, got %+v", round, comm, "GC Thread#0", snap)
			}
		}
	}

	acc.Add(newThreadPair(pid, pid, "java"))
	acc.Add(newThreadPair(pid, pid+1, "GC Thread#0"))
	if got := acc.Snapshot(time.Second)[0].Comm; got != "java" {
		t.Fatalf("expected leader comm once seen, got %q", got)
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

// TestProcessAccumulatorRetireSplitsRecycledPID is the regression test for
// task ro2: once a PID's process has exited (RetireProcess), a new process
// handed the same PID must get its own row, count and label, and the dead
// one's row must stay listed so the table remains cumulative.
func TestProcessAccumulatorRetireSplitsRecycledPID(t *testing.T) {
	acc := newProcessAccumulator()
	for i := 0; i < 3; i++ {
		acc.Add(newThreadPair(2000, 2000, "a"))
	}
	acc.RetireProcess(2000)
	for i := 0; i < 5; i++ {
		acc.Add(newThreadPair(2000, 2000, "b"))
	}
	acc.RetireProcess(2000)
	acc.Add(newThreadPair(2000, 2000, "c"))

	want := []ProcessSnapshot{
		{PID: 2000, Lifetime: 1, Comm: "b", Syscalls: 5},
		{PID: 2000, Lifetime: 0, Comm: "a", Syscalls: 3},
		{PID: 2000, Lifetime: 2, Comm: "c", Syscalls: 1},
	}
	assertProcessLifetimes(t, acc.Snapshot(time.Second), want)
}

// TestProcessAccumulatorRetireNoOps covers the retirements that must not
// change anything: an unknown PID, a PID retired twice, and a nil accumulator.
func TestProcessAccumulatorRetireNoOps(t *testing.T) {
	var nilAcc *processAccumulator
	nilAcc.RetireProcess(1) // must not panic

	acc := newProcessAccumulator()
	acc.Add(newThreadPair(10, 10, "a"))
	acc.RetireProcess(99) // never seen
	acc.RetireProcess(10)
	acc.RetireProcess(10) // already retired, no live row
	acc.Add(newThreadPair(10, 10, "b"))

	assertProcessLifetimes(t, acc.Snapshot(time.Second), []ProcessSnapshot{
		{PID: 10, Lifetime: 0, Comm: "a", Syscalls: 1},
		{PID: 10, Lifetime: 1, Comm: "b", Syscalls: 1},
	})
	if len(acc.nextLifetime) != 0 {
		t.Fatalf("nextLifetime should be empty while every PID has a live row, got %v", acc.nextLifetime)
	}
}

// TestProcessAccumulatorCompactsRetiredRows checks that retired rows count
// against the memory bound: compaction keeps the topN best rows of either
// kind, and drops the lifetime bookkeeping of PIDs whose rows all went.
func TestProcessAccumulatorCompactsRetiredRows(t *testing.T) {
	acc := newProcessAccumulatorWithLimits(2, 4)
	for i := 0; i < 5; i++ {
		acc.Add(newProcessPair(10, "hot-dead", 10, 1))
	}
	acc.RetireProcess(10)
	for i := 0; i < 3; i++ {
		acc.Add(newProcessPair(20, "warm-live", 10, 1))
	}
	// The fifth row (PID 3) triggers compaction down to PIDs 10 and 20, so
	// retiring PID 3 afterwards finds no live row and is a no-op.
	for pid := uint32(1); pid <= 3; pid++ {
		acc.Add(newProcessPair(pid, "cold-dead", 10, 1))
		acc.RetireProcess(pid)
	}

	if got := len(acc.byPID) + len(acc.retired); got != 2 {
		t.Fatalf("expected compaction to keep topN rows, got %d live + %d retired", len(acc.byPID), len(acc.retired))
	}
	if _, ok := acc.nextLifetime[1]; ok {
		t.Fatalf("nextLifetime kept a PID whose rows were all compacted away: %v", acc.nextLifetime)
	}
	if acc.nextLifetime[10] != 1 {
		t.Fatalf("nextLifetime[10] = %d, want 1 while its retired row survives", acc.nextLifetime[10])
	}
	assertProcessLifetimes(t, acc.Snapshot(time.Second), []ProcessSnapshot{
		{PID: 10, Lifetime: 0, Comm: "hot-dead", Syscalls: 5},
		{PID: 20, Lifetime: 0, Comm: "warm-live", Syscalls: 3},
	})

	// The retired row stays retired after compaction: PID 10's next process
	// gets a new row rather than reviving the old one.
	acc.Add(newProcessPair(10, "reborn", 10, 1))
	if got := acc.byPID[10]; got == nil || got.lifetime != 1 || got.count != 1 {
		t.Fatalf("expected a fresh lifetime-1 row for PID 10, got %+v", got)
	}
}

// assertProcessLifetimes compares the identity and count of each row.
func assertProcessLifetimes(t *testing.T, got, want []ProcessSnapshot) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d rows, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		g, w := got[i], want[i]
		if g.PID != w.PID || g.Lifetime != w.Lifetime || g.Comm != w.Comm || g.Syscalls != w.Syscalls {
			t.Fatalf("row %d = %+v, want PID %d lifetime %d comm %q syscalls %d",
				i, g, w.PID, w.Lifetime, w.Comm, w.Syscalls)
		}
	}
}
