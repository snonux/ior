package statsengine

import (
	"testing"

	"ior/internal/event"
	"ior/internal/types"
)

// newNoReturnPair builds a noreturn row the way the event loop emits it
// (eventLoop.completeNoReturnEnter): enter plus a synthetic NullEvent exit,
// Duration 0, NoReturn set.
func newNoReturnPair(traceID types.TraceId, pid uint32) *event.Pair {
	return &event.Pair{
		EnterEv:  &types.NullEvent{EventType: types.ENTER_NULL_EVENT, TraceId: traceID, Pid: pid, Tid: pid},
		ExitEv:   &types.NullEvent{EventType: types.EXIT_NULL_EVENT, TraceId: traceID - 1, Pid: pid, Tid: pid},
		Comm:     "proc",
		NoReturn: true,
	}
}

// TestNoReturnPairsAreCountedButUntimed (task pr2): a noreturn row (exit,
// exit_group, rt_sigreturn) is a syscall and counts, but its Duration of 0 is
// no measurement. It must not add a latency sample anywhere - the global mean
// and histogram, the per-syscall min/mean/percentiles, the per-process
// average - or a signal-heavy program would drag every latency figure toward
// zero.
func TestNoReturnPairsAreCountedButUntimed(t *testing.T) {
	e := NewEngine(10)
	const pid = 4100
	timed := newEnginePair(types.SYS_ENTER_READ, 10, types.READ_CLASSIFIED, "proc", pid, "/f", 10, 0, 1000, 0)
	e.Ingest(timed)
	e.Ingest(newNoReturnPair(types.SYS_ENTER_RT_SIGRETURN, pid))
	e.Ingest(newNoReturnPair(types.SYS_ENTER_RT_SIGRETURN, pid))
	e.Ingest(newNoReturnPair(types.SYS_ENTER_EXIT_GROUP, pid))

	snap, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.TotalSyscalls != 4 {
		t.Errorf("TotalSyscalls = %d, want 4", snap.TotalSyscalls)
	}
	if snap.LatencyMeanNs != 1000 {
		t.Errorf("LatencyMeanNs = %v, want 1000 (the one timed pair)", snap.LatencyMeanNs)
	}
	if snap.LatencyHistogram.Total != 1 {
		t.Errorf("latency histogram total = %d, want 1", snap.LatencyHistogram.Total)
	}
	if snap.TotalErrors != 0 {
		t.Errorf("TotalErrors = %d, want 0", snap.TotalErrors)
	}

	sigreturn := findSyscall(t, snap.Syscalls(), "rt_sigreturn")
	if sigreturn.Count != 2 || sigreturn.LatencyMeanNs != 0 || sigreturn.LatencyMaxNs != 0 || sigreturn.LatencyP99Ns != 0 {
		t.Errorf("rt_sigreturn row = %+v, want count 2 and no latency", sigreturn)
	}

	procs := snap.Processes()
	if len(procs) != 1 || procs[0].Syscalls != 4 || procs[0].AvgLatencyNs != 1000 {
		t.Errorf("process rows = %+v, want one row: 4 syscalls, average 1000ns", procs)
	}
}

func findSyscall(t *testing.T, rows []SyscallSnapshot, name string) SyscallSnapshot {
	t.Helper()
	for _, row := range rows {
		if row.Name == name {
			return row
		}
	}
	t.Fatalf("no %s row in %+v", name, rows)
	return SyscallSnapshot{}
}

// TestSyscallAccumulatorNeverTimesANoReturnPair pins the per-syscall rule on
// its own: whatever Duration a NoReturn pair carries, it adds no latency
// sample, min, max or mean contribution. The event loop always hands it 0,
// which would hide a regression in the end-to-end test above (a 0 sample and
// no sample both read as 0 there), so this feeds a timed pair of the same
// syscall next to a NoReturn one with a non-zero Duration.
func TestSyscallAccumulatorNeverTimesANoReturnPair(t *testing.T) {
	acc := newSyscallAccumulator()
	timed := newNoReturnPair(types.SYS_ENTER_RT_SIGRETURN, 1)
	timed.NoReturn, timed.Duration = false, 1000
	untimed := newNoReturnPair(types.SYS_ENTER_RT_SIGRETURN, 1)
	untimed.Duration = 9000
	acc.Add(timed)
	acc.Add(untimed)

	row := findSyscall(t, acc.Snapshot(0), "rt_sigreturn")
	if row.Count != 2 || row.LatencyMinNs != 1000 || row.LatencyMaxNs != 1000 ||
		row.LatencyMeanNs != 1000 || row.TotalLatencyNs != 1000 || row.LatencyP99Ns != 1000 {
		t.Fatalf("rt_sigreturn row = %+v, want count 2 with only the timed 1000ns sample", row)
	}
}
