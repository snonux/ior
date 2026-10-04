package statsengine

import (
	"fmt"
	"maps"
	"sync"
	"testing"
	"time"

	"ior/internal/event"
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

// TestEngineResetClearsRetiredProcesses checks that Reset drops the rows of
// exited processes: after a reset only the rows of processes seen again exist.
// Their identity survives (see TestEngineResetKeepsProcessIdentity), so the
// still-running second process of PID 7 comes back as lifetime 1, alone.
func TestEngineResetClearsRetiredProcesses(t *testing.T) {
	e := NewEngine(8)
	var nilEngine *Engine
	nilEngine.RetireProcess(7) // must not panic

	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "old", 7, "/tmp/a", 7, 0, 1000, 50))
	e.RetireProcess(7)
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "new", 7, "/tmp/a", 7, 0, 1000, 50))
	if snap, err := e.Snapshot(); err != nil || len(snap.Processes()) != 2 {
		t.Fatalf("expected two lifetimes of PID 7 before reset, got %+v (err %v)", snap, err)
	}

	e.Reset()
	if snap, err := e.Snapshot(); err != nil || len(snap.Processes()) != 0 {
		t.Fatalf("expected no process rows right after reset, got %+v (err %v)", snap, err)
	}
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "after", 7, "/tmp/a", 7, 0, 1000, 50))
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatalf("unexpected snapshot error after reset: %v", err)
	}
	procs := snap.Processes()
	if len(procs) != 1 || procs[0].Comm != "after" || procs[0].Lifetime != 1 || procs[0].Syscalls != 1 {
		t.Fatalf("expected only the running process' lifetime-1 row after reset, got %+v", procs)
	}
}

// pidLifetimes returns the Lifetime of the row of every process in the
// engine's snapshot, keyed by "pid/comm", so a test can tell rows of one PID
// apart by their label.
func pidLifetimes(t *testing.T, e *Engine) map[string]uint32 {
	t.Helper()
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	got := map[string]uint32{}
	for _, p := range snap.Processes() {
		got[fmt.Sprintf("%d/%s", p.PID, p.Comm)] = p.Lifetime
	}
	return got
}

func ingestPID(e *Engine, pid uint32, comm string) {
	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, comm, pid, "/tmp/a", 7, 0, 1000, 50))
}

// TestEngineResetKeepsProcessIdentity: the TUI selects a process by PID and
// lifetime ordinal, so Reset must not renumber the processes that keep
// running. A live second process of PID 8 reopens as 8#1, not as 8; a live
// first process stays 8 - and the process that takes PID 8 after either exits
// gets the next ordinal, never the one the selection was made on.
func TestEngineResetKeepsProcessIdentity(t *testing.T) {
	e := NewEngine(8)
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second") // live 8#1
	ingestPID(e, 9, "nine")   // live 9#0
	ingestPID(e, 10, "ten")
	e.RetireProcess(10) // retired 10#0, no live row

	e.Reset()
	ingestPID(e, 8, "second")
	ingestPID(e, 9, "nine")
	ingestPID(e, 10, "successor") // a new process after the retired 10#0
	want := map[string]uint32{"8/second": 1, "9/nine": 0, "10/successor": 1}
	if got := pidLifetimes(t, e); !maps.Equal(got, want) {
		t.Fatalf("lifetimes after reset = %v, want %v", got, want)
	}
}

// TestEngineResetCarriedProcessThatExitsBeforeItsNextPair: process 8#1 is live
// at the reset, exits before it issues another syscall (no row to retire),
// and the next process with PID 8 must be 8#2 - not the 8#1 a selection
// remembers for the dead one.
func TestEngineResetCarriedProcessThatExitsBeforeItsNextPair(t *testing.T) {
	e := NewEngine(8)
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second")

	e.Reset()
	e.RetireProcess(8) // exit of the carried process, no row yet
	e.RetireProcess(8) // a duplicate exit record must not skip an ordinal
	ingestPID(e, 8, "third")
	if got, want := pidLifetimes(t, e), map[string]uint32{"8/third": 2}; !maps.Equal(got, want) {
		t.Fatalf("lifetimes = %v, want %v", got, want)
	}
}

// TestEngineResetIdentityAcrossSeveralResets: an idle process is not lost by
// the second reset before it reappears, and a consumed ordinal does not
// linger to renumber a later process.
func TestEngineResetIdentityAcrossSeveralResets(t *testing.T) {
	e := NewEngine(8)
	ingestPID(e, 8, "first")
	e.RetireProcess(8)
	ingestPID(e, 8, "second")

	e.Reset()
	e.Reset() // 8#1 never spoke in between
	ingestPID(e, 8, "second")
	e.Reset() // the ordinal was consumed and is re-carried from the live row
	e.RetireProcess(8)
	ingestPID(e, 8, "third")
	if got, want := pidLifetimes(t, e), map[string]uint32{"8/third": 2}; !maps.Equal(got, want) {
		t.Fatalf("lifetimes = %v, want %v", got, want)
	}
}

// TestProcessCarryOverConsumesEntriesWhenPIDsReappear: a carried entry lives
// only until the first row of its PID opens.
func TestProcessCarryOverConsumesEntriesWhenPIDsReappear(t *testing.T) {
	e := NewEngine(8)
	for pid := uint32(1); pid <= 5; pid++ {
		ingestPID(e, pid, "p")
	}
	e.Reset()
	if n := e.processes.carried.size(); n != 5 {
		t.Fatalf("carried %d PIDs, want 5", n)
	}
	ingestPID(e, 3, "p")
	if n := e.processes.carried.size(); n != 4 {
		t.Fatalf("carried %d PIDs after PID 3 reappeared, want 4", n)
	}
}

func ingestAcc(a *processAccumulator, pid uint32) {
	a.Add(&event.Pair{EnterEv: &types.RetEvent{TraceId: types.SYS_ENTER_READ, Pid: pid, Tid: pid}, Comm: "p"})
}

// TestEngineResetConcurrentWithIngestAndSnapshot is the regression guard for
// audit finding M5 (AUDIT-REPORT.md section 3, evidence
// audit/domain-03-statsengine.md F2): Reset, Ingest and Snapshot all serialize
// on the engine mutex, so a baseline reset while events stream in must never
// expose a half-reset engine. The test hammers all three operations from
// concurrent goroutines (run under -race in the task verification) and asserts
// per-snapshot consistency plus deterministic behavior afterwards.
func TestEngineResetConcurrentWithIngestAndSnapshot(t *testing.T) {
	e := NewEngine(8)

	const (
		ingesters = 4
		ingests   = 400
		snapshots = 200
		resets    = 20
	)

	var wg sync.WaitGroup
	for g := 0; g < ingesters; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < ingests; i++ {
				// Alternate successful and failed calls so totals and error
				// counters are exercised together.
				ret := int64(7)
				if i%2 == 1 {
					ret = -5
				}
				e.Ingest(newEnginePair(types.SYS_ENTER_READ, ret, types.READ_CLASSIFIED, "reset-race", uint32(g+1), "/tmp/a", 512, 1000, 50, 0))
			}
		}(g)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < resets; i++ {
			e.Reset()
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < snapshots; i++ {
			snap, err := e.Snapshot()
			if err != nil {
				t.Errorf("concurrent Snapshot() error: %v", err)
				return
			}
			// Every error is also a syscall, so a snapshot torn by a
			// concurrent reset would break this invariant.
			if snap.TotalErrors > snap.TotalSyscalls {
				t.Errorf("inconsistent snapshot: TotalErrors(%d) > TotalSyscalls(%d)", snap.TotalErrors, snap.TotalSyscalls)
				return
			}
		}
	}()

	wg.Wait()

	// After concurrent Reset+Ingest traffic, the engine must still behave
	// deterministically for a sequential caller: a final reset clears
	// everything and one ingest produces exactly one syscall.
	e.Reset()
	snap, err := e.Snapshot()
	if err != nil {
		t.Fatalf("post-race Snapshot() error: %v", err)
	}
	if snap.TotalSyscalls != 0 || snap.TotalErrors != 0 || snap.TotalBytes != 0 {
		t.Fatalf("post-race Reset() left totals: %+v", snap)
	}

	e.Ingest(newEnginePair(types.SYS_ENTER_READ, 7, types.READ_CLASSIFIED, "reset-race", 1, "/tmp/a", 512, 1000, 50, 0))
	snap, err = e.Snapshot()
	if err != nil {
		t.Fatalf("post-race ingest Snapshot() error: %v", err)
	}
	if snap.TotalSyscalls != 1 {
		t.Fatalf("post-race ingest TotalSyscalls = %d, want 1", snap.TotalSyscalls)
	}
}
