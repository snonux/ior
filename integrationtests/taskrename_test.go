package integrationtests

import (
	"testing"

	iorparquet "ior/internal/parquet"
)

const (
	lateRenameScenario = "thread-comm-late-rename"
	// The workload's counts (lateRenameThreads / lateRenameOps in
	// cmd/ioworkload/scenario_threadrename.go): 12 fresh workers, 4 calls per
	// phase, three rename styles used by 4 workers each.
	lateRenameWorkers       = 12
	lateRenameOpsPerPhase   = 4
	lateRenameWorkerRows    = lateRenameWorkers * lateRenameOpsPerPhase
	lateRenameStyleRows     = lateRenameWorkerRows / 3
	lateRenameMainName      = "main-renamed"
	lateRenameOriginalName  = "ioworkload"
	lateRenameSiblingName   = "wk-sibling"
	lateRenameSyscallFilter = "pread64,pwrite64"
)

// lateRenameWorkerNames are the names the workers give themselves, one per
// rename style: prctl(PR_SET_NAME) on itself, a write to its own procfs comm
// (pthread_setname_np(self)) and a write to its comm by another thread
// (pthread_setname_np(other)).
var lateRenameWorkerNames = []string{"wk-prctl", "wk-procself", lateRenameSiblingName}

// TestRenamedTasksAreRelabelledByTheRenameRecord pins task lr2 end to end. Every
// task of the scenario issues pread64 calls under its old name, renames itself
// (the main thread and the workers by three different routes) and issues
// pwrite64 calls. Nothing but the task:task_rename record tells ior about the
// rename: the task has no exec, and the pwrite64 phase opens nothing whose
// payload comm could heal the cache. Before the record every pwrite64 row kept
// the old name (the comm cache was only ever updated by exec records and open
// events).
//
// The pwrite64 (new name) assertions are strict. The pread64 (old name)
// ones are too, which holds while ior's event loop trails the workload by less
// than the scenario's pause before the rename (threadCommRenameSettle, 500ms):
// a stalled event loop could resolve a task's name from procfs after its
// rename. The main thread's pread64 rows are not asserted: it pre-dates ior, so
// its name is resolved lazily and a row may carry no comm. Row counts are only
// bounded, see threadCommMinKeptPercent.
func TestRenamedTasksAreRelabelledByTheRenameRecord(t *testing.T) {
	allowed := append([]string{lateRenameOriginalName, lateRenameMainName}, lateRenameWorkerNames...)
	rows, pid := runParquetScenarioRowsAllowingComms(t, lateRenameScenario, defaultDuration,
		[]string{"-trace-syscalls", lateRenameSyscallFilter}, nil, allowed...)

	mainWrites, workerReads, workerWrites := splitLateRenameRows(rows, uint32(pid))
	requireRowCount(t, "main thread pwrite64 rows", len(mainWrites), lateRenameOpsPerPhase)
	for _, row := range mainWrites {
		if row.Comm != lateRenameMainName {
			t.Errorf("main thread pwrite64 after PR_SET_NAME: comm = %q, want %q: %+v", row.Comm, lateRenameMainName, row)
		}
	}

	requireRowCount(t, "worker pread64 rows", len(workerReads), lateRenameWorkerRows)
	for _, row := range workerReads {
		if row.Comm != lateRenameOriginalName {
			t.Errorf("worker pread64 before its rename: comm = %q, want %q: %+v", row.Comm, lateRenameOriginalName, row)
		}
	}

	requireRowCount(t, "worker pwrite64 rows", len(workerWrites), lateRenameWorkerRows)
	perName := make(map[string]int)
	for _, row := range workerWrites {
		perName[row.Comm]++
	}
	for _, name := range lateRenameWorkerNames {
		requireRowCount(t, "worker pwrite64 rows named "+name, perName[name], lateRenameStyleRows)
		delete(perName, name)
	}
	if len(perName) != 0 {
		t.Errorf("worker pwrite64 rows with a name that is not any rename target: %v", perName)
	}
}

// splitLateRenameRows sorts the scenario's rows into the main thread's pwrite64
// rows (tid == pid), the workers' pread64 rows and the workers' pwrite64 rows.
func splitLateRenameRows(rows []iorparquet.Record, pid uint32) (mainWrites, workerReads, workerWrites []iorparquet.Record) {
	for _, row := range rows {
		switch {
		case row.Syscall == "pwrite64" && row.TID == pid:
			mainWrites = append(mainWrites, row)
		case row.Syscall == "pread64" && row.TID != pid:
			workerReads = append(workerReads, row)
		case row.Syscall == "pwrite64":
			workerWrites = append(workerWrites, row)
		}
	}
	return mainWrites, workerReads, workerWrites
}

// TestCommFilterSelectsTheNewNameOfRenamedTasks is the -comm half of the bug: the
// filter used to invert for a renamed task. With -comm <new name> the renamed
// tasks' rows were dropped (the cache still said the old name) while a stale
// name selected them. Here -comm wk-sibling - the name only the sibling-renamed
// workers take, by a write from another thread - must keep exactly their
// pwrite64 rows: every record has that comm, none is a pread64 (those ran
// under the old name), and nearly all the expected rows survive.
func TestCommFilterSelectsTheNewNameOfRenamedTasks(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(lateRenameScenario, defaultDuration,
		[]string{"-trace-syscalls", lateRenameSyscallFilter, "-comm", lateRenameSiblingName})
	if err != nil {
		t.Fatalf("run scenario %s: %v", lateRenameScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)

	if reads := countCollapsed(t, result, "pread64", lateRenameSiblingName); reads != 0 {
		t.Errorf("-comm %s kept %d pread64 rows, want 0: they ran before the rename", lateRenameSiblingName, reads)
	}
	writes := countCollapsed(t, result, "pwrite64", lateRenameSiblingName)
	requireRowCount(t, "pwrite64 rows kept by -comm "+lateRenameSiblingName, writes, lateRenameStyleRows)
}

// TestCommFilterNoLongerSelectsTheOldNameAfterARename is the negative of the
// test above: -comm ioworkload must keep the pread64 rows the tasks issued under
// that name, but not one pwrite64 row, because every task renamed itself before
// them (the stale cache used to keep admitting them, five rows labelled with the
// old name in the original report).
func TestCommFilterNoLongerSelectsTheOldNameAfterARename(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(lateRenameScenario, defaultDuration,
		[]string{"-trace-syscalls", lateRenameSyscallFilter, "-comm", lateRenameOriginalName})
	if err != nil {
		t.Fatalf("run scenario %s: %v", lateRenameScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)

	if writes := countCollapsed(t, result, "pwrite64", lateRenameOriginalName); writes != 0 {
		t.Errorf("-comm %s kept %d pwrite64 rows, want 0: every task renamed itself first", lateRenameOriginalName, writes)
	}
	reads := countCollapsed(t, result, "pread64", lateRenameOriginalName)
	// The workers' phase-1 reads plus the main thread's: it keeps the inherited
	// name until its own rename too.
	requireRowCount(t, "pread64 rows kept by -comm "+lateRenameOriginalName, reads, lateRenameWorkerRows+lateRenameOpsPerPhase)
}
