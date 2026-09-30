package integrationtests

import (
	"strings"
	"testing"

	iorparquet "ior/internal/parquet"
)

const (
	threadCommScenario = "thread-comm-short-lived"
	// threadCommRows is what the scenario issues: 40 fresh short-lived threads
	// with 4 pread64 calls each (threadCommThreads * threadCommPreads in
	// cmd/ioworkload/scenario_threadcomm.go).
	threadCommRows = 40 * 4
	// threadCommMinKeptPercent is the share of the expected rows (and of the
	// expected threads) a test requires, instead of an exact total. ior
	// occasionally loses a thread's whole set of pread64/pwrite64 ENTER records
	// while the EXIT records still arrive, at ~1.5-2% of runs, with the
	// ring-buffer drop counter at 0 (seen 152/160, 144/160 and 38/40 rows; it
	// also happens with an ior built before task fr2, so it is not what these
	// tests are about - see the follow-up task filed for it). What the tests
	// pin is which comm the rows that do arrive carry, so they require a large
	// fraction and forbid extras, never equality. A missing newtask seed loses
	// or mislabels nearly everything (11/160 rows under -comm, empty comm
	// otherwise), far below this bar.
	threadCommMinKeptPercent = 80
)

// minKept is the smallest count a test accepts when it expects want rows or
// threads (threadCommMinKeptPercent of want).
func minKept(want int) int { return want * threadCommMinKeptPercent / 100 }

// requireRowCount fails the test unless got is within [minKept(want), want]:
// a small loss is tolerated (see threadCommMinKeptPercent), rows beyond what
// the scenario issues never are.
func requireRowCount(t *testing.T, what string, got, want int) {
	t.Helper()
	if got > want || got < minKept(want) {
		t.Fatalf("captured %d %s, want between %d and %d", got, what, minKept(want), want)
	}
}

// TestNewThreadsAreNamedWithoutAFilter pins task fr2 end to end. Each of the
// workload's 40 threads is a task ior has never seen and issues its preads
// within microseconds, so an asynchronous /proc/<tid>/comm lookup lands after
// the thread's rows were emitted: before the task:task_newtask record, all of
// these rows carried an empty comm. The comm assertion is strict on purpose -
// assertParquetRowsOwnedBy tolerates an empty comm, which is exactly the
// symptom under test - while the row count is only bounded (see
// threadCommMinKeptPercent).
//
// Rows are selected by syscall and checked by comm/tid, never by row.File: with
// -trace-syscalls pread64 the open is not traced, so a row's path comes from a
// lazy /proc/<pid>/fd lookup that depends on how far ior's event loop trails
// the workload, which has nothing to do with the property under test.
func TestNewThreadsAreNamedWithoutAFilter(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, threadCommScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64"}, nil)
	preads := rowsBySyscall(rows, "pread64")
	requireRowCount(t, "pread64 rows", len(preads), threadCommRows)
	tids := make(map[uint32]struct{})
	for _, row := range preads {
		if row.Comm != "ioworkload" {
			t.Errorf("row comm = %q, want %q: %+v", row.Comm, "ioworkload", row)
		}
		tids[row.TID] = struct{}{}
	}
	requireRowCount(t, "threads with pread64 rows", len(tids), threadCommRows/4)
}

// rowsBySyscall returns the rows of one syscall, in their recorded order.
func rowsBySyscall(rows []iorparquet.Record, syscall string) []iorparquet.Record {
	var out []iorparquet.Record
	for _, row := range rows {
		if row.Syscall == syscall {
			out = append(out, row)
		}
	}
	return out
}

// countCollapsed sums the call counts of the collapsed records of one syscall
// and fails the test for any such record that does not carry wantComm. Records
// are matched by syscall only (see TestNewThreadsAreNamedWithoutAFilter for why
// not by path).
func countCollapsed(t *testing.T, result TestResult, syscall, wantComm string) int {
	t.Helper()
	total := 0
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), syscall) {
			continue
		}
		if rec.Comm != wantComm {
			t.Errorf("%s record comm = %q, want %q: %+v", syscall, rec.Comm, wantComm, rec)
		}
		total += int(rec.Cnt.Count)
	}
	return total
}

// TestNewThreadsSurviveACommFilter is the sharper half: with -comm a syscall of
// a tid that has no cached comm yet is judged with an empty comm, so a new
// thread's rows disappeared without any warning (0 of 200 in the original
// report). The newtask record seeds the cache before the thread's first
// syscall, so every one of them must now pass the comm filter. -parquet refuses
// content filters, hence the collapsed output; a surviving record always has
// the filter's comm, and their counts must add up to (nearly) every pread
// issued - the sharp signal is that they are not near zero.
func TestNewThreadsSurviveACommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64", "-comm", "ioworkload"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	total := countCollapsed(t, result, "pread64", "ioworkload")
	requireRowCount(t, "pread64 rows kept by -comm ioworkload", total, threadCommRows)
}

const (
	threadCommRenamedScenario = "thread-comm-renamed"
	// renamedThreadComm is the name the scenario's threads give themselves
	// (threadCommRenamedName in cmd/ioworkload/scenario_threadcomm.go).
	renamedThreadComm = "iorworker"
)

// TestRenamedThreadsKeepTheirNewName is the regression test for the review of
// task fr2: threads that rename themselves first thing (prctl(PR_SET_NAME) -
// tokio, Java, Chrome and Bun worker pools) kept the parent's comm for good,
// because the seed from the task_newtask record was authoritative and retired
// the procfs read that would have found the new name. The scenario's threads
// issue one pwrite64 (warm-up), pause, then four pread64 calls (measured);
// every pread64 row must carry the renamed comm, not "ioworkload".
//
// What is and is not deterministic: the warm-up row may carry the inherited
// name - the one /proc read that finds the new name is queued by that very row,
// so nothing can name it earlier - which is why the phases are told apart by
// syscall and only the measured ones are held to the renamed comm. The measured
// rows depend on the read having landed by the time the event loop reaches
// them. The scenario makes that true for an event-loop lag under about
// threadCommRenameSettle (500ms in the workload): the pause keeps the measured
// rows away from the warm-up. Past that (measured: ior stalled 0.8-1.4s right
// after the threads were created) the warm-up and measured rows are already
// queued in the ring buffer and are processed back to back, faster than the
// async read lands, so the measured rows legitimately keep "ioworkload" and
// this test fails. The linger (threadCommLinger) does not widen that bound: it
// only keeps the threads alive so a late read still finds them. The row count
// is only bounded, see threadCommMinKeptPercent.
func TestRenamedThreadsKeepTheirNewName(t *testing.T) {
	rows, _ := runParquetScenarioRowsAllowingComms(t, threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pwrite64,pread64"}, nil, "ioworkload", renamedThreadComm)
	warm := rowsBySyscall(rows, "pwrite64")
	if len(warm) > threadCommRows/4 || len(warm) < minKept(threadCommRows/4) {
		t.Errorf("captured %d warm-up pwrite64 rows, want between %d and %d",
			len(warm), minKept(threadCommRows/4), threadCommRows/4)
	}
	measured := rowsBySyscall(rows, "pread64")
	for _, row := range measured {
		if row.Comm != renamedThreadComm {
			t.Errorf("row comm = %q, want the thread's own %q: %+v", row.Comm, renamedThreadComm, row)
		}
	}
	requireRowCount(t, "measured pread64 rows", len(measured), threadCommRows)
	tids := make(map[uint32]struct{})
	for _, row := range measured {
		tids[row.TID] = struct{}{}
	}
	requireRowCount(t, "threads with measured pread64 rows", len(tids), threadCommRows/4)
}

// TestRenamedThreadsSurviveTheRenamedCommFilter: -comm <renamed> must keep the
// rows of the renamed threads (0 of them survived before the fix). Only the
// measured pread64 rows are counted: the warm-up pwrite64 is judged against the
// still-provisional inherited name, exactly like before any name was known, so
// the exit-side comm filter may drop it. Same timing caveat as the test above:
// an event-loop stall beyond ~500ms can fail it, and the count is only bounded.
func TestRenamedThreadsSurviveTheRenamedCommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pwrite64,pread64", "-comm", renamedThreadComm})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommRenamedScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	total := countCollapsed(t, result, "pread64", renamedThreadComm)
	requireRowCount(t, "measured pread64 rows kept by -comm "+renamedThreadComm, total, threadCommRows)
}

const threadCommFdTableScenario = "thread-comm-fdtable"

// TestFdTableChangeOfAnUncachedThreadReachesRowsUnderCommFilter pins task dr2
// end to end. The scenario's second thread pre-dates ior's attach, so no
// task_newtask record names it and its first traced syscall meets a tid with no
// cached comm; it dup3s b's description over a's descriptor number, and the
// main thread (comm seeded) then preads that number. Under -comm the old
// enter-side gate recycled the dup3 enter of such a thread, the shared fd table
// never changed, and the main thread's row reported a's path.
//
// Only ior-traced syscalls are involved (openat, dup3, pread64), so the path of
// the surviving row comes from the fd table, not from a lazy /proc lookup, and
// nothing depends on timing: the pread is issued after the dup3 returned.
func TestFdTableChangeOfAnUncachedThreadReachesRowsUnderCommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommFdTableScenario, defaultDuration,
		[]string{"-trace-syscalls", "openat,dup3,pread64", "-comm", "ioworkload"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommFdTableScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)

	var onB, onA uint64
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), "pread64") {
			continue
		}
		switch {
		case strings.Contains(rec.Path, "fdtable-b.txt"):
			onB += rec.Cnt.Count
		case strings.Contains(rec.Path, "fdtable-a.txt"):
			onA += rec.Cnt.Count
		default:
			t.Errorf("pread64 record with unexpected path %q", rec.Path)
		}
	}
	if onA != 0 || onB != 1 {
		t.Fatalf("pread64 after the other thread's dup3: %d row(s) on a's path, %d on b's path; want 0 and 1", onA, onB)
	}
}
