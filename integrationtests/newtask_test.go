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
)

// TestNewThreadsAreNamedWithoutAFilter pins task fr2 end to end. Each of the
// workload's 40 threads is a task ior has never seen and issues its preads
// within microseconds, so an asynchronous /proc/<tid>/comm lookup lands after
// the thread's rows were emitted: before the task:task_newtask record, all of
// these rows carried an empty comm. The assertion is strict on purpose -
// assertParquetRowsOwnedBy tolerates an empty comm, which is exactly the
// symptom under test.
//
// Rows are selected by syscall and checked by comm/tid, never by row.File: with
// -trace-syscalls pread64 the open is not traced, so a row's path comes from a
// lazy /proc/<pid>/fd lookup that depends on how far ior's event loop trails
// the workload, which has nothing to do with the property under test.
func TestNewThreadsAreNamedWithoutAFilter(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, threadCommScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64"}, nil)
	preads := rowsBySyscall(rows, "pread64")
	if len(preads) != threadCommRows {
		t.Fatalf("captured %d pread64 rows, want %d", len(preads), threadCommRows)
	}
	tids := make(map[uint32]struct{})
	for _, row := range preads {
		if row.Comm != "ioworkload" {
			t.Errorf("row comm = %q, want %q: %+v", row.Comm, "ioworkload", row)
		}
		tids[row.TID] = struct{}{}
	}
	if len(tids) != threadCommRows/4 {
		t.Errorf("rows span %d threads, want %d short-lived ones", len(tids), threadCommRows/4)
	}
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
// the filter's comm, and their counts must add up to every pread issued.
func TestNewThreadsSurviveACommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64", "-comm", "ioworkload"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	if total := countCollapsed(t, result, "pread64", "ioworkload"); total != threadCommRows {
		t.Fatalf("-comm ioworkload kept %d pread64 rows, want %d", total, threadCommRows)
	}
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
// them, which the scenario makes true for any lag shorter than the pause and
// the linger (threadCommRenameSettle, threadCommLinger in the workload) by
// keeping the threads alive and the pause long; an event loop that stalls for
// longer than that would legitimately fail this test.
func TestRenamedThreadsKeepTheirNewName(t *testing.T) {
	rows, _ := runParquetScenarioRowsAllowingComms(t, threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pwrite64,pread64"}, nil, "ioworkload", renamedThreadComm)
	if warm := rowsBySyscall(rows, "pwrite64"); len(warm) != threadCommRows/4 {
		t.Errorf("captured %d warm-up pwrite64 rows, want %d", len(warm), threadCommRows/4)
	}
	measured := rowsBySyscall(rows, "pread64")
	for _, row := range measured {
		if row.Comm != renamedThreadComm {
			t.Errorf("row comm = %q, want the thread's own %q: %+v", row.Comm, renamedThreadComm, row)
		}
	}
	if len(measured) != threadCommRows {
		t.Fatalf("captured %d measured pread64 rows, want %d", len(measured), threadCommRows)
	}
}

// TestRenamedThreadsSurviveTheRenamedCommFilter: -comm <renamed> must keep the
// rows of the renamed threads (0 of them survived before the fix). Only the
// measured pread64 rows are counted: the warm-up pwrite64 is judged against the
// still-provisional inherited name, exactly like before any name was known, so
// the gate may drop it. Same timing caveat as the test above.
func TestRenamedThreadsSurviveTheRenamedCommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pwrite64,pread64", "-comm", renamedThreadComm})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommRenamedScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	if total := countCollapsed(t, result, "pread64", renamedThreadComm); total != threadCommRows {
		t.Fatalf("-comm %s kept %d measured pread64 rows, want %d", renamedThreadComm, total, threadCommRows)
	}
}
