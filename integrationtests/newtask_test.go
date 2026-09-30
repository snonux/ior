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
// workload's 40 threads is a task ior has never seen and lives for a few
// microseconds, so an asynchronous /proc/<tid>/comm lookup either finds no
// process any more or lands after the thread's rows were emitted: before the
// task:task_newtask record, all of these rows carried an empty comm. The
// assertion is strict on purpose - assertParquetRowsOwnedBy tolerates an empty
// comm, which is exactly the symptom under test.
func TestNewThreadsAreNamedWithoutAFilter(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, threadCommScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64"}, nil)
	var preads []iorparquet.Record
	for _, row := range rows {
		if row.Syscall == "pread64" && strings.Contains(row.File, "thread-comm") {
			preads = append(preads, row)
		}
	}
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

// TestNewThreadsSurviveACommFilter is the sharper half: with -comm the enter
// gate drops a non-open syscall whose tid has no cached comm yet, so a new
// thread's rows disappeared without any warning (0 of 200 in the original
// report). The newtask record seeds the cache before the thread's first
// syscall, so every one of them must now pass the gate. -parquet refuses
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
	total := 0
	for _, rec := range result.Records {
		if strings.Contains(rec.TraceID.String(), "pread64") && strings.Contains(rec.Path, "thread-comm") {
			total += int(rec.Cnt.Count)
		}
	}
	if total != threadCommRows {
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
// warm up on one file and then read a second one after a pause; every row on
// the second file must carry the renamed comm, not "ioworkload".
func TestRenamedThreadsKeepTheirNewName(t *testing.T) {
	rows, _ := runParquetScenarioRowsAllowingComms(t, threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64"}, nil, "ioworkload", renamedThreadComm)
	measured := 0
	for _, row := range rows {
		if row.Syscall != "pread64" || !strings.Contains(row.File, "measured") {
			continue
		}
		measured++
		if row.Comm != renamedThreadComm {
			t.Errorf("row comm = %q, want the thread's own %q: %+v", row.Comm, renamedThreadComm, row)
		}
	}
	if measured != threadCommRows {
		t.Fatalf("captured %d measured pread64 rows, want %d", measured, threadCommRows)
	}
}

// TestRenamedThreadsSurviveTheRenamedCommFilter: -comm <renamed> must keep the
// rows of the renamed threads (0 of them survived before the fix). Warm-up rows
// are excluded from the count by path: the first enter of a thread is judged
// against the still-provisional inherited name, exactly like before any name
// was known.
func TestRenamedThreadsSurviveTheRenamedCommFilter(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pread64", "-comm", renamedThreadComm})
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadCommRenamedScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	total := 0
	for _, rec := range result.Records {
		if strings.Contains(rec.TraceID.String(), "pread64") && strings.Contains(rec.Path, "measured") {
			total += int(rec.Cnt.Count)
		}
	}
	if total != threadCommRows {
		t.Fatalf("-comm %s kept %d measured pread64 rows, want %d", renamedThreadComm, total, threadCommRows)
	}
}
