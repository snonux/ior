package integrationtests

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
// issue one pwrite64 (warm-up), pause, then four pread64 calls (measured).
//
// Since task lr2 the rename is reported by the task:task_rename record, in
// ring-buffer order with the thread's syscalls, so every row of a thread - the
// warm-up too - carries the new name, whatever the lag of the event loop. (The
// fr2 mechanism, one /proc read queued by the first row, left the warm-up row
// with the inherited name and made the measured rows depend on the pause.) The
// row counts are only bounded, see threadCommMinKeptPercent.
func TestRenamedThreadsKeepTheirNewName(t *testing.T) {
	rows, _ := runParquetScenarioRowsAllowingComms(t, threadCommRenamedScenario, defaultDuration,
		[]string{"-trace-syscalls", "pwrite64,pread64"}, nil, "ioworkload", renamedThreadComm)
	warm := rowsBySyscall(rows, "pwrite64")
	requireRowCount(t, "warm-up pwrite64 rows", len(warm), threadCommRows/4)
	for _, row := range warm {
		if row.Comm != renamedThreadComm {
			t.Errorf("warm-up row comm = %q, want the thread's own %q: %+v", row.Comm, renamedThreadComm, row)
		}
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
// rows of the renamed threads (0 of them survived before the fix). The warm-up
// pwrite64 is judged against the renamed name too since task lr2 (before it the
// provisional inherited name was all the filter knew at that point), so the
// counts below cover both syscalls. The count is only bounded.
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
	warm := countCollapsed(t, result, "pwrite64", renamedThreadComm)
	requireRowCount(t, "warm-up pwrite64 rows kept by -comm "+renamedThreadComm, warm, threadCommRows/4)
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

const (
	forkInheritScenario = "fork-inherit-fds"
	// forkChildPidFileEnv mirrors ioworkload's env var for the child pid file.
	forkChildPidFileEnv = "IOR_WORKLOAD_CHILD_PID_FILE"
	// forkInheritDuration is how long the system-wide ior of the fork test runs.
	forkInheritDuration = 4
)

// TestForkedChildReadsInheritedPipeUnderItsTracedName pins task gr2 end to end.
// The workload creates a pipe (traced pipe2, named "pipe:<flags>:<r>:<w>"),
// writes a byte, fork()s, and the child reads the byte from its inherited copy
// of the read end. The child is a process ior has never seen: before the
// task_newtask record carried the creator's tgid, the child started with an
// empty fd table and its read row fell back to /proc/<child>/fd/<fd>, which
// spells the pipe "pipe:[N]" (or, once the child has exited, names nothing).
//
// The run is system-wide and narrowed by -comm: the fork child is out of scope
// under -pid, and it inherits the name "ioworkload", which the newtask record
// seeds (the parent's own rows are not matched: a pre-existing pid has no record
// and, without -pid, no startup seed, so they are not what is asserted).
//
// A system-wide run also sees every other ioworkload on the machine (a parallel
// integration test, a leftover process), whose reads of a pipe that pre-dates
// its ior resolve through procfs as "pipe:[N]" by design. The assertion is
// therefore restricted to the rows of this test's own child: the scenario
// publishes the child's pid ($IOR_WORKLOAD_CHILD_PID_FILE) and only records
// with that pid count, so a foreign read can neither fail nor satisfy the test.
// The child's read is the only reader of the pipe, so its record must exist and
// carry the traced spelling, never the procfs one. No timing is involved.
func TestForkedChildReadsInheritedPipeUnderItsTracedName(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	pidFile := filepath.Join(h.OutputDir, "fork-inherit.childpid")
	h.WorkloadEnv = []string{forkChildPidFileEnv + "=" + pidFile}
	result, _, err := h.RunSystemWideWithIorArgs(forkInheritScenario, forkInheritDuration,
		[]string{"-trace-syscalls", "pipe2,read,write", "-comm", "ioworkload"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", forkInheritScenario, err)
	}
	child := readForkChildPid(t, pidFile)

	tracedPipe := regexp.MustCompile(`^pipe:\d+:\d+:\d+$`)
	pipeReads := 0
	for _, rec := range result.Records {
		if rec.Pid != child || !strings.HasSuffix(rec.TraceID.String(), "_read") || !strings.HasPrefix(rec.Path, "pipe:") {
			continue
		}
		pipeReads += int(rec.Cnt.Count)
		if !tracedPipe.MatchString(rec.Path) {
			t.Errorf("forked child %d's read is named %q, want the inherited traced pipe name (pipe:<flags>:<r>:<w>), not a procfs form", child, rec.Path)
		}
	}
	if pipeReads == 0 {
		t.Fatalf("the forked child %d's read on the inherited pipe produced no record", child)
	}
}

// readForkChildPid returns the pid the fork-inherit-fds scenario published.
func readForkChildPid(t *testing.T, path string) uint32 {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the forked child's pid: %v", err)
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil || pid == 0 {
		t.Fatalf("forked child pid file holds %q: %v", raw, err)
	}
	return uint32(pid)
}
