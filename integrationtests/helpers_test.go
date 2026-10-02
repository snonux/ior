package integrationtests

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	iorparquet "ior/internal/parquet"
)

const (
	iorBinaryDefault      = "../ior"
	workloadBinaryDefault = "../ioworkload"
	defaultDuration       = 10
	parallelEnvVar        = "IOR_INTEGRATION_PARALLEL"
)

func newTestHarness(t *testing.T) TestHarness {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF")
	}

	return TestHarness{
		IorBinary:      absPath(t, iorBinaryDefault),
		WorkloadBinary: absPath(t, workloadBinaryDefault),
		OutputDir:      t.TempDir(),
	}
}

func absPath(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatalf("resolve path %s: %v", rel, err)
	}
	return p
}

// writeScript creates an executable shell script in dir and returns its path.
func writeScript(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+content+"\n"), 0o755); err != nil {
		t.Fatalf("write script %s: %v", name, err)
	}
	return path
}

func runScenario(t *testing.T, scenario string, expected []ExpectedEvent) {
	t.Helper()
	runScenarioResult(t, scenario, expected)
}

func runScenarioResult(t *testing.T, scenario string, expected []ExpectedEvent) (TestResult, int) {
	t.Helper()
	return runScenarioResultWithIorArgs(t, scenario, expected, nil)
}

func runScenarioResultWithIorArgs(t *testing.T, scenario string, expected []ExpectedEvent, extraIorArgs []string) (TestResult, int) {
	t.Helper()
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs(scenario, defaultDuration, extraIorArgs)
	if err != nil {
		t.Fatalf("run scenario %s: %v", scenario, err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, expected)
	return result, pid
}

func runParquetScenarioRows(t *testing.T, scenario string, duration int, extraIorArgs, workloadEnv []string) ([]iorparquet.Record, int) {
	t.Helper()
	return runParquetScenarioRowsAllowingComms(t, scenario, duration, extraIorArgs, workloadEnv, "ioworkload")
}

// runParquetScenarioRowsAllowingComms is runParquetScenarioRows for scenarios
// whose threads rename themselves: a row may carry any of comms (or none).
func runParquetScenarioRowsAllowingComms(t *testing.T, scenario string, duration int, extraIorArgs, workloadEnv []string, comms ...string) ([]iorparquet.Record, int) {
	t.Helper()
	enableParallelIfRequested(t)
	run := parquetScenarioRun(t, scenario, duration, extraIorArgs, workloadEnv, comms...)
	return run.rows, run.pid
}

// parquetRun is one headless Parquet run of a scenario: its rows, the
// workload's pid and everything ior printed, the statistics block included.
type parquetRun struct {
	rows   []iorparquet.Record
	pid    int
	logged string
}

// parquetScenarioRun runs scenario once in headless Parquet mode, with a
// harness of its own, and fails the test when the run fails, records nothing
// or records a row of another process or comm.
func parquetScenarioRun(t *testing.T, scenario string, duration int, extraIorArgs, workloadEnv []string, comms ...string) parquetRun {
	t.Helper()
	h := newTestHarness(t)
	h.WorkloadEnv = workloadEnv
	h.IorOutput = &OutputCapture{}
	path, pid, err := h.RunParquetWithIorArgs(scenario, duration, extraIorArgs)
	if err != nil {
		t.Fatalf("run parquet scenario %s: %v", scenario, err)
	}

	rows := readParquetRecords(t, path)
	if len(rows) == 0 {
		t.Fatalf("scenario %s produced no parquet rows", scenario)
	}
	assertParquetRowsOwnedBy(t, rows, uint32(pid), comms...)
	return parquetRun{rows: rows, pid: pid, logged: h.IorOutput.String()}
}

// foldRunAttempts is how often a scenario whose test requires folded rows is
// run before the test gives up on this host: once, and once more.
const foldRunAttempts = 2

// runFoldScenarioRows is runParquetScenarioRows for a test that requires an
// interrupted call to come out FOLDED into one row. ior refuses a fold when
// a record may have been lost between the call's halves - a ring-buffer
// drop, or a probe run the kernel skipped, which on a host with real-time
// tasks happens for real and for tasks that have nothing to do with the
// trace (task 723). Such a run cannot show what the test wants to see, and
// it is no failure either. So the rows of the first run whose statistics
// report no kernel-side loss are returned; a run that reports one is logged
// and the scenario run once more, and when that run lost something too the
// test is SKIPPED with the counts - never passed, and never failed for what
// the environment did.
func runFoldScenarioRows(t *testing.T, scenario string, duration int, extraIorArgs, workloadEnv []string) ([]iorparquet.Record, int) {
	t.Helper()
	enableParallelIfRequested(t)
	run, lost, err := FirstRunWithoutKernelLoss(foldRunAttempts, func() (parquetRun, KernelLoss, error) {
		run := parquetScenarioRun(t, scenario, duration, extraIorArgs, workloadEnv, "ioworkload")
		loss, err := ParseKernelLoss(run.logged)
		return run, loss, err
	})
	if err != nil {
		t.Fatalf("scenario %s: %v", scenario, err)
	}
	for i, loss := range lost {
		t.Logf("run %d of scenario %s lost or may have lost records (%s): ior refuses folds across that", i+1, scenario, loss)
	}
	if len(lost) == foldRunAttempts {
		t.Skipf("scenario %s: every one of %d runs reported kernel-side loss (last: %s); "+
			"folds cannot be required on this host right now", scenario, foldRunAttempts, lost[len(lost)-1])
	}
	return run.rows, run.pid
}

func runParquetErrorScenario(t *testing.T, scenario string, errno syscall.Errno, exp ExpectedRow, extraIorArgs []string) {
	t.Helper()
	rows, _ := runParquetScenarioRows(t, scenario, defaultDuration, extraIorArgs, nil)
	exp.Comm = "ioworkload"
	exp.RetVal = ptrTo(-int64(errno))
	exp.IsError = ptrTo(true)
	AssertRowsPresent(t, rows, []ExpectedRow{exp})
}

func readParquetRecords(t *testing.T, path string) []iorparquet.Record {
	t.Helper()
	rows, err := LoadParquetRows(path)
	if err != nil {
		t.Fatalf("load parquet records: %v", err)
	}
	return rows
}

func assertParquetRowsOwnedBy(t *testing.T, rows []iorparquet.Record, pid uint32, comms ...string) {
	t.Helper()
	for _, row := range rows {
		if row.PID != pid {
			t.Fatalf("parquet row PID = %d, want %d: %+v", row.PID, pid, row)
		}
		if row.Comm != "" && !slices.Contains(comms, row.Comm) {
			t.Fatalf("parquet row comm = %q, want one of %q: %+v", row.Comm, comms, row)
		}
	}
}

func ptrTo[T any](value T) *T {
	return &value
}

func enableParallelIfRequested(t *testing.T) {
	t.Helper()
	if os.Getenv(parallelEnvVar) == "1" {
		t.Parallel()
	}
}
