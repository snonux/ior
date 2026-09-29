package integrationtests

import (
	"os"
	"path/filepath"
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
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.WorkloadEnv = workloadEnv
	path, pid, err := h.RunParquetWithIorArgs(scenario, duration, extraIorArgs)
	if err != nil {
		t.Fatalf("run parquet scenario %s: %v", scenario, err)
	}

	rows := readParquetRecords(t, path)
	if len(rows) == 0 {
		t.Fatalf("scenario %s produced no parquet rows", scenario)
	}
	assertParquetRowsOwnedBy(t, rows, uint32(pid), "ioworkload")
	return rows, pid
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

func assertParquetRowsOwnedBy(t *testing.T, rows []iorparquet.Record, pid uint32, comm string) {
	t.Helper()
	for _, row := range rows {
		if row.PID != pid {
			t.Fatalf("parquet row PID = %d, want %d: %+v", row.PID, pid, row)
		}
		if row.Comm != "" && row.Comm != comm {
			t.Fatalf("parquet row comm = %q, want %q: %+v", row.Comm, comm, row)
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
