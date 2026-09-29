package integrationtests

import (
	"strings"
	"syscall"
	"testing"
)

var processExecTraceArgs = []string{"-trace-syscalls", "execve,execveat"}

func TestProcessKcmpFile(t *testing.T) {
	testProcessKcmpAttribution(t, "process-kcmp-file", true)
}

func TestProcessKcmpVM(t *testing.T) {
	testProcessKcmpAttribution(t, "process-kcmp-vm", false)
}

func testProcessKcmpAttribution(t *testing.T, scenario string, wantFile bool) {
	t.Helper()
	rows, _ := runParquetScenarioRows(t, scenario, defaultDuration,
		[]string{"-trace-syscalls", "kcmp,openat,close"}, nil)
	var targetPath string
	var targetFD int32
	for _, row := range rows {
		if row.Syscall == "openat" && strings.HasSuffix(row.File, "/kcmp-target") && !row.IsError {
			targetPath, targetFD = row.File, row.FD
		}
	}
	if targetPath == "" {
		t.Fatal("kcmp target open was not captured")
	}
	count := 0
	for _, row := range rows {
		if row.Syscall != "kcmp" {
			continue
		}
		count++
		if row.Ret != 0 && row.Ret != -int64(syscall.EPERM) && row.Ret != -int64(syscall.ENOSYS) {
			t.Errorf("unexpected kcmp return: %+v", row)
		}
		wantError := row.Ret >= -4095 && row.Ret < 0
		if row.IsError != wantError {
			t.Errorf("kcmp error flag disagrees with its return: %+v", row)
		}
		if wantFile && (row.File != targetPath || row.FD != targetFD) {
			t.Errorf("KCMP_FILE file=%q fd=%d, want %q fd=%d", row.File, row.FD, targetPath, targetFD)
		}
		// Pair.FileName persists nil File as the established N:file marker.
		if !wantFile && (row.File != "N:file" || row.FD != -1) {
			t.Errorf("KCMP_VM must have no file or fd: %+v", row)
		}
		if row.IsError {
			t.Logf("host denied kcmp (ret=%d); operand attribution still verified", row.Ret)
		}
	}
	if count != 1 {
		t.Errorf("captured %d kcmp rows, want 1", count)
	}
}

func TestProcessExecLifecycle(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "process-exec-lifecycle", []ExpectedEvent{
		{
			Tracepoint:   "enter_execve",
			PathContains: "ior-missing-execve-only",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint:   "enter_execveat",
			PathContains: "ior-missing-execveat-only",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, processExecTraceArgs)

	assertEventDurationPositive(t, result, ExpectedEvent{
		Tracepoint:   "enter_execve",
		PathContains: "ior-missing-execve-only",
		Comm:         "ioworkload",
	})
	assertEventDurationPositive(t, result, ExpectedEvent{
		Tracepoint:   "enter_execveat",
		PathContains: "ior-missing-execveat-only",
		Comm:         "ioworkload",
	})
}
