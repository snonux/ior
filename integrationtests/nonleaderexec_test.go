package integrationtests

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	nonLeaderExecScenario = "exec-non-leader-thread"
	// nonLeaderExecTidScenario is the same exec, with the exec thread parked
	// and its tid published before ior starts, for -tid runs.
	nonLeaderExecTidScenario = "exec-non-leader-thread-tid"
)

// TestNonLeaderExecIsPaired pins task 0p2 end to end. The workload calls
// execve from a non-main OS thread; de_thread() makes that thread continue
// under the leader's tid, so the execve enters under the caller's tid and
// returns under the pid. ior must still emit exactly one execve row, under
// the calling thread's tid and the workload's pid, with a measured duration.
// Before the fix the exit found no parked enter under the leader tid and the
// row was lost.
func TestNonLeaderExecIsPaired(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	tidFile := filepath.Join(h.OutputDir, "caller.tid")
	h.WorkloadEnv = []string{workerTidFileEnv + "=" + tidFile}
	result, pid, err := h.RunWithIorArgs(nonLeaderExecScenario, defaultDuration,
		[]string{"-trace-syscalls", "execve"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", nonLeaderExecScenario, err)
	}
	callerTid := readCallerTid(t, tidFile)
	if callerTid == pid {
		t.Fatalf("caller tid %d must be a non-leader tid of pid %d", callerTid, pid)
	}
	AssertNoUnexpectedPID(t, result, pid)
	assertOneExecveRowFor(t, result, callerTid)
}

// TestNonLeaderExecUnderTidFilterIsCompleted pins task dp2 end to end. ior
// traces only the exec'ing non-leader thread (-pid -1 -tid <caller>). After
// de_thread() that thread runs under the leader's tid, which the kernel-side
// tid filter rejects, so the execve's sys_exit record never reaches ior. The
// sched_process_exec record must still be emitted for the traced caller
// (flagged exit_untraced) and complete the parked enter: exactly one execve
// row under the caller's tid with a measured duration. Before the fix the
// exec record was filtered as well and no execve row appeared at all.
func TestNonLeaderExecUnderTidFilterIsCompleted(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	tidFile := filepath.Join(h.OutputDir, "caller.tid")
	h.WorkloadEnv = []string{workerTidFileEnv + "=" + tidFile}
	// The scenario parks the exec thread and publishes its tid before the
	// PID is announced, so the tid is known when ior starts.
	// An unreadable tid file is returned as an error, not t.Fatal: the
	// callback runs after the workload started and the harness must get the
	// chance to kill and reap it.
	h.IorArgsForPID = func(int) ([]string, error) {
		tid, err := readCallerTidFile(tidFile)
		if err != nil {
			return nil, err
		}
		return []string{"-pid", "-1", "-tid", strconv.Itoa(tid)}, nil
	}
	result, pid, err := h.RunWithIorArgs(nonLeaderExecTidScenario, defaultDuration,
		[]string{"-trace-syscalls", "execve"})
	if err != nil {
		t.Fatalf("run scenario %s: %v", nonLeaderExecTidScenario, err)
	}
	callerTid := readCallerTid(t, tidFile)
	if callerTid == pid {
		t.Fatalf("caller tid %d must be a non-leader tid of pid %d", callerTid, pid)
	}
	AssertNoUnexpectedPID(t, result, pid)
	assertOneExecveRowFor(t, result, callerTid)
}

// readCallerTidFile reads and parses the exec'ing thread's tid published by
// the workload. It returns an error instead of failing the test so it is safe
// to call from the harness's IorArgsForPID callback.
func readCallerTidFile(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read caller tid: %w", err)
	}
	tid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0, fmt.Errorf("parse caller tid %q: %w", raw, err)
	}
	return tid, nil
}

// readCallerTid is readCallerTidFile for test bodies: it fails the test.
func readCallerTid(t *testing.T, path string) int {
	t.Helper()
	tid, err := readCallerTidFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return tid
}

// assertOneExecveRowFor asserts exactly one execve row of true(1), reported
// under callerTid, with a measured duration.
func assertOneExecveRowFor(t *testing.T, result TestResult, callerTid int) {
	t.Helper()
	exp := ExpectedEvent{Tracepoint: "enter_execve", PathContains: "true", Comm: "ioworkload"}
	var count, duration uint64
	for _, rec := range result.Records {
		if !matchesExpectation(rec, exp) {
			continue
		}
		if int(rec.Tid) != callerTid {
			t.Errorf("execve row tid = %d, want the calling thread %d", rec.Tid, callerTid)
		}
		count += rec.Cnt.Count
		duration += rec.Cnt.Duration
	}
	if count != 1 {
		t.Fatalf("captured %d execve rows, want exactly 1", count)
	}
	if duration == 0 {
		t.Fatal("execve row has no duration")
	}
}
