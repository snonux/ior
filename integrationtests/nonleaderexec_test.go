package integrationtests

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const nonLeaderExecScenario = "exec-non-leader-thread"

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
	raw, err := os.ReadFile(tidFile)
	if err != nil {
		t.Fatalf("read caller tid: %v", err)
	}
	callerTid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || callerTid == pid {
		t.Fatalf("caller tid %q must be a non-leader tid of pid %d", raw, pid)
	}
	AssertNoUnexpectedPID(t, result, pid)

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
