package integrationtests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Task os2: a headless -tid run ends when the traced thread exits (the -tid
// counterpart of the vr2 -pid tests in signal_shutdown_test.go). Before the
// fix a -tid run whose thread was gone idled to -duration (60s here, 900s by
// default) and traced a recycled tid.

// workerTidTarget traces the parked worker thread of thread-exit-tid-worker
// with -tid alone: the workload publishes the worker's tid in a file before
// it announces its pid, the worker writes to a pipe and exits, and the
// process (held alive by the hold file) lives on.
func workerTidTarget(h *TestHarness) signalTarget {
	tidFile := filepath.Join(h.OutputDir, "worker.tid")
	h.WorkloadEnv = append(h.WorkloadEnv, workerTidFileEnv+"="+tidFile)
	return signalTarget{
		scenario: tidWorkerScenario,
		scope: func(int) ([]string, error) {
			raw, err := os.ReadFile(tidFile)
			if err != nil {
				return nil, err
			}
			return []string{"-tid", strings.TrimSpace(string(raw))}, nil
		},
	}
}

// TestHeadlessTidRunEndsWhenItsThreadExits: -tid <worker> ends shortly after
// the worker thread exits although the process is still alive (non-leader
// semantics), says so on stderr and keeps the worker's rows. The second case
// disables the exit-record trigger, so the liveness watcher alone has to end
// the run.
func TestHeadlessTidRunEndsWhenItsThreadExits(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"exit record", nil},
		{"liveness watcher only", []string{testDisableTargetExitRecordEnv + "=1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			target := workerTidTarget(&h)
			newCmd := func(iorArgs []string) *exec.Cmd {
				cmd := exec.Command(h.IorBinary, iorArgs...)
				cmd.Env = append(os.Environ(), tc.env...)
				return cmd
			}
			run := startTargetRun(t, h, target, modeArgs("plain", h.OutputDir), shutdownRunDuration, newCmd)

			// Far below -duration: only the thread's exit can have ended it.
			run.requireCleanExit(t, iorShutdownGrace)
			if err := run.workload.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("the workload process must outlive the traced thread: %v", err)
			}
			stdout, stderr := run.text()
			if !strings.Contains(stderr, "Traced thread ") || !strings.Contains(stderr, "exited, stopping the trace") {
				t.Fatalf("stderr does not announce the thread's exit:\n%s", stderr)
			}
			if !strings.Contains(stdout, "write") {
				t.Fatalf("plain output lost the worker's rows:\n%s", stdout)
			}
			run.releaseTarget(t)
		})
	}
}

// TestHeadlessTidRunOutlivesSiblingExitsAndEndsWithTheLeader traces the leader
// thread (-tid <pid>) of thread-exit-keeps-fd: a sibling thread exits while
// the leader runs on (the negative case: another task's exit must not end the
// run), and the run ends only when the leader itself exits with the process.
func TestHeadlessTidRunOutlivesSiblingExitsAndEndsWithTheLeader(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	target := signalTarget{
		scenario: threadExitScenario,
		scope:    func(pid int) ([]string, error) { return []string{"-tid", strconv.Itoa(pid)}, nil },
	}
	run := startTargetRun(t, h, target, modeArgs("plain", h.OutputDir), shutdownRunDuration, func(iorArgs []string) *exec.Cmd {
		return exec.Command(h.IorBinary, iorArgs...)
	})
	// The sibling thread exits right after the workload starts; give the
	// record time to travel, then require ior to be running still.
	time.Sleep(2 * shutdownDrainDelay)
	select {
	case err := <-run.done:
		t.Fatalf("ior ended although the traced thread was alive (a sibling exited; wait: %v)", err)
	default:
	}

	run.releaseTarget(t)
	run.requireCleanExit(t, iorShutdownGrace)
	stdout, stderr := run.text()
	if !strings.Contains(stderr, "Traced thread "+strconv.Itoa(run.workload.Process.Pid)+" exited, stopping the trace") {
		t.Fatalf("stderr does not announce the leader thread's exit:\n%s", stderr)
	}
	if !strings.Contains(stdout, "write") {
		t.Fatalf("plain output lost the leader's rows:\n%s", stdout)
	}
}
