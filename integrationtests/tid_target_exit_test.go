package integrationtests

import (
	"os"
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

// triggerCases are the ways a headless run can learn that its target ended,
// each tested alone: the target's exit record with the liveness watcher off,
// and the watcher with the record trigger off. Both print the same status
// line, so only switching the other one off proves a trigger works.
var triggerCases = []struct {
	name string
	env  []string
}{
	{"exit record only", []string{testDisableTargetWatchEnv + "=1"}},
	{"liveness watcher only", []string{testDisableTargetExitRecordEnv + "=1"}},
}

// TestHeadlessTidRunEndsWhenItsThreadExits: -tid <worker> ends shortly after
// the worker thread exits although the process is still alive (non-leader
// semantics), says so on stderr and keeps the worker's rows; once through the
// exit record alone and once through the liveness watcher alone.
func TestHeadlessTidRunEndsWhenItsThreadExits(t *testing.T) {
	for _, tc := range triggerCases {
		t.Run(tc.name, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			target := workerTidTarget(&h)
			run := startTargetRun(t, h, target, modeArgs("plain", h.OutputDir), shutdownRunDuration, iorCmdWithEnv(h, tc.env...))

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

// requireStillRunning fails if ior has already ended, after giving the
// workload's earlier records time to travel through the ring buffer.
func requireStillRunning(t *testing.T, run *signalRun, why string) {
	t.Helper()
	time.Sleep(2 * shutdownDrainDelay)
	select {
	case err := <-run.done:
		t.Fatalf("ior ended although %s (wait: %v)", why, err)
	default:
	}
}

// requireLeaderEnd releases the workload and requires the run to end, naming
// the leader thread, with wantRow in the plain output.
func requireLeaderEnd(t *testing.T, run *signalRun, wantRow string) {
	t.Helper()
	run.releaseTarget(t)
	run.requireCleanExit(t, iorShutdownGrace)
	stdout, stderr := run.text()
	if !strings.Contains(stderr, "Traced thread "+strconv.Itoa(run.workload.Process.Pid)+" exited, stopping the trace") {
		t.Fatalf("stderr does not announce the leader thread's exit:\n%s", stderr)
	}
	if !strings.Contains(stdout, wantRow) {
		t.Fatalf("plain output lacks the leader's %q rows:\n%s", wantRow, stdout)
	}
}

// leaderTidScope traces the workload's leader thread: -tid <pid>.
func leaderTidScope(pid int) ([]string, error) {
	return []string{"-tid", strconv.Itoa(pid)}, nil
}

// TestHeadlessTidRunOutlivesSiblingExitsAndEndsWithTheLeader traces the leader
// thread (-tid <pid>) of thread-exit-keeps-fd: a sibling thread exits while
// the leader runs on (the negative case: another task's exit must not end the
// run), and the run ends only when the leader itself exits with the process,
// through either trigger alone.
func TestHeadlessTidRunOutlivesSiblingExitsAndEndsWithTheLeader(t *testing.T) {
	for _, tc := range triggerCases {
		t.Run(tc.name, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			target := signalTarget{scenario: threadExitScenario, scope: leaderTidScope}
			run := startTargetRun(t, h, target, modeArgs("plain", h.OutputDir), shutdownRunDuration, iorCmdWithEnv(h, tc.env...))
			// The sibling thread exits right after the workload starts.
			requireStillRunning(t, run, "the traced thread was alive (a sibling exited)")
			requireLeaderEnd(t, run, "write")
		})
	}
}

// TestHeadlessTidLeaderRunSurvivesANonLeaderExec pins the decided -tid <leader>
// semantics for an execve from a non-leader thread (task os2). de_thread()
// kills the old leader, whose exit record carries the traced tid, then hands
// that tid to the exec'ing thread, which runs on as the new program (here the
// workload re-executed as open-basic). The BPF tid filter keeps tracing it,
// so the run must survive the old leader's record (flagged
// IOR_EXIT_TID_INHERITED), record the new program's open of testfile.txt, and
// end when the new program exits. Run with both triggers and with each alone:
// without the flag the record ended the run at the exec while the watcher
// never noticed anything.
//
// The "liveness watcher only" subtest proves that the watcher follows the
// inherited tid (pidfd and /proc/<tid> stay valid, the start time matches) and
// ends the run with the new program. It does not exercise the watcher's
// two-poll rule for the old leader's zombie state during de_thread(): that
// window lasts microseconds, and a 500 ms poll practically never lands in it.
// The rule is pinned by the unit tests (TestThreadWatchIgnoresTheExecHandoverZombie).
func TestHeadlessTidLeaderRunSurvivesANonLeaderExec(t *testing.T) {
	cases := append([]struct {
		name string
		env  []string
	}{{"both triggers", nil}}, triggerCases...)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enableParallelIfRequested(t)
			h := newTestHarness(t)
			target := signalTarget{scenario: nonLeaderExecIntoOpenScenario, scope: leaderTidScope}
			run := startTargetRun(t, h, target, modeArgs("plain", h.OutputDir), shutdownRunDuration, iorCmdWithEnv(h, tc.env...))
			// The exec happens right after the workload is released.
			requireStillRunning(t, run, "the traced tid lives on in the exec'd program")
			requireLeaderEnd(t, run, "testfile.txt")
		})
	}
}

// nonLeaderExecIntoOpenScenario is ioworkload's exec-non-leader-into-open.
const nonLeaderExecIntoOpenScenario = "exec-non-leader-into-open"
