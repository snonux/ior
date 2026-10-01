package integrationtests

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	threadExitScenario = "thread-exit-keeps-fd"
	tidWorkerScenario  = "thread-exit-tid-worker"
	// workerTidFileEnv mirrors ioworkload's env var for the worker TID file.
	workerTidFileEnv = "IOR_WORKLOAD_TID_FILE"
	// exitProbeSkipped is the warning ior logs when sched_process_exit
	// cannot be attached; without the probe no exit record exists and the
	// name-stability assertion would pass vacuously.
	exitProbeSkipped = "skipping sched_process_exit probe"
	// zeroDropsLine is the end-of-run statistics line for a run that lost
	// no ring-buffer record; a lost exit record would also make the
	// assertion vacuous.
	zeroDropsLine = "ring buffer drops: 0 ("
	// targetStopLineSuffix ends the status line ior prints when a target-exit
	// trigger stops a headless run (eventLoop.targetExited).
	targetStopLineSuffix = "exited, stopping the trace"
)

var (
	threadExitTraceArgs = []string{"-trace-syscalls", "pipe2,write,close"}
	groupDeadExitsLine  = regexp.MustCompile(`group-dead exits: (\d+)`)
)

// TestThreadExitKeepsFdName pins the sched_process_exit group_dead gate end to
// end: the kernel must report a sibling thread's exit with group_dead clear,
// so userspace keeps the still-living process's fd-table entries. The
// workload writes to one pipe before and after another of its threads exits;
// both writes must carry the same tracked pipe name. Before the gate, the
// thread exit evicted the process's descriptors and the second write fell
// back to /proc/<pid>/fd, which renamed it or left it without a name.
func TestThreadExitKeepsFdName(t *testing.T) {
	runThreadExitScenario(t, nil)
}

// TestThreadExitKeepsFdNameUnderTidFilter runs the same scenario under -tid
// alone (the harness's -pid is reset to -1). The workload's main goroutine is
// pinned to the main thread (ioworkload init()), whose tid equals the pid, so
// -tid <pid> traces the thread that does the pipe I/O. The exiting sibling
// thread is not traced, so this covers BPF verifier acceptance and fd-name
// stability under a tid filter; the scoped group-dead bypass is exercised by
// TestTidFilterForwardsGroupDeadExitOfUntracedThread.
func TestThreadExitKeepsFdNameUnderTidFilter(t *testing.T) {
	runThreadExitScenario(t, func(pid int) ([]string, error) {
		return []string{"-pid", "-1", "-tid", strconv.Itoa(pid)}, nil
	})
}

// TestTidFilterForwardsGroupDeadExitOfUntracedThread pins the scoped -tid
// bypass end to end. ior traces only a worker thread (-tid <worker>, no
// -pid). The worker does pipe I/O and exits; then the process exits from its
// other threads, so the record ending the thread group comes from an
// untraced thread. filter() alone would drop it; the TID_FILTER_TGID bypass
// must forward it, and ior's "group-dead exits" statistic must count it.
// Without the bypass that counter stays 0, because the worker's own exit is
// not group-dead.
//
// Both target-exit triggers are switched off (task wz2). Since task os2 a
// headless -tid run ends on the traced thread's own exit record, and the
// liveness watcher ends it within one poll of that thread vanishing; both
// happen before the process exits, so the group-dead record arrives after
// the stop. The stop drain decodes only the backlog present at the stop (the
// trace window ends there), so the record was counted only when it happened
// to be buffered already: the test failed 9 of 20 runs at 15f7ecd and nearly
// always on a quiet host later. With the triggers off the run lasts until
// -duration, long after the workload exited, so the record is consumed
// inside the window whatever the timing. The bypass is BPF-side and
// independent of either trigger; the triggers are pinned by
// tid_target_exit_test.go.
func TestTidFilterForwardsGroupDeadExitOfUntracedThread(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.IorOutput = &OutputCapture{}
	h.IorEnv = []string{testDisableTargetExitRecordEnv + "=1", testDisableTargetWatchEnv + "=1"}
	tidFile := filepath.Join(h.OutputDir, "worker.tid")
	h.WorkloadEnv = []string{workerTidFileEnv + "=" + tidFile}
	h.IorArgsForPID = func(int) ([]string, error) {
		raw, err := os.ReadFile(tidFile)
		if err != nil {
			return nil, fmt.Errorf("read worker tid: %w", err)
		}
		return []string{"-pid", "-1", "-tid", strings.TrimSpace(string(raw))}, nil
	}
	result, pid, err := h.RunWithIorArgs(tidWorkerScenario, defaultDuration, threadExitTraceArgs)
	if err != nil {
		t.Fatalf("run scenario %s: %v", tidWorkerScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	AssertEventsPresent(t, result, []ExpectedEvent{
		{PathContains: "pipe:", Tracepoint: "enter_write", MinCount: 1},
	})
	assertExitProbeEffective(t, h.IorOutput)
	// A stop line means a trigger still fired (a renamed or ignored hook),
	// which would make the count below timing-dependent again.
	if strings.Contains(h.IorOutput.String(), targetStopLineSuffix) {
		t.Fatalf("ior ended on the target's exit despite the disabled triggers; the group-dead count would race the stop")
	}
	if got := groupDeadExits(t, h.IorOutput.String()); got < 1 {
		t.Fatalf("group-dead exits = %d, want >= 1: the untraced thread's group-dead record did not bypass -tid", got)
	}
}

// groupDeadExits parses the count from ior's "group-dead exits: N" line.
func groupDeadExits(t *testing.T, logged string) int {
	t.Helper()
	m := groupDeadExitsLine.FindStringSubmatch(logged)
	if m == nil {
		t.Fatalf("ior output lacks a %q statistics line", "group-dead exits")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse group-dead exits %q: %v", m[1], err)
	}
	return n
}

// runThreadExitScenario runs the thread-exit scenario with the extra ior args
// scopeArgs(workloadPID) returns (nil: none; an error aborts the run and the
// harness reaps the workload) and asserts the pipe name is
// stable, the exit probe attached, and no ring-buffer record was lost.
func runThreadExitScenario(t *testing.T, scopeArgs func(pid int) ([]string, error)) {
	t.Helper()
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	h.IorOutput = &OutputCapture{}
	h.IorArgsForPID = scopeArgs
	result, pid, err := h.RunWithIorArgs(threadExitScenario, defaultDuration, threadExitTraceArgs)
	if err != nil {
		t.Fatalf("run scenario %s: %v", threadExitScenario, err)
	}
	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_pipe2",
			MinCount:   1,
			Flags:      &ExpectedFlags{AccessMode: ptrTo(syscall.O_RDONLY), Set: syscall.O_CLOEXEC},
		},
		{PathContains: "pipe:", Tracepoint: "enter_write", MinCount: 2},
	})
	assertExitProbeEffective(t, h.IorOutput)
	assertStablePipeWriteName(t, result)
}

// assertExitProbeEffective fails the test when its premise did not hold: the
// sched_process_exit probe must have attached and no record may have been
// dropped, or a stable name would prove nothing. The harness reads ior's
// output to EOF before it reaps ior, so the capture already holds the final
// statistics block when the run returns; no polling is needed.
func assertExitProbeEffective(t *testing.T, out *OutputCapture) {
	t.Helper()
	logged := out.String()
	if strings.Contains(logged, exitProbeSkipped) {
		t.Fatalf("ior skipped the sched_process_exit probe; the scenario would pass vacuously")
	}
	if !strings.Contains(logged, zeroDropsLine) {
		t.Fatalf("ior output lacks %q: ring-buffer records were lost or the statistics are missing", zeroDropsLine)
	}
}

// assertStablePipeWriteName requires every pipe write to carry one tracked
// pipe name, never the procfs pipe:[inode] form.
func assertStablePipeWriteName(t *testing.T, result TestResult) {
	t.Helper()
	names := writePaths(result, "pipe")
	var total uint64
	for name, count := range names {
		if strings.HasPrefix(name, "pipe:[") {
			t.Fatalf("write resolved through the procfs fallback as %q (count %d): "+
				"a thread exit evicted the living process's fd entries; all names %v", name, count, names)
		}
		total += count
	}
	if len(names) != 1 {
		t.Fatalf("pipe writes split across %d names %v, want one stable name", len(names), names)
	}
	if total < 2 {
		// A write resolved through the fallback may not carry a pipe name at
		// all, so show every write path to make the regression visible.
		t.Fatalf("pipe writes = %d, want >= 2 (before and after the thread exit); all write paths %v",
			total, writePaths(result, ""))
	}
}

// writePaths sums enter_write counts per path name starting with prefix.
func writePaths(result TestResult, prefix string) map[string]uint64 {
	names := make(map[string]uint64)
	for _, rec := range result.Records {
		if !strings.Contains(rec.TraceID.String(), "enter_write") || !strings.HasPrefix(rec.Path, prefix) {
			continue
		}
		names[rec.Path] += rec.Cnt.Count
	}
	return names
}
