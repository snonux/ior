package integrationtests

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	threadExitScenario = "thread-exit-keeps-fd"
	// exitProbeSkipped is the warning ior logs when sched_process_exit
	// cannot be attached; without the probe no exit record exists and the
	// name-stability assertion would pass vacuously.
	exitProbeSkipped = "skipping sched_process_exit probe"
	// zeroDropsLine is the end-of-run statistics line for a run that lost
	// no ring-buffer record; a lost exit record would also make the
	// assertion vacuous.
	zeroDropsLine = "ring buffer drops: 0 ("
	// statsLineWait bounds the wait for ior's final statistics to be
	// scanned from its output after the process exited.
	statsLineWait = 2 * time.Second
)

var threadExitTraceArgs = []string{"-trace-syscalls", "pipe2,write,close"}

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
// alone (the harness's -pid is reset to -1), exercising the BPF program with
// TID_FILTER set and TID_FILTER_TGID resolved from /proc/<tid>/status. The
// workload's main goroutine is pinned to the main thread (ioworkload init()),
// whose tid equals the pid, so -tid <pid> traces exactly the thread that does
// the pipe I/O.
func TestThreadExitKeepsFdNameUnderTidFilter(t *testing.T) {
	runThreadExitScenario(t, func(pid int) []string {
		return []string{"-pid", "-1", "-tid", strconv.Itoa(pid)}
	})
}

// runThreadExitScenario runs the thread-exit scenario with the extra ior args
// scopeArgs(workloadPID) returns (nil: none) and asserts the pipe name is
// stable, the exit probe attached, and no ring-buffer record was lost.
func runThreadExitScenario(t *testing.T, scopeArgs func(pid int) []string) {
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
// dropped, or a stable name would prove nothing.
func assertExitProbeEffective(t *testing.T, out *OutputCapture) {
	t.Helper()
	deadline := time.Now().Add(statsLineWait)
	for !strings.Contains(out.String(), "ring buffer drops:") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
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
