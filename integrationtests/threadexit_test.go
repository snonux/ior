package integrationtests

import (
	"strings"
	"syscall"
	"testing"
)

var threadExitTraceArgs = []string{"-trace-syscalls", "pipe2,write,close"}

// TestThreadExitKeepsFdName pins the sched_process_exit group_dead gate end to
// end: the kernel must report a sibling thread's exit with group_dead clear,
// so userspace keeps the still-living process's fd-table entries. The
// workload writes to one pipe before and after another of its threads exits;
// both writes must carry the same tracked pipe name. Before the gate, the
// thread exit evicted the process's descriptors and the second write fell
// back to /proc/<pid>/fd, renaming it to the pipe:[inode] form.
func TestThreadExitKeepsFdName(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "thread-exit-keeps-fd", []ExpectedEvent{
		{
			Tracepoint: "enter_pipe2",
			MinCount:   1,
			Flags:      &ExpectedFlags{AccessMode: ptrTo(syscall.O_RDONLY), Set: syscall.O_CLOEXEC},
		},
		{PathContains: "pipe:", Tracepoint: "enter_write", MinCount: 2},
	}, threadExitTraceArgs)

	names := pipeWritePaths(result)
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

// pipeWritePaths sums enter_write counts per pipe path name.
func pipeWritePaths(result TestResult) map[string]uint64 {
	return writePaths(result, "pipe")
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
