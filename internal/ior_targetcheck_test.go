package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ior/internal/flags"
)

// fakeProc lays out a procfs-like tree: one directory per pid with a task/
// subdirectory per thread, and (like the real /proc) a directly addressable
// /proc/<tid> for every thread.
func fakeProc(t *testing.T, threads map[int][]int) string {
	t.Helper()
	root := t.TempDir()
	for pid, tids := range threads {
		for _, tid := range tids {
			if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(pid), "task", strconv.Itoa(tid)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, strconv.Itoa(tid)), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestCheckTraceTarget(t *testing.T) {
	// Process 100 has threads 100 and 101; process 200 has thread 200.
	root := fakeProc(t, map[int][]int{100: {100, 101}, 200: {200}})
	tests := []struct {
		name     string
		pid, tid int
		wantErr  string
	}{
		{name: "no filter", pid: -1, tid: -1},
		{name: "existing pid", pid: 100, tid: -1},
		{name: "nonexistent pid", pid: 4000000, tid: -1, wantErr: "-pid 4000000: no such process"},
		{name: "tid of the pid", pid: 100, tid: 101},
		{name: "tid in another process", pid: 100, tid: 200, wantErr: "-tid 200: not a thread of -pid 100"},
		{name: "nonexistent tid with pid", pid: 100, tid: 999, wantErr: "-tid 999: not a thread of -pid 100"},
		{name: "tid alone exists", pid: -1, tid: 101},
		{name: "tid alone nonexistent", pid: -1, tid: 999, wantErr: "-tid 999: no such thread"},
		{name: "nonexistent pid wins over tid", pid: 999, tid: 101, wantErr: "-pid 999: no such process"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTraceTarget(root, flags.Config{PidFilter: tc.pid, TidFilter: tc.tid})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestCheckTraceTargetTreatsUnreadableProcAsPlausible pins the fail-open
// policy: only a definite "does not exist" rejects the target. A procfs that
// cannot be inspected (here a path component that is a file, so stat returns
// ENOTDIR rather than ENOENT) must not refuse a trace that might work.
func TestCheckTraceTargetTreatsUnreadableProcAsPlausible(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "100"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkTraceTarget(root, flags.Config{PidFilter: 100, TidFilter: 101}); err != nil {
		t.Fatalf("an inconclusive stat must not reject the target, got %v", err)
	}
}

// TestCheckTraceTargetAgainstTheRealProc runs against the live /proc: this
// process exists, and its own main thread belongs to it.
func TestCheckTraceTargetAgainstTheRealProc(t *testing.T) {
	self := os.Getpid()
	if err := checkTraceTarget(procRoot, flags.Config{PidFilter: self, TidFilter: self}); err != nil {
		t.Fatalf("own pid/tid rejected: %v", err)
	}
	if err := checkTraceTarget(procRoot, flags.Config{PidFilter: 1, TidFilter: self}); err == nil {
		t.Fatal("a tid that is not a thread of pid 1 must be rejected")
	}
}

func TestReportTraceTargetHeadlessFailsTUIWarns(t *testing.T) {
	cfg := flags.Config{PidFilter: 0x7ffffff0, TidFilter: -1} // far beyond pid_max: never exists
	if err := reportTraceTarget(cfg, true, failOnLog(t)); err == nil {
		t.Fatal("a headless run on a nonexistent pid must fail")
	}
	warned := &lineRecorder{}
	if err := reportTraceTarget(cfg, false, warned.log); err != nil {
		t.Fatalf("the TUI must only warn, got %v", err)
	}
	if !strings.Contains(warned.joined(), "no such process") {
		t.Fatalf("warning = %q, want the diagnostic", warned.joined())
	}
	if err := reportTraceTarget(flags.Config{PidFilter: -1, TidFilter: -1}, true, failOnLog(t)); err != nil {
		t.Fatalf("an unfiltered run must pass, got %v", err)
	}
}
