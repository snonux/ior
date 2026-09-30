package internal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
)

// statLine is a /proc/<pid>/stat line: the command name is deliberately nasty
// (spaces and a closing parenthesis) to pin that fields are counted after the
// LAST ')'. Field 22 (starttime) is start.
func statLine(pid int, state, start string) string {
	// fields 3..21 are 19 placeholders (state first), then starttime.
	pre := []string{state}
	for i := 4; i <= 21; i++ {
		pre = append(pre, "0")
	}
	return fmt.Sprintf("%d (my ) comm) %s %s 0 0\n", pid, strings.Join(pre, " "), start)
}

// fakeProc lays out <root>/<pid>/stat and the listed task directories.
func fakeProcStat(t *testing.T, pid int, stat string, tasks ...int) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "task"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tid := range tasks {
		if err := os.MkdirAll(filepath.Join(dir, "task", fmt.Sprint(tid)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestStartTimeOfHandlesCommWithParentheses pins the field arithmetic.
func TestStartTimeOfHandlesCommWithParentheses(t *testing.T) {
	if got := startTimeOf(parseStatFields(statLine(42, "S", "987654"))); got != "987654" {
		t.Fatalf("start time = %q, want 987654", got)
	}
	if got := startTimeOf(parseStatFields("garbage")); got != "" {
		t.Fatalf("start time of a malformed line = %q, want empty", got)
	}
}

// TestTargetWatchGoneFromProcfs covers the procfs mechanism: alive, recycled
// pid (another start time), vanished /proc entry, exited zombie and the
// zombie leader whose threads still run. pidfd is off (-1) so only procfs
// decides.
func TestTargetWatchGoneFromProcfs(t *testing.T) {
	const pid = 4242
	tests := []struct {
		name  string
		stat  string // "" removes the pid's directory
		tasks []int
		want  bool
	}{
		{"alive, same process", statLine(pid, "S", "100"), []int{pid}, false},
		{"recycled pid has another start time", statLine(pid, "S", "555"), []int{pid}, true},
		{"vanished", "", nil, true},
		{"exited zombie, leader only", statLine(pid, "Z", "100"), []int{pid}, true},
		{"zombie leader, threads still running", statLine(pid, "Z", "100"), []int{pid, pid + 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fakeProcStat(t, pid, statLine(pid, "S", "100"), pid)
			w := &targetWatch{pid: pid, root: root, pidfd: -1, startTime: "100"}
			if tt.stat == "" {
				if err := os.RemoveAll(filepath.Join(root, fmt.Sprint(pid))); err != nil {
					t.Fatal(err)
				}
			} else {
				root = fakeProcStat(t, pid, tt.stat, tt.tasks...)
				w.root = root
			}
			if got := w.gone(); got != tt.want {
				t.Fatalf("gone() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTargetWatchUnknownIsAlive is the negative test: a stat failure that is
// not "no such file" says nothing, so the trace must not be ended on it.
func TestTargetWatchUnknownIsAlive(t *testing.T) {
	root := t.TempDir()
	// <root>/7/stat is a directory: ReadFile fails with EISDIR, not ENOENT.
	if err := os.MkdirAll(filepath.Join(root, "7", "stat"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := &targetWatch{pid: 7, root: root, pidfd: -1, startTime: "1"}
	if w.gone() {
		t.Fatal("an unreadable stat entry was treated as a dead target")
	}
}

// TestTargetWatchRealProcess drives both mechanisms against a real child:
// alive, then dead after a kill and reap. pidfd is the primary mechanism; the
// second half forces the procfs fallback, where a forged start time stands in
// for a recycled pid.
func TestTargetWatchRealProcess(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	w := openTargetWatch(procRoot, cmd.Process.Pid)
	defer w.Close()
	if w.startTime == "" {
		t.Fatal("the start time of a live child was not captured")
	}
	if w.gone() {
		t.Fatal("a live process reported gone")
	}

	recycled := &targetWatch{pid: w.pid, root: procRoot, pidfd: -1, startTime: w.startTime + "1"}
	if !recycled.gone() {
		t.Fatal("a pid whose start time changed was not reported gone")
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if !w.gone() {
		t.Fatal("a killed and reaped process was not reported gone")
	}
	procfsOnly := &targetWatch{pid: w.pid, root: procRoot, pidfd: -1, startTime: w.startTime}
	if !procfsOnly.gone() {
		t.Fatal("the procfs fallback did not report the dead process gone")
	}
}

// TestWatchTargetLivenessFiresOnce runs the watcher with a fake liveness
// function: alive for a few polls, then gone. It must stop the trace once,
// announce it, and return by itself.
func TestWatchTargetLivenessFiresOnce(t *testing.T) {
	el, stops, status := targetExitLoop(t, int(crossPidA), false)
	var polls atomic.Int32
	gone := func() bool { return polls.Add(1) > 3 }

	done := make(chan struct{})
	go func() {
		defer close(done)
		el.watchTargetLiveness(context.Background(), time.Millisecond, gone)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the watcher never noticed the dead target")
	}
	if polls.Load() != 4 {
		t.Fatalf("polls = %d, want 4 (it stops polling after firing)", polls.Load())
	}
	if *stops != 1 || len(*status) != 1 || !strings.Contains((*status)[0], "exited, stopping the trace") {
		t.Fatalf("stops = %d, status = %q, want one stop and the exit line", *stops, *status)
	}
}

// TestWatchTargetLivenessNegatives: a target that stays alive, a cancelled
// trace, no -pid and no liveness function must never stop the trace.
func TestWatchTargetLivenessNegatives(t *testing.T) {
	t.Run("alive target", func(t *testing.T) {
		el, stops, _ := targetExitLoop(t, int(crossPidA), false)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		el.watchTargetLiveness(ctx, time.Millisecond, func() bool { return false })
		if *stops != 0 {
			t.Fatal("the watcher stopped the trace of a live target")
		}
	})
	t.Run("trace already ending", func(t *testing.T) {
		el, stops, _ := targetExitLoop(t, int(crossPidA), false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		el.watchTargetLiveness(ctx, time.Millisecond, func() bool { return true })
		if *stops != 0 {
			t.Fatal("the watcher claimed a target death on a trace that was already ending")
		}
	})
	t.Run("no -pid", func(t *testing.T) {
		el, stops, _ := targetExitLoop(t, -1, false)
		el.watchTargetLiveness(context.Background(), time.Millisecond, func() bool { return true })
		if *stops != 0 {
			t.Fatal("the watcher acted without a -pid filter")
		}
	})
	t.Run("no liveness function", func(t *testing.T) {
		el, stops, _ := targetExitLoop(t, int(crossPidA), false)
		el.watchTargetLiveness(context.Background(), time.Millisecond, nil)
		if *stops != 0 {
			t.Fatal("the watcher acted without a liveness function")
		}
	})
}

// TestTargetExitTriggersShareOneStop: the group-dead record and the watcher
// are two routes to one stop and one status line, in either order.
func TestTargetExitTriggersShareOneStop(t *testing.T) {
	record := func(el *eventLoop) {
		el.processRawEvent(makeProcessExitEvent(t, defaulTime, crossPidA, crossTidA), make(chan *event.Pair, 1))
	}
	watcher := func(el *eventLoop) {
		el.watchTargetLiveness(context.Background(), time.Millisecond, func() bool { return true })
	}
	for name, order := range map[string][]func(*eventLoop){
		"record then watcher": {record, watcher},
		"watcher then record": {watcher, record},
	} {
		t.Run(name, func(t *testing.T) {
			el, stops, status := targetExitLoop(t, int(crossPidA), true)
			for _, trigger := range order {
				trigger(el)
			}
			if *stops != 1 || len(*status) != 1 {
				t.Fatalf("stops = %d, status lines = %d, want 1 and 1", *stops, len(*status))
			}
		})
	}
}

// TestHeadlessPidRunEndsWithoutTheExitRecord drives runTraceLoop with no
// group-dead record at all (as when the ring buffer dropped it): only the
// liveness watcher can end the run, and only for a headless one.
func TestHeadlessPidRunEndsWithoutTheExitRecord(t *testing.T) {
	run := func(verbose bool, wait time.Duration) bool {
		infra, rawCh, _, _ := plainTraceInfra(t)
		infra.el.cfg.pidFilter = int(defaultPid)
		infra.el.SetStatusCallback(func(...any) {})
		// The target "dies" only after the loop has taken a row, so sending it
		// cannot race the loop ending.
		var dead atomic.Bool
		infra.targetGone = dead.Load
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			runTraceLoop(infra, verbose, nil, func(...any) {})
		}()
		sendOpenPair(t, rawCh, defaulTime)
		dead.Store(true)
		select {
		case <-finished:
			return true
		case <-time.After(wait):
			infra.cancel()
			<-finished
			return false
		}
	}
	if !run(true, 10*time.Second) {
		t.Fatal("the headless trace kept running although its target was gone and no exit record came")
	}
	if run(false, 500*time.Millisecond) {
		t.Fatal("the liveness watcher ended a non-headless (TUI) trace")
	}
}

// TestTargetWatchOpensBeforeTheProbesAttach pins the ordering the watch exists
// for: the process snapshot (pidfd and start time) must be taken before the
// probe load/attach, which takes seconds. A target that dies in that window
// leaves no exit record, and a pid recycled before the snapshot would be
// recorded under the new process's start time, so gone() could never fire.
// It is structural, like the filter-before-BPF ordering test, because the
// real setup needs root and the BPF toolchain. Both headless entry points are
// checked: the parquet one bypasses runTraceWithContext.
func TestTargetWatchOpensBeforeTheProbesAttach(t *testing.T) {
	for _, tc := range []struct{ file, function, setup string }{
		{"ior.go", "runTraceWithContext", "setupTraceInfra"},
		{"ior_parquet_sink.go", "runHeadlessParquetWith", "setup"},
	} {
		t.Run(tc.function, func(t *testing.T) {
			decl, _ := parseInternalFunction(t, tc.file, tc.function)
			open := firstCallPosition(decl, "openHeadlessTargetWatch")
			setup := firstCallPosition(decl, tc.setup)
			if !open.IsValid() || !setup.IsValid() {
				t.Fatalf("%s must call openHeadlessTargetWatch and %s", tc.function, tc.setup)
			}
			if open >= setup {
				t.Fatalf("%s opens the target watch after %s: a target dying during the probe attach could no longer be told from a recycled pid", tc.function, tc.setup)
			}
			// The watch only reaches the trace loop through the infra, so the
			// handover must follow the setup that builds it.
			if attach := firstCallPosition(decl, "attachTo"); !attach.IsValid() || attach <= setup {
				t.Fatalf("%s must hand the watch to the infra (attachTo) after %s", tc.function, tc.setup)
			}
		})
	}
}

// TestTargetExitRecordHookIsExactlyOne pins the test hook's contract: only
// "1" disables the group-dead-record trigger, so a stray or empty value in the
// environment cannot silently turn the primary trigger off.
func TestTargetExitRecordHookIsExactlyOne(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "": false, "0": false, "true": false, "yes": false, "11": false} {
		t.Setenv(disableTargetExitRecordEnv, value)
		if got := targetExitRecordDisabled(); got != want {
			t.Errorf("%s=%q: targetExitRecordDisabled() = %v, want %v", disableTargetExitRecordEnv, value, got, want)
		}
	}
}
