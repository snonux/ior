package internal

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"

	"golang.org/x/sys/unix"
)

// Task os2: a headless -tid run ends when the traced thread exits.

const (
	// workerTid is the traced thread; it belongs to process crossPidA, whose
	// leader (tid == crossPidA) and another sibling (siblingTid) are not traced.
	workerTid  = crossPidA + 7
	siblingTid = crossPidA + 8
)

// feedExit hands one raw exit record to the loop.
func feedExit(el *eventLoop, raw []byte) {
	el.processRawEvent(raw, make(chan *event.Pair, 1))
}

// TestTidTargetExitStopsTheTrace: the traced thread's own exit record ends a
// headless -tid run, for every shape the record can have, with one status
// line that names the thread.
func TestTidTargetExitStopsTheTrace(t *testing.T) {
	tests := []struct {
		name string
		pid  int // -pid filter, -1: none
		tid  uint32
		raw  func(t *testing.T, tid uint32) []byte
	}{
		{"non-leader thread, process lives on", -1, workerTid, func(t *testing.T, tid uint32) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, tid)
		}},
		{"last thread of the process (group-dead)", -1, workerTid, func(t *testing.T, tid uint32) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidA, tid)
		}},
		{"leader exits while siblings run", -1, crossPidA, func(t *testing.T, tid uint32) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, tid)
		}},
		{"legacy record with unknown group_dead", -1, workerTid, func(t *testing.T, tid uint32) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, tid)[:24]
		}},
		{"with -pid of the same process", crossPidA, workerTid, func(t *testing.T, tid uint32) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, tid)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el, stops, status := targetExitLoopTid(t, tt.pid, int(tt.tid), true)
			feedExit(el, tt.raw(t, tt.tid))
			if *stops != 1 {
				t.Fatalf("stopTrace called %d times after the traced thread's exit, want 1", *stops)
			}
			want := "Traced thread " + strconv.FormatUint(uint64(tt.tid), 10) + " exited, stopping the trace"
			if len(*status) != 1 || (*status)[0] != want {
				t.Fatalf("status = %q, want [%q]", *status, want)
			}
		})
	}
}

// TestTidTargetExitIgnoresEveryOtherExit is the negative test: the exit of any
// task other than the traced thread must keep the run going - a sibling
// thread, the leader of the traced thread's process when the tid differs, the
// group-dead record of that process forwarded from another thread (the -tid
// bypass), an unrelated process, a record whose pid (not tid) equals the -tid
// value, and the whole thing in the TUI (not armed).
func TestTidTargetExitIgnoresEveryOtherExit(t *testing.T) {
	tests := []struct {
		name  string
		armed bool
		raw   func(t *testing.T) []byte
	}{
		{"sibling thread exits", true, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, siblingTid)
		}},
		{"leader exits, a worker is traced", true, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, crossPidA)
		}},
		{"group-dead record of the traced process from another thread", true, func(t *testing.T) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidA, siblingTid)
		}},
		{"unrelated process dies", true, func(t *testing.T) []byte {
			return makeProcessExitEvent(t, defaulTime, crossPidB, crossTidB)
		}},
		{"unrelated thread with the same pid number as the tid filter", true, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, workerTid, siblingTid)
		}},
		{"not armed (TUI)", false, func(t *testing.T) []byte {
			return makeThreadExitEvent(t, defaulTime, crossPidA, workerTid)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			el, stops, status := targetExitLoopTid(t, -1, workerTid, tt.armed)
			feedExit(el, tt.raw(t))
			if *stops != 0 || len(*status) != 0 {
				t.Fatalf("stopTrace calls = %d, status = %q, want none", *stops, *status)
			}
		})
	}
}

// TestTidTargetExitStopsOnce: the exit record, a recycled tid exiting later and
// the liveness watcher are routes to one stop and one status line.
func TestTidTargetExitStopsOnce(t *testing.T) {
	el, stops, status := targetExitLoopTid(t, -1, workerTid, true)
	feedExit(el, makeThreadExitEvent(t, defaulTime, crossPidA, workerTid))
	feedExit(el, makeThreadExitEvent(t, defaulTime+2*groupDeadDedupWindowNs, crossPidB, workerTid))
	el.watchTargetLiveness(context.Background(), time.Millisecond, func() bool { return true })
	if *stops != 1 || len(*status) != 1 {
		t.Fatalf("stops = %d, status lines = %d, want 1 and 1", *stops, len(*status))
	}
}

// TestPidAndTidTargetsKeepBothTriggers: with -pid P -tid T the run ends on T's
// exit and, should that record never come, on P's group-dead record; neither
// P's other threads nor other processes end it.
func TestPidAndTidTargetsKeepBothTriggers(t *testing.T) {
	el, stops, _ := targetExitLoopTid(t, crossPidA, workerTid, true)
	feedExit(el, makeThreadExitEvent(t, defaulTime, crossPidA, siblingTid))
	feedExit(el, makeProcessExitEvent(t, defaulTime, crossPidB, crossTidB))
	if *stops != 0 {
		t.Fatal("an exit that is neither the traced thread nor its process ended the run")
	}
	feedExit(el, makeProcessExitEvent(t, defaulTime, crossPidA, siblingTid))
	if *stops != 1 {
		t.Fatalf("stopTrace called %d times after the process died, want 1", *stops)
	}
}

// TestTidWatcherNamesTheThread: the liveness watcher of a -tid run ends it
// naming the thread, and without any filter it never acts.
func TestTidWatcherNamesTheThread(t *testing.T) {
	el, stops, status := targetExitLoopTid(t, -1, workerTid, false)
	el.watchTargetLiveness(context.Background(), time.Millisecond, func() bool { return true })
	if *stops != 1 || len(*status) != 1 || !strings.HasPrefix((*status)[0], "Traced thread ") {
		t.Fatalf("stops = %d, status = %q, want one 'Traced thread ...' line", *stops, *status)
	}
	el, stops, _ = targetExitLoopTid(t, -1, -1, false)
	el.watchTargetLiveness(context.Background(), time.Millisecond, func() bool { return true })
	if *stops != 0 {
		t.Fatal("the watcher acted without a -pid or -tid filter")
	}
}

// TestNewTraceTarget pins how the two filters resolve: -tid is the narrower
// scope and wins, -pid alone is the process, neither is no target.
func TestNewTraceTarget(t *testing.T) {
	tests := []struct {
		pid, tid int
		want     traceTarget
		wantOK   bool
	}{
		{-1, -1, traceTarget{}, false},
		{0, 0, traceTarget{}, false},
		{42, -1, traceTarget{id: 42}, true},
		{-1, 43, traceTarget{id: 43, thread: true}, true},
		{42, 43, traceTarget{id: 43, thread: true}, true},
	}
	for _, tt := range tests {
		got, ok := newTraceTarget(tt.pid, tt.tid)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("newTraceTarget(%d, %d) = %v, %v; want %v, %v", tt.pid, tt.tid, got, ok, tt.want, tt.wantOK)
		}
	}
	if got := (traceTarget{id: 5, thread: true}).String(); got != "thread 5" {
		t.Errorf("String() = %q, want %q", got, "thread 5")
	}
}

// runTidTraceLoop runs runTraceLoop over a loop scoped to -tid defaultTid and
// feeds it one syscall pair followed by the exit record of exitTid (process
// defaultPid). It reports whether the loop ended by itself within wait and the
// rows that reached stdout; the loop is cancelled before returning either way.
func runTidTraceLoop(t *testing.T, verbose bool, exitTid uint32, wait time.Duration) (ended bool, stdout string) {
	t.Helper()
	infra, rawCh, pipeR, _ := plainTraceInfra(t)
	infra.el.cfg.tidFilter = int(defaultTid)
	infra.el.SetStatusCallback(func(...any) {})

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		runTraceLoop(infra, verbose, nil, func(...any) {})
	}()
	sendOpenPair(t, rawCh, defaulTime)
	rawCh <- makeThreadExitEvent(t, defaulTime+1_000, defaultPid, exitTid)

	select {
	case <-finished:
		ended = true
	case <-time.After(wait):
		infra.cancel()
		<-finished
	}
	return ended, readPipeFor(t, pipeR, 200*time.Millisecond)
}

// TestHeadlessTidRunEndsWithItsThread drives the real runTraceLoop wiring: a
// headless -tid run ends by itself when the traced thread exits (its process
// lives on: the record is a thread exit) and keeps the rows it produced.
func TestHeadlessTidRunEndsWithItsThread(t *testing.T) {
	ended, stdout := runTidTraceLoop(t, true, defaultTid, 10*time.Second)
	if !ended {
		t.Fatal("the headless trace kept running after its -tid thread exited")
	}
	if !strings.Contains(stdout, "openat") {
		t.Fatalf("the thread's row before its exit was lost, stdout = %q", stdout)
	}
}

// TestHeadlessTidRunSurvivesOtherExits is the negative wiring test: another
// thread of the process exiting, or the same exit in a non-headless run (the
// TUI), must not end the trace.
func TestHeadlessTidRunSurvivesOtherExits(t *testing.T) {
	if ended, _ := runTidTraceLoop(t, true, defaultTid+1, 500*time.Millisecond); ended {
		t.Fatal("a sibling thread's exit ended the headless -tid trace")
	}
	if ended, _ := runTidTraceLoop(t, false, defaultTid, 500*time.Millisecond); ended {
		t.Fatal("the exit of the traced thread ended a non-headless trace")
	}
}

// TestHeadlessTidRunEndsWithoutTheExitRecord: with no exit record at all (a
// ring-buffer drop) the liveness watcher ends a -tid run, and only a headless
// one.
func TestHeadlessTidRunEndsWithoutTheExitRecord(t *testing.T) {
	run := func(verbose bool, wait time.Duration) bool {
		infra, rawCh, _, _ := plainTraceInfra(t)
		infra.el.cfg.tidFilter = int(defaultTid)
		infra.el.SetStatusCallback(func(...any) {})
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
		t.Fatal("the headless -tid trace kept running although its thread was gone and no exit record came")
	}
	if run(false, 500*time.Millisecond) {
		t.Fatal("the liveness watcher ended a non-headless (TUI) -tid trace")
	}
}

// TestThreadWatchFromProcfs covers the -tid specifics of the procfs
// mechanism: a zombie thread is gone even though its siblings run (a zombie
// process leader with live threads is not, for -pid), a recycled tid has
// another start time, and a live thread is alive.
func TestThreadWatchFromProcfs(t *testing.T) {
	const id = 4242
	tests := []struct {
		name   string
		thread bool
		stat   string
		tasks  []int
		want   bool
	}{
		{"live thread", true, statLine(id, "S", "100"), []int{id, id + 1}, false},
		{"zombie thread, siblings run", true, statLine(id, "Z", "100"), []int{id, id + 1}, true},
		{"dead-state thread", true, statLine(id, "X", "100"), []int{id}, true},
		{"recycled tid", true, statLine(id, "S", "999"), []int{id}, true},
		{"zombie leader with threads, process target", false, statLine(id, "Z", "100"), []int{id, id + 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fakeProcStat(t, id, tt.stat, tt.tasks...)
			w := &targetWatch{target: traceTarget{id: id, thread: tt.thread}, root: root, pidfd: -1, startTime: "100"}
			if got := w.gone(); got != tt.want {
				t.Fatalf("gone() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTargetWatchRealThread drives the watch against a real non-leader
// thread: alive while it runs while the process (this test) lives on, gone
// once it exited, through the pidfd where the kernel has PIDFD_THREAD and
// through procfs alone either way.
func TestTargetWatchRealThread(t *testing.T) {
	tidCh := make(chan int)
	exit := make(chan struct{})
	go func() {
		// Locked and never unlocked: returning terminates this OS thread.
		runtime.LockOSThread()
		tidCh <- unix.Gettid()
		<-exit
	}()
	tid := <-tidCh

	w := openTargetWatch(procRoot, traceTarget{id: tid, thread: true})
	defer w.Close()
	procfsOnly := &targetWatch{target: w.target, root: procRoot, pidfd: -1, startTime: w.startTime}
	if w.startTime == "" {
		t.Fatal("the start time of a live thread was not captured")
	}
	if w.pidfd < 0 {
		t.Log("pidfd_open(PIDFD_THREAD) unavailable on this kernel: procfs mechanism only")
	}
	if w.gone() || procfsOnly.gone() {
		t.Fatal("a live thread reported gone")
	}
	// The thread's process (this test) lives on; its leader must stay alive.
	leader := openTargetWatch(procRoot, traceTarget{id: os.Getpid()})
	defer leader.Close()

	close(exit)
	deadline := time.Now().Add(5 * time.Second)
	for !(w.gone() && procfsOnly.gone()) {
		if time.Now().After(deadline) {
			t.Fatalf("exited thread not reported gone (pidfd watch: %v, procfs only: %v)", w.gone(), procfsOnly.gone())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if leader.gone() {
		t.Fatal("the process was reported gone when only one of its threads exited")
	}
}
