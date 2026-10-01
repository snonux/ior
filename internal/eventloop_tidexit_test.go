package internal

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/event"
	"ior/internal/types"

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
		{"leader target, its process dies from another thread (group-dead)", -1, crossPidA, func(t *testing.T, tid uint32) []byte {
			// E.g. the thread that inherited the leader tid in an execve was
			// killed in de_thread: no unflagged record of the tid comes, but
			// a group-dead record of tgid == -tid means the tid is gone.
			return makeProcessExitEvent(t, defaulTime, tid, siblingTid)
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

// makeTidInheritedExitEvent is the exit record of leader pid killed by another
// thread's execve (de_thread): a thread exit flagged IOR_EXIT_TID_INHERITED,
// because the exec'ing thread takes over the tid.
func makeTidInheritedExitEvent(t *testing.T, time uint64, pid uint32) []byte {
	t.Helper()
	raw := makeThreadExitEvent(t, time, pid, pid)
	binary.LittleEndian.PutUint32(raw[28:32], types.ProcessExitTidInherited)
	return raw
}

// TestTidLeaderSurvivesANonLeaderExec pins the decided semantics for
// -tid <leader> when another thread of the process calls execve (task os2):
// the old leader's exit record (flagged TidInherited) does not end the run,
// because the exec'ing thread now holds the traced tid and the BPF filter
// keeps tracing the new program; that program's own exit later does end it.
// The flag is ignored for any other tid, so it cannot shield a non-leader.
func TestTidLeaderSurvivesANonLeaderExec(t *testing.T) {
	el, stops, status := targetExitLoopTid(t, -1, int(crossPidA), true)
	feedExit(el, makeTidInheritedExitEvent(t, defaulTime, crossPidA))
	if *stops != 0 || len(*status) != 0 {
		t.Fatalf("the inherited-tid exit of the old leader ended the run: stops = %d, status = %q", *stops, *status)
	}
	// The exec'd program, now the leader under the same tid, exits.
	feedExit(el, makeThreadExitEvent(t, defaulTime+1_000, crossPidA, crossPidA))
	want := "Traced thread " + strconv.Itoa(int(crossPidA)) + " exited, stopping the trace"
	if *stops != 1 || len(*status) != 1 || (*status)[0] != want {
		t.Fatalf("the exec'd program's exit: stops = %d, status = %q, want 1 and [%q]", *stops, *status, want)
	}

	// -pid P with -tid P: the -pid rule only acts on group-dead records, so
	// the flagged record ends nothing there either.
	el, stops, _ = targetExitLoopTid(t, int(crossPidA), int(crossPidA), true)
	feedExit(el, makeTidInheritedExitEvent(t, defaulTime, crossPidA))
	if *stops != 0 {
		t.Fatal("the inherited-tid exit ended a -pid P -tid P run")
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
// ring-buffer drop) the liveness watcher ends a -tid run, only a headless one,
// and not under the IOR_TEST_DISABLE_TARGET_WATCH test hook.
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
	// The integration tests' record-only runs rely on this hook keeping the
	// watcher off.
	t.Setenv(disableTargetWatchEnv, "1")
	if run(true, 500*time.Millisecond) {
		t.Fatal("the liveness watcher ran although " + disableTargetWatchEnv + "=1")
	}
}

// TestThreadWatchFromProcfs covers the -tid specifics of the procfs
// mechanism: a zombie thread is gone even though its siblings run (a zombie
// process leader with live threads is not, for -pid), a recycled tid has
// another start time, and a live thread is alive. A thread's zombie state is
// only trusted on the second poll in a row (confirm); a missing or recycled
// entry is final at once.
func TestThreadWatchFromProcfs(t *testing.T) {
	const id = 4242
	tests := []struct {
		name    string
		thread  bool
		stat    string
		tasks   []int
		want    bool
		confirm bool // the first gone() must say false, the second want
	}{
		{"live thread", true, statLine(id, "S", "100"), []int{id, id + 1}, false, false},
		{"zombie thread, siblings run", true, statLine(id, "Z", "100"), []int{id, id + 1}, true, true},
		{"dead-state thread", true, statLine(id, "X", "100"), []int{id}, true, true},
		{"recycled tid", true, statLine(id, "S", "999"), []int{id}, true, false},
		{"zombie leader with threads, process target", false, statLine(id, "Z", "100"), []int{id, id + 1}, false, false},
		{"zombie leader alone, process target", false, statLine(id, "Z", "100"), []int{id}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fakeProcStat(t, id, tt.stat, tt.tasks...)
			w := &targetWatch{target: traceTarget{id: id, thread: tt.thread}, root: root, pidfd: -1, startTime: "100"}
			if tt.confirm && w.gone() {
				t.Fatal("first gone() = true, want the exit confirmed by a second poll")
			}
			if got := w.gone(); got != tt.want {
				t.Fatalf("gone() = %v, want %v", got, tt.want)
			}
		})
	}
	// A thread with no /proc entry at all is gone at the first poll.
	w := &targetWatch{target: traceTarget{id: id, thread: true}, root: t.TempDir(), pidfd: -1, startTime: "100"}
	if !w.gone() {
		t.Fatal("a thread without a /proc entry was not gone at once")
	}
}

// TestThreadWatchIgnoresTheExecHandoverZombie pins why a thread's exit needs
// two polls (task os2): when a non-leader thread execs, the old leader is a
// zombie for an instant before the exec'ing thread takes over its tid and
// start time. A -tid <leader> watch that polls in that instant and then sees
// the live program must not end the run; a zombie seen once, then live, then
// a zombie again needs two fresh polls.
func TestThreadWatchIgnoresTheExecHandoverZombie(t *testing.T) {
	const id = 4343
	root := fakeProcStat(t, id, statLine(id, "Z", "100"), id, id+1)
	stat := filepath.Join(root, strconv.Itoa(id), "stat")
	setState := func(state string) {
		t.Helper()
		if err := os.WriteFile(stat, []byte(statLine(id, state, "100")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := &targetWatch{target: traceTarget{id: id, thread: true}, root: root, pidfd: -1, startTime: "100"}
	if w.gone() {
		t.Fatal("a zombie seen once ended the watch")
	}
	setState("S") // the exec'd program now holds the tid, same start time
	if w.gone() {
		t.Fatal("the exec'd program holding the tid was reported gone")
	}
	setState("Z")
	if w.gone() {
		t.Fatal("a zombie after a live poll was trusted without confirmation")
	}
	if !w.gone() {
		t.Fatal("a zombie seen on two polls in a row was not gone")
	}
}

// kernelHasPidfdThread reports whether the running kernel is Linux 6.9 or
// newer, the release that added PIDFD_THREAD (pidfd_open of a non-leader).
func kernelHasPidfdThread(t *testing.T) bool {
	t.Helper()
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("uname: %v", err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(unix.ByteSliceToString(uts.Release[:]), "%d.%d", &major, &minor); err != nil {
		t.Fatalf("parse kernel release %q: %v", unix.ByteSliceToString(uts.Release[:]), err)
	}
	return major > 6 || (major == 6 && minor >= 9)
}

// startNonLeaderThread parks a goroutine locked to an OS thread that is not
// the thread-group leader and returns that thread's tid; closing exit makes
// the goroutine return, which terminates the thread. A new goroutine can land
// on the main thread (the test binary does not pin its main goroutine; while
// the caller blocks on the handoff, the scheduler readily runs the new
// goroutine on the caller's own thread, which may be the main one), where
// returning while locked would not end the thread. The caller's goroutine is
// therefore locked to its thread while spawning, so the worker cannot take
// it, and a draw that still lands on the main thread is unlocked and retried.
func startNonLeaderThread(t *testing.T) (tid int, exit chan struct{}) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	exit = make(chan struct{})
	for range 100 {
		tidCh := make(chan int)
		go func() {
			runtime.LockOSThread()
			id := unix.Gettid()
			tidCh <- id
			if id == os.Getpid() {
				runtime.UnlockOSThread()
				return
			}
			// Locked and never unlocked: returning terminates this thread.
			<-exit
		}()
		if id := <-tidCh; id != os.Getpid() {
			return id, exit
		}
	}
	t.Fatal("could not get a goroutine onto a non-leader OS thread")
	return 0, nil
}

// TestTargetWatchRealThread drives the watch against a real non-leader
// thread: alive while it runs while the process (this test) lives on, gone
// once it exited, through the PIDFD_THREAD pidfd alone (procfs pointed at a
// fake entry that always says "alive", so only the pidfd can tell) and
// through procfs alone. On a kernel with PIDFD_THREAD (6.9+) the pidfd must
// open; a pidfdThread of 0 makes pidfd_open refuse the non-leader (EINVAL)
// and fails here.
func TestTargetWatchRealThread(t *testing.T) {
	tid, exit := startNonLeaderThread(t)

	w := openTargetWatch(procRoot, traceTarget{id: tid, thread: true})
	defer w.Close()
	if w.startTime == "" {
		t.Fatal("the start time of a live thread was not captured")
	}
	procfsOnly := &targetWatch{target: w.target, root: procRoot, pidfd: -1, startTime: w.startTime}
	var pidfdOnly *targetWatch
	switch {
	case w.pidfd >= 0:
		alive := fakeProcStat(t, tid, statLine(tid, "S", w.startTime), tid)
		pidfdOnly = &targetWatch{target: w.target, root: alive, pidfd: w.pidfd, startTime: w.startTime}
	case kernelHasPidfdThread(t):
		t.Fatal("pidfd_open(PIDFD_THREAD) of a live non-leader failed on a kernel that has PIDFD_THREAD (6.9+)")
	default:
		t.Log("kernel older than 6.9 has no PIDFD_THREAD: the pidfd-only check is skipped, procfs only")
	}
	if w.gone() || procfsOnly.gone() || (pidfdOnly != nil && pidfdOnly.gone()) {
		t.Fatal("a live thread reported gone")
	}
	// The thread's process (this test) lives on; its leader must stay alive.
	leader := openTargetWatch(procRoot, traceTarget{id: os.Getpid()})
	defer leader.Close()

	close(exit)
	waitGone := func(name string, watch *targetWatch) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !watch.gone() {
			if time.Now().After(deadline) {
				t.Fatalf("exited thread not reported gone by the %s watch", name)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitGone("combined", w)
	waitGone("procfs-only", procfsOnly)
	if pidfdOnly != nil {
		waitGone("pidfd-only", pidfdOnly)
	}
	if leader.gone() {
		t.Fatal("the process was reported gone when only one of its threads exited")
	}
}
