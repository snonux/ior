package internal

import (
	"slices"
	"testing"

	"ior/internal/globalfilter"
)

// Tests for the -516 row of a run that does not trace restart_syscall and
// cannot start to (task u13, "Output order" in eventloop_restart.go). Such a
// row can never fold, and held it would wait for the thread's next record -
// the rest of the stopped sleep, or the thread's exit. A run whose trace set
// is final (traceSetIsFinal: every headless run) therefore completes it at
// its own exit. What trace setup tells the loop, and when, is pinned in
// ior_trace_wiring_test.go.

// allButRestartSyscall is the probe manager's IsActive of a run that traces
// everything except restart_syscall, and onlyRestartSyscall that of one that
// traces nothing else: together they show that restart_syscall's probe is the
// one the loop asks about.
func allButRestartSyscall(syscall string) bool { return syscall != "restart_syscall" }

func onlyRestartSyscall(syscall string) bool { return syscall == "restart_syscall" }

// TestUntracedRestartSyscallRowIsNotHeld: with restart_syscall outside a
// final trace set the stopped sleep's row is emitted by its -516 exit and
// the tracker stays empty. BPF knows nothing of that: the task is pending
// there, and the RESUME record it sends ahead of the thread's next traced
// enter - here the next sleep, long after the stopped one was resumed unseen
// - finds no row and changes nothing.
func TestUntracedRestartSyscallRowIsNotHeld(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.el.traceSetIsFinal(allButRestartSyscall)
		const next = restartBase + 5000

		f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
		rows := []restartRow{f.feedOne(f.sleepExit(restartBase+500, restartTid, -516), "clock_nanosleep -516 exit")}
		f.requireNothingHeld()
		f.feedNone(f.resumeRecord(next, restartTid), "RESUME ahead of the next traced enter")
		f.feedNone(f.sleepEnter(next, restartTid), "the next sleep's enter")
		rows = append(rows, f.feedOne(f.sleepExit(next+700, restartTid, 0), "the next sleep's exit"))

		want := []restartRow{
			{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase, duration: 500,
				sleepNs: restartSleepNs},
			{name: "clock_nanosleep", tid: restartTid, ret: 0, enterTime: next, duration: 700,
				gap: next - restartBase - 500, sleepNs: restartSleepNs},
		}
		if !slices.Equal(rows, want) {
			t.Fatalf("rows = %+v, want the -516 sleep at its own exit and the next sleep %+v", rows, want)
		}
		f.requireNothingHeld()
	})
}

// TestTracedRestartSyscallFoldsInAFinalTraceSet is the control: a final trace
// set that has restart_syscall in it folds a stopped sleep as every run did
// before the loop was told anything, whatever else is or is not attached.
func TestTracedRestartSyscallFoldsInAFinalTraceSet(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.el.traceSetIsFinal(onlyRestartSyscall)
		rows := stoppedSleepThenRestart(f, restartBase, restartBase+1500, restartBase+1500, restartBase+3000, 0)
		requireFoldedSleep(t, rows, restartBase, "restart_syscall is attached")
		f.requireNothingHeld()
		if f.el.numSyscalls != 1 {
			t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
		}
	})
}

// TestUntracedRestartSyscallLeavesTheReexecutionFoldOn: a call interrupted
// with -512/-513/-514 is continued by its own syscall, not by
// restart_syscall, so its row is held and folded whether or not
// restart_syscall is traced.
func TestUntracedRestartSyscallLeavesTheReexecutionFoldOn(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.el.traceSetIsFinal(allButRestartSyscall)
	requireFolded(t, f.foldRead(restartBase), restartBase, "restart_syscall does not continue a re-executed read")
	f.requireNothingHeld()
}
