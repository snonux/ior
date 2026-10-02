package internal

import (
	"slices"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
)

// Tests for the -516 row of a run that does not trace restart_syscall
// ("Output order" in eventloop_restart.go). Such a row can never fold, and
// held it would wait for the thread's next record - the rest of the stopped
// sleep, or the thread's exit. So it is completed at its own exit: in a run
// whose trace set is final (task u13, traceSetIsFinal: every headless run),
// and in a TUI run for as long as the probe manager's reports say that
// restart_syscall's probes are off (task 023, watchProbeChanges and
// probesChanged). What trace setup tells the loop, and when, is pinned in
// ior_trace_wiring_test.go.

// allButRestartSyscall is the probe manager's IsActive of a run that traces
// everything except restart_syscall, and onlyRestartSyscall that of one that
// traces nothing else: together they show that restart_syscall's probe is the
// one the loop asks about.
func allButRestartSyscall(syscall string) bool { return syscall != "restart_syscall" }

func onlyRestartSyscall(syscall string) bool { return syscall == "restart_syscall" }

// requireStoppedSleepNotHeld feeds a sleep of restartTid that is stopped at
// base+500 and requires its row at that very record, the -516 exit, with the
// tracker left empty. BPF knows nothing of that: the task is pending there,
// and the RESUME record it sends ahead of the thread's next traced enter -
// here the next sleep, long after the stopped one was resumed unseen - finds
// no row and changes nothing.
func (f *restartFixture) requireStoppedSleepNotHeld(base uint64) {
	f.t.Helper()
	next := base + 5000
	if f.drops != nil {
		f.clockAt(base + 550)
	}
	f.feedNone(f.sleepEnter(base, restartTid), "clock_nanosleep enter")
	rows := []restartRow{f.feedOne(f.sleepExit(base+500, restartTid, -516), "clock_nanosleep -516 exit")}
	f.requireNothingHeld()
	f.feedNone(f.resumeRecord(next, restartTid), "RESUME ahead of the next traced enter")
	f.feedNone(f.sleepEnter(next, restartTid), "the next sleep's enter")
	rows = append(rows, f.feedOne(f.sleepExit(next+700, restartTid, 0), "the next sleep's exit"))

	// The first row's gap depends on what the thread did before base.
	rows[0].gap = 0
	want := []restartRow{
		{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: base, duration: 500, sleepNs: restartSleepNs},
		{name: "clock_nanosleep", tid: restartTid, ret: 0, enterTime: next, duration: 700,
			gap: next - base - 500, sleepNs: restartSleepNs},
	}
	if !slices.Equal(rows, want) {
		f.t.Fatalf("rows = %+v, want the -516 sleep at its own exit and the next sleep %+v", rows, want)
	}
	f.requireNothingHeld()
}

// TestUntracedRestartSyscallRowIsNotHeld: with restart_syscall outside a
// final trace set the stopped sleep's row is emitted by its -516 exit and
// the tracker stays empty.
func TestUntracedRestartSyscallRowIsNotHeld(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.el.traceSetIsFinal(allButRestartSyscall)
		f.requireStoppedSleepNotHeld(restartBase)
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

// The tests below are about a TUI run (task 023). Its probes change while the
// loop runs, so "attached now" says nothing about the moment a row the loop
// reads from the ring buffer was interrupted. The loop keeps the state of
// restart_syscall's probes from the probe manager's reports instead and holds
// no -516 row while they are provably detached; in every other state the
// rows are held, folded and refused as before.

// newTUIRestartFixture is a loop that listens to probe changes as a TUI run's
// does: watchProbeChanges at boot-clock time restartBase-1000, with isActive
// as the probe manager's IsActive at that moment. The manager itself is left
// out; the tests report its changes through the hook
// (changeRestartSyscallProbes).
func newTUIRestartFixture(t *testing.T, isActive func(syscall string) bool) *restartFixture {
	t.Helper()
	f := newReexecFixture(t, globalfilter.Filter{})
	f.clockAt(restartBase - 1000)
	f.el.watchProbeChanges(func(func(probemanager.Change)) {}, isActive)
	return f
}

// changeRestartSyscallProbes reports one change of restart_syscall's own
// probes at boot-clock time at, as the probe manager does on the goroutine
// that makes it: a detach (Changed), or the begin or the end of an attach,
// the end with what the attach left attached.
func (f *restartFixture) changeRestartSyscallProbes(at uint64, phase probemanager.ChangePhase, attached bool) {
	f.t.Helper()
	f.clockAt(at)
	f.el.probesChanged(probemanager.Change{Syscall: "restart_syscall", Phase: phase, Attached: attached})
}

// TestTUIDoesNotHoldAStoppedSleepWithoutRestartSyscall is the task's case: a
// TUI session that started without restart_syscall. The stopped sleep's row
// used to wait for the thread's next record; it is emitted by its own exit.
// The loop was not told that its trace set is final - it is not.
func TestTUIDoesNotHoldAStoppedSleepWithoutRestartSyscall(t *testing.T) {
	f := newTUIRestartFixture(t, allButRestartSyscall)
	if f.el.restarts.restartSyscallUntraced {
		t.Fatal("a loop that listens to probe changes was told that its trace set is final")
	}
	f.requireStoppedSleepNotHeld(restartBase)
}

// TestTUIFoldsAStoppedSleepWithRestartSyscallAttached is the control: a TUI
// session that traces restart_syscall folds a stopped sleep into one row, as
// before.
func TestTUIFoldsAStoppedSleepWithRestartSyscallAttached(t *testing.T) {
	f := newTUIRestartFixture(t, onlyRestartSyscall)
	requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "restart_syscall is attached")
	f.requireNothingHeld()
	if f.el.numSyscalls != 1 {
		t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
	}
}

// TestTUIStopsHoldingStoppedSleepsWhenRestartSyscallIsDetached: the probes of
// restart_syscall are switched off in the modal. A sleep stopped before that
// is held - it was interrupted before the detach's stamp - and the woken loop
// releases it, as it does at any probe change. A sleep stopped afterwards is
// the one that used to wait: it is not held any more.
func TestTUIStopsHoldingStoppedSleepsWhenRestartSyscallIsDetached(t *testing.T) {
	f := newTUIRestartFixture(t, onlyRestartSyscall)
	f.interrupt(restartBase, restartTid)
	f.changeRestartSyscallProbes(restartBase+1000, probemanager.Changed, false)

	rows := f.noticeProbeChange()
	if len(rows) != 1 || rows[0].ret != -516 || rows[0].enterTime != restartBase || rows[0].duration != 500 {
		t.Fatalf("woken loop released %+v, want the sleep stopped before the detach, unchanged", rows)
	}
	f.requireNothingHeld()
	f.requireStoppedSleepNotHeld(restartBase + 10_000)
}

// TestTUISleepStoppedBeforeTheDetachIsStillTwoRowsForALaggingLoop: a loop
// that lags reads, after the detach, a sleep that was stopped and resumed
// while restart_syscall was attached. The state says "detached" and the row
// is not held - which the detach's stamp, younger than the row, decides
// anyway. Nothing is lost: the restart_syscall recorded before the detach is
// a row of its own.
func TestTUISleepStoppedBeforeTheDetachIsStillTwoRowsForALaggingLoop(t *testing.T) {
	f := newTUIRestartFixture(t, onlyRestartSyscall)
	f.changeRestartSyscallProbes(restartBase+10_000, probemanager.Changed, false)

	rows := stoppedSleepThenRestart(f, restartBase, restartBase+1500, restartBase+1500, restartBase+3000, 0)
	requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+3000, 0)
	f.requireNothingHeld()
	if f.el.numSyscalls != 2 {
		t.Fatalf("numSyscalls = %d, want 2: the stopped sleep and its restart_syscall", f.el.numSyscalls)
	}
}

// TestTUIRestartSyscallAttachedWhileASleepIsStoppedIsNotFolded: the probes of
// restart_syscall come on while a sleep is stopped, and the restart_syscall
// that resumes it is recorded. With the probes off when the sleep was stopped
// its row was emitted at once; with them on, then off and on again, it was
// held and the changes refuse it. Either way the sleep keeps its -516 row and
// the restart_syscall is a row of its own - never one row made of the two.
func TestTUIRestartSyscallAttachedWhileASleepIsStoppedIsNotFolded(t *testing.T) {
	t.Run("stopped with the probes off", func(t *testing.T) {
		f := newTUIRestartFixture(t, allButRestartSyscall)
		f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
		rows := []restartRow{f.feedOne(f.sleepExit(restartBase+500, restartTid, -516), "clock_nanosleep -516 exit")}
		f.changeRestartSyscallProbes(restartBase+1000, probemanager.ChangeBegins, false)
		f.changeRestartSyscallProbes(restartBase+1100, probemanager.ChangeEnds, true)

		rows = append(rows, f.foldSleepFrom(restartBase)...)
		requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+3000, 0)
		f.requireNothingHeld()
	})
	t.Run("stopped with the probes on, then off and on again", func(t *testing.T) {
		f := newTUIRestartFixture(t, onlyRestartSyscall)
		f.interrupt(restartBase, restartTid)
		f.changeRestartSyscallProbes(restartBase+1000, probemanager.Changed, false)
		f.changeRestartSyscallProbes(restartBase+1100, probemanager.ChangeBegins, false)
		f.changeRestartSyscallProbes(restartBase+1200, probemanager.ChangeEnds, true)

		requireSleepAndRestartRows(t, f.foldSleepFrom(restartBase), restartBase, restartBase+1500, restartBase+3000, 0)
		f.requireNothingHeld()
	})
}

// TestTUIHoldsStoppedSleepsAgainOnceRestartSyscallIsAttached: from the first
// report of restart_syscall's attach the state is "may be attached" and the
// new rule is silent. While the attach is in flight the count of task x13
// decides, as for every row: the sleep stopped then is not held. A sleep
// stopped after the attach is over is held and folds.
func TestTUIHoldsStoppedSleepsAgainOnceRestartSyscallIsAttached(t *testing.T) {
	f := newTUIRestartFixture(t, allButRestartSyscall)
	f.changeRestartSyscallProbes(restartBase-100, probemanager.ChangeBegins, false)
	if !f.el.restarts.restartBlockHeld() {
		t.Fatal("restart_syscall still counts as detached while its attach is in flight")
	}
	f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
	row := f.feedOne(f.sleepExit(restartBase+500, restartTid, -516), "sleep stopped while the attach is in flight")
	if row.ret != -516 || row.duration != 500 {
		t.Fatalf("row = %+v, want the unchanged -516 sleep: nothing is held while an attach is in flight", row)
	}
	f.requireNothingHeld()

	f.changeRestartSyscallProbes(restartBase+1000, probemanager.ChangeEnds, true)
	later := restartBase + 10_000
	requireFoldedSleep(t, f.foldSleep(later), later, "restart_syscall's probes were attached before the interruption")
	f.requireNothingHeld()
}

// TestTUIAttachOfRestartSyscallThatFailsLeavesItDetached: an attach that
// fails leaves nothing attached, and its second report says so. Between its
// two reports the probes may be attached; afterwards a stopped sleep is not
// held, as before the attempt.
func TestTUIAttachOfRestartSyscallThatFailsLeavesItDetached(t *testing.T) {
	f := newTUIRestartFixture(t, allButRestartSyscall)
	f.changeRestartSyscallProbes(restartBase-200, probemanager.ChangeBegins, false)
	if !f.el.restarts.restartBlockHeld() {
		t.Fatal("restart_syscall still counts as detached while its attach is in flight")
	}
	f.changeRestartSyscallProbes(restartBase-100, probemanager.ChangeEnds, false)
	if got := f.el.restarts.probes.inFlight.Load(); got != 0 {
		t.Fatalf("%d attaches in flight after the failed attach ended, want 0", got)
	}
	f.requireStoppedSleepNotHeld(restartBase)
}

// otherSyscallsChanges are the reports of a detach, an attach that succeeds
// and an attach that fails, each of a syscall that is not restart_syscall.
func otherSyscallsChanges() []probemanager.Change {
	return []probemanager.Change{
		{Syscall: "clock_nanosleep", Phase: probemanager.Changed},
		{Syscall: "clock_nanosleep", Phase: probemanager.ChangeBegins},
		{Syscall: "clock_nanosleep", Phase: probemanager.ChangeEnds, Attached: true},
		{Syscall: "read", Phase: probemanager.ChangeBegins},
		{Syscall: "read", Phase: probemanager.ChangeEnds},
		{Phase: probemanager.Changed},
	}
}

// TestTUIChangesOfOtherSyscallsLeaveRestartSyscallsStateAlone: the state is
// that of restart_syscall's probes and moves only with reports that name it.
// A detach of the sleep's own probes, or a failed attach of read, does not
// make restart_syscall detached - a sleep stopped afterwards folds - and an
// attach of another syscall does not make it attached.
func TestTUIChangesOfOtherSyscallsLeaveRestartSyscallsStateAlone(t *testing.T) {
	report := func(f *restartFixture) {
		for i, change := range otherSyscallsChanges() {
			f.clockAt(restartBase - 900 + uint64(i))
			f.el.probesChanged(change)
		}
	}
	f := newTUIRestartFixture(t, onlyRestartSyscall)
	report(f)
	requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "only other syscalls' probes changed, before the interruption")
	f.requireNothingHeld()

	f = newTUIRestartFixture(t, allButRestartSyscall)
	report(f)
	f.requireStoppedSleepNotHeld(restartBase)
}

// TestTUIDetachedRestartSyscallLeavesTheReexecutionFoldOn: a call interrupted
// with -512/-513/-514 is continued by its own syscall, so its row is held
// and folded with restart_syscall's probes off.
func TestTUIDetachedRestartSyscallLeavesTheReexecutionFoldOn(t *testing.T) {
	f := newTUIRestartFixture(t, allButRestartSyscall)
	requireFolded(t, f.foldRead(restartBase), restartBase, "restart_syscall does not continue a re-executed read")
	f.requireNothingHeld()
}

// TestInstallDoesNotOverwriteAReportThatRacedIt: the hook is set before the
// loop asks the manager about restart_syscall, and a change that begins in
// between reports to it. Here an attach of restart_syscall makes its first
// report from inside the install: the manager still calls the probe inactive
// - an attach is committed after its last report - and the answer must not
// replace what the report said, or the sleeps stopped after the attach would
// never fold.
func TestInstallDoesNotOverwriteAReportThatRacedIt(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	f.clockAt(restartBase - 1000)
	var hook func(probemanager.Change)
	f.el.watchProbeChanges(func(registered func(probemanager.Change)) {
		hook = registered
		hook(probemanager.Change{Syscall: "restart_syscall", Phase: probemanager.ChangeBegins})
	}, allButRestartSyscall)
	if !f.el.restarts.restartBlockHeld() {
		t.Fatal("the install called restart_syscall detached over the report of its attach")
	}
	f.clockAt(restartBase - 500)
	hook(probemanager.Change{Syscall: "restart_syscall", Phase: probemanager.ChangeEnds, Attached: true})
	requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "restart_syscall was attached while the hook was installed")
}

// reportReading is what one reading inside a report finds on the watch.
type reportReading struct {
	off      bool   // restart_syscall counts as detached
	stamp    uint64 // the change stamp standing then
	inFlight int64
}

// readingsDuring makes the report change through f's hook and returns what
// the watch showed at the three moments test code runs inside a report: the
// first clock reading, the clear of the kernel's pending restarts, and the
// second clock reading. The clock moves by 100 at every reading, from at.
func (f *restartFixture) readingsDuring(at uint64, change probemanager.Change) []reportReading {
	watch := &f.el.restarts.probes
	var seen []reportReading
	look := func() {
		seen = append(seen, reportReading{off: watch.restartSyscallOff(), stamp: watch.changedAt.Load(),
			inFlight: watch.inFlight.Load()})
	}
	f.el.dropStampClock = func() uint64 {
		look()
		at += 100
		return at
	}
	f.el.restartPending = &scriptedPendingClearer{clock: func() uint64 {
		look()
		return 0
	}}
	f.el.probesChanged(change)
	return seen
}

// TestRestartSyscallIsCalledDetachedBetweenTheTwoStampsOfItsReport pins the
// order inside the report that leaves restart_syscall detached - its detach,
// or its attach that failed - as far as one goroutine can see it ("Output
// order" in eventloop_restart.go). At the first clock reading the state is
// not "detached" yet: stored ahead of the first stamp, a loop that lags would
// read it for a call interrupted and resumed while the probes were on. At
// the second reading it is: stored after the second stamp, a row held in
// between would have nothing to release it.
func TestRestartSyscallIsCalledDetachedBetweenTheTwoStampsOfItsReport(t *testing.T) {
	const installed, at = restartBase - 1000, restartBase
	reports := map[string]probemanager.Change{
		"a detach":        {Syscall: "restart_syscall", Phase: probemanager.Changed},
		"a failed attach": {Syscall: "restart_syscall", Phase: probemanager.ChangeEnds},
	}
	for name, change := range reports {
		t.Run(name, func(t *testing.T) {
			f := newTUIRestartFixture(t, onlyRestartSyscall)
			inFlight := int64(0)
			if change.Phase == probemanager.ChangeEnds {
				f.el.restarts.probes.begin()
				inFlight = 1
			}
			want := []reportReading{
				{off: false, stamp: installed, inFlight: inFlight},
				{off: true, stamp: at + 100, inFlight: inFlight},
				{off: true, stamp: at + 100, inFlight: inFlight},
			}
			if seen := f.readingsDuring(at, change); !slices.Equal(seen, want) {
				t.Fatalf("the watch during the report = %+v, want %+v", seen, want)
			}
			if got := f.el.restarts.probes.changedAt.Load(); got != at+200 {
				t.Fatalf("change stamp = %d after the report, want the second reading %d", got, at+200)
			}
		})
	}
}

// TestRestartSyscallMayBeAttachedBeforeItsAttachReadsTheClock: the first
// report of restart_syscall's attach takes the state off "detached" before it
// does anything else, so a loop that still reads "detached" reads it before
// the attach has touched a tracepoint.
func TestRestartSyscallMayBeAttachedBeforeItsAttachReadsTheClock(t *testing.T) {
	f := newTUIRestartFixture(t, allButRestartSyscall)
	if !f.el.restarts.probes.restartSyscallOff() {
		t.Fatal("restart_syscall does not count as detached in a TUI run that started without it")
	}
	seen := f.readingsDuring(restartBase, probemanager.Change{Syscall: "restart_syscall", Phase: probemanager.ChangeBegins})
	for i, reading := range seen {
		if reading.off || reading.inFlight != 1 {
			t.Fatalf("reading %d of the attach's first report = %+v, want restart_syscall not detached and the attach counted",
				i, reading)
		}
	}
	if len(seen) != 3 {
		t.Fatalf("%d readings in the report, want 3: two clock readings around one clear", len(seen))
	}
}
