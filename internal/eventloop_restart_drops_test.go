package internal

import (
	"errors"
	"testing"

	"ior/internal/globalfilter"
)

// Tests for the drop check of the restart_syscall fold (task p03,
// eventloop_restart.go): with a drop counter, a -516 row is folded only when
// no record can have been lost since its interrupted exit; without one the
// fold is what it was (task fs2), and the stranger it can then fold is pinned
// as the documented residual. The watch itself (restartDropWatch) and the same
// check on the re-execution fold are tested in
// eventloop_restart_reexec_test.go.

// newDropCountedFixture is newRestartFixture with a scripted drop counter and
// boot clock (reexecDrops) but without BPF's re-execution proof: a run whose
// signal_deliver or sched_process_exit probe did not attach. The -516 fold
// needs the counter alone.
func newDropCountedFixture(t *testing.T, filter globalfilter.Filter) *restartFixture {
	t.Helper()
	f := newRestartFixture(t, filter)
	f.drops = &reexecDrops{}
	f.el.dropSrc = ringbufDropSourceFunc(func() (uint64, error) { return f.drops.total, f.drops.err })
	f.drops.monitor = newRingbufDropMonitor(f.el.dropSrc)
	f.el.dropStampClock = func() uint64 { return f.drops.now }
	return f
}

// dropCountedFixtures are the two kinds of run that have a drop counter: with
// and without the re-execution proof. The -516 fold's drop check must not
// depend on which.
func dropCountedFixtures() map[string]func(*testing.T, globalfilter.Filter) *restartFixture {
	return map[string]func(*testing.T, globalfilter.Filter) *restartFixture{
		"re-execution proof off": newDropCountedFixture,
		"re-execution proof on":  newReexecFixture,
	}
}

// foldSleep drives one stopped sleep at base through its restart_syscall with
// a live clock - each record is processed 50ns after it was stamped - and
// returns what the restart_syscall enter and exit emitted together: the folded
// row, or, when the fold is refused, the -516 row and the restart_syscall row.
func (f *restartFixture) foldSleep(base uint64) []restartRow {
	f.t.Helper()
	f.interrupt(base, restartTid)
	return f.foldSleepFrom(base)
}

// foldSleepFrom is foldSleep for a sleep already interrupted at base.
func (f *restartFixture) foldSleepFrom(base uint64) []restartRow {
	f.t.Helper()
	f.clockAt(base + 1550)
	rows := f.feed(f.restartEnter(base+1500, restartTid))
	f.clockAt(base + 3050)
	return append(rows, f.feed(f.restartExit(base+3000, restartTid, 0))...)
}

// requireFoldedSleep fails unless rows is the single folded row of the sleep
// interrupted at base (foldSleep).
func requireFoldedSleep(t *testing.T, rows []restartRow, base uint64, why string) {
	t.Helper()
	want := restartRow{name: "clock_nanosleep", tid: restartTid, ret: 0, enterTime: base, duration: 3000,
		sleepNs: restartSleepNs}
	if len(rows) != 1 || rows[0].name != want.name || rows[0].ret != want.ret ||
		rows[0].enterTime != want.enterTime || rows[0].duration != want.duration || rows[0].sleepNs != want.sleepNs {
		t.Fatalf("rows = %+v, want one folded sleep %+v: %s", rows, want, why)
	}
}

// requireSleepAndRestartRows fails unless rows are the sleep interrupted at
// base, unchanged, followed by restart_syscall as a row of its own: its enter
// at enterAt paired with an exit at exitAt returning ret.
func requireSleepAndRestartRows(t *testing.T, rows []restartRow, base, enterAt, exitAt uint64, ret int64) {
	t.Helper()
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the -516 row and the restart_syscall row", rows)
	}
	if rows[0].name != "clock_nanosleep" || rows[0].ret != -516 || rows[0].enterTime != base || rows[0].duration != 500 {
		t.Fatalf("first row = %+v, want the unchanged -516 sleep from %d", rows[0], base)
	}
	want := restartRow{name: "restart_syscall", tid: restartTid, ret: ret, enterTime: enterAt,
		duration: exitAt - enterAt, gap: enterAt - base - 500}
	if rows[1] != want {
		t.Fatalf("second row = %+v, want restart_syscall as its own row %+v", rows[1], want)
	}
}

// TestLostRestartSyscallRecordsNeverFoldAStranger is the defect of task p03:
// the ways a full ring buffer can cut a -516 row's restart_syscall out of the
// stream while a LATER stopped call's restart_syscall arrives in its place.
// The stream that is left is well formed - a -516 exit, then restart_syscall
// on the same thread - and only the drop counter tells that the pieces belong
// to two calls.
func TestLostRestartSyscallRecordsNeverFoldAStranger(t *testing.T) {
	for name, newFixture := range dropCountedFixtures() {
		// The restart_syscall enter arrived and was taken. Its exit, the
		// thread's next sleep (enter and -516 exit) and that sleep's
		// restart_syscall enter were refused in one burst; the later
		// restart_syscall's exit is the tid's next record. Folded, the row
		// would carry the later call's return value and end time.
		t.Run(name+"/exit and the later call up to its exit lost", func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			f.clockAt(restartBase + 1550)
			f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
			f.loseRecords(4)
			f.clockAt(restartBase + 9050)
			rows := f.feed(f.restartExit(restartBase+9000, restartTid, -4))
			requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+9000, -4)
			f.requireNothingHeld()
			if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
				t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
			}
		})
		// The whole restart_syscall and the later sleep (enter and -516 exit)
		// were refused; the later sleep's restart_syscall arrives complete. The
		// row is released at that enter, before anything is taken for a fold.
		t.Run(name+"/restart_syscall and the later interruption lost", func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			f.loseRecords(4)
			f.clockAt(restartBase + 9050)
			rows := f.feed(f.restartEnter(restartBase+9000, restartTid))
			if len(rows) != 1 {
				t.Fatalf("restart_syscall enter after a loss emitted %+v, want the released -516 row", rows)
			}
			f.requireNothingHeld()
			f.clockAt(restartBase + 9550)
			rows = append(rows, f.feed(f.restartExit(restartBase+9500, restartTid, 0))...)
			requireSleepAndRestartRows(t, rows, restartBase, restartBase+9000, restartBase+9500, 0)
		})
	}
}

// TestRestartSyscallFoldWithoutADropCounterIsUnchecked pins the residual: a
// run without a drop counter (an older IOR_BPF_OBJECT, a counter map that
// could not be opened) still folds restart_syscall, as it did before the
// counter existed, and so still folds the stranger of the test above. ior
// warns at startup that drops are not reported in such a run.
func TestRestartSyscallFoldWithoutADropCounterIsUnchecked(t *testing.T) {
	f := newRestartFixture(t, globalfilter.Filter{})
	if f.el.dropSrc != nil {
		t.Fatal("the plain restart fixture has a drop counter")
	}
	f.interrupt(restartBase, restartTid)
	f.feedNone(f.restartEnter(restartBase+1500, restartTid), "restart_syscall enter")
	// The same stream as the lost-records test; nothing can count the loss.
	row := f.feedOne(f.restartExit(restartBase+9000, restartTid, -4), "a later call's restart_syscall exit")
	if row.name != "clock_nanosleep" || row.ret != -4 || row.duration != 9000 {
		t.Fatalf("row = %+v, want the fold a run without a drop counter makes", row)
	}
	if f.el.numSyscalls != 1 {
		t.Fatalf("numSyscalls = %d, want 1", f.el.numSyscalls)
	}
}

// TestRestartSyscallFoldsWhenNoRecordWasLost is the negative control of the
// drop check: with a counter that proves nothing was lost since the
// interrupted exit, the stopped sleep is one row. That holds when the counter
// never moved, when the monitor saw a loss before the call was interrupted
// (however recently), and when it saw one while the call was still blocked -
// the question is asked from the interrupted EXIT's time.
func TestRestartSyscallFoldsWhenNoRecordWasLost(t *testing.T) {
	for name, newFixture := range dropCountedFixtures() {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "the counter never moved")

			const second, third = restartBase + 10000, restartBase + 20000
			f.loseRecords(5)
			f.monitorPoll(second - 100)
			requireFoldedSleep(t, f.foldSleep(second), second, "the monitor saw the loss before the interruption")

			f.feedNone(f.sleepEnter(third, restartTid), "clock_nanosleep enter")
			f.loseRecords(1)
			f.monitorPoll(third + 200)
			f.feedNone(f.sleepExit(third+500, restartTid, -516), "clock_nanosleep -516 exit")
			f.clockAt(third + 1550)
			f.feedNone(f.restartEnter(third+1500, restartTid), "restart_syscall enter")
			f.clockAt(third + 3050)
			rows := f.feed(f.restartExit(third+3000, restartTid, 0))
			requireFoldedSleep(t, rows, third, "the loss was seen before the interrupted exit")
			if f.el.numSyscalls != 3 {
				t.Fatalf("numSyscalls = %d, want 3 (three folded sleeps)", f.el.numSyscalls)
			}
		})
	}
}

// TestDropsAfterTheInterruptionRefuseTheRestartSyscallFold: a loss whose first
// observation comes at or after the interrupted exit refuses the fold, whoever
// notices it - the monitor while the row is held, the loop's own read at the
// restart_syscall enter, or its read at the exit, where the enter taken for
// the fold is parked again. Each time the call is two rows and nothing is
// lost, and the sleep after it folds again: the loss then lies before its
// interruption.
func TestDropsAfterTheInterruptionRefuseTheRestartSyscallFold(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.loseRecords(1)
	f.monitorPoll(restartBase + 600)
	f.clockAt(restartBase + 1550)
	rows := f.feed(f.restartEnter(restartBase+1500, restartTid))
	if len(rows) != 1 {
		t.Fatalf("restart_syscall enter after the monitor saw a loss emitted %+v, want the released -516 row", rows)
	}
	rows = append(rows, f.feed(f.restartExit(restartBase+3000, restartTid, 0))...)
	requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+3000, 0)

	const second, third, fourth = restartBase + 10000, restartBase + 20000, restartBase + 30000
	requireFoldedSleep(t, f.foldSleep(second), second, "the loss lies before this call's interruption")

	f.interrupt(third, restartTid)
	f.loseRecords(1)
	requireSleepAndRestartRows(t, f.foldSleepFrom(third), third, third+1500, third+3000, 0)

	f.interrupt(fourth, restartTid)
	f.clockAt(fourth + 1550)
	f.feedNone(f.restartEnter(fourth+1500, restartTid), "restart_syscall enter")
	if held, ok := f.el.restarts.lookup(restartTid); !ok || held.continuation == nil {
		t.Fatal("the restart_syscall enter was not taken for the fold")
	}
	f.loseRecords(1)
	f.clockAt(fourth + 3050)
	rows = f.feed(f.restartExit(fourth+3000, restartTid, 0))
	requireSleepAndRestartRows(t, rows, fourth, fourth+1500, fourth+3000, 0)
	f.requireNothingHeld()
	if _, pending := f.el.pairs.pending(restartTid); pending {
		t.Fatal("the restart_syscall enter is still parked after its exit")
	}
	if f.el.numSyscalls != 7 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 7 (three refused folds of two rows each, one fold) and 0",
			f.el.numSyscalls, f.el.numTracepointMismatches)
	}
}

// TestUnreadableDropCounterRefusesTheRestartSyscallFold: a counter that exists
// but cannot be read vouches for nothing, for this fold as for the
// re-execution fold. That is not the run without a counter, which folds
// unchecked.
func TestUnreadableDropCounterRefusesTheRestartSyscallFold(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	f.interrupt(restartBase, restartTid)
	f.drops.err = errors.New("map gone")
	requireSleepAndRestartRows(t, f.foldSleepFrom(restartBase), restartBase, restartBase+1500, restartBase+3000, 0)
	f.requireNothingHeld()
}

// TestRepeatedStopsFoldEachFromItsOwnInterruption: a sleep stopped
// twice is a chain - -516, restart_syscall returning -516, restart_syscall
// returning 0 - and each hop asks about the time since ITS interruption, the
// exit the row carries after the hop before.
func TestRepeatedStopsFoldEachFromItsOwnInterruption(t *testing.T) {
	// The first hop folds. A loss first seen after the second interruption
	// refuses the second hop only: the row keeps what the first hop proved (it
	// ran until the second interruption), and the second restart_syscall is a
	// row of its own.
	t.Run("loss after the second interruption", func(t *testing.T) {
		f := newDropCountedFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.clockAt(restartBase + 1050)
		f.feedNone(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
		f.clockAt(restartBase + 1550)
		f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
		f.loseRecords(1)
		f.monitorPoll(restartBase + 1700)
		f.clockAt(restartBase + 2050)
		sleep := f.feedOne(f.restartEnter(restartBase+2000, restartTid), "second restart_syscall enter")
		if sleep.name != "clock_nanosleep" || sleep.ret != -516 || sleep.enterTime != restartBase || sleep.duration != 1500 {
			t.Fatalf("released row = %+v, want the sleep from its enter to the second interruption", sleep)
		}
		restart := f.feedOne(f.restartExit(restartBase+4000, restartTid, 0), "second restart_syscall exit")
		want := restartRow{name: "restart_syscall", tid: restartTid, enterTime: restartBase + 2000, duration: 2000, gap: 500}
		if restart != want || f.el.numSyscalls != 2 {
			t.Fatalf("row = %+v numSyscalls=%d, want %+v and 2", restart, f.el.numSyscalls, want)
		}
	})
	// The first hop is refused over a loss seen after the first interruption.
	// Its restart_syscall, now a row of its own, is stopped in turn (-516) and
	// held; the loss lies before THAT interruption, so the second
	// restart_syscall folds into the first.
	t.Run("loss between the two interruptions", func(t *testing.T) {
		f := newDropCountedFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.loseRecords(1)
		f.monitorPoll(restartBase + 600)
		f.clockAt(restartBase + 1050)
		sleep := f.feedOne(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
		if sleep.name != "clock_nanosleep" || sleep.ret != -516 || sleep.duration != 500 {
			t.Fatalf("released row = %+v, want the unchanged -516 sleep", sleep)
		}
		f.clockAt(restartBase + 1550)
		f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
		f.clockAt(restartBase + 2050)
		f.feedNone(f.restartEnter(restartBase+2000, restartTid), "second restart_syscall enter")
		f.clockAt(restartBase + 4050)
		restart := f.feedOne(f.restartExit(restartBase+4000, restartTid, 0), "second restart_syscall exit")
		want := restartRow{name: "restart_syscall", tid: restartTid, enterTime: restartBase + 1000, duration: 3000, gap: 500}
		if restart != want || f.el.numSyscalls != 2 {
			t.Fatalf("row = %+v numSyscalls=%d, want %+v and 2", restart, f.el.numSyscalls, want)
		}
		f.requireNothingHeld()
	})
}

// TestSleepInterruptedInAHandlerFoldsFromItsOwnInterruption is the
// interplay with the re-execution fold's handler phase: a read interrupted
// with -512 waits for its SA_RESTART handler, whose sleep is stopped in turn
// (-516) and takes the row's place. The inner sleep's fold asks about the time
// since the inner interruption, so a loss seen while the outer row was held
// does not refuse it; one seen after the inner interruption does.
func TestSleepInterruptedInAHandlerFoldsFromItsOwnInterruption(t *testing.T) {
	for name, lossAt := range map[string]uint64{"loss before the inner interruption": 650, "loss after it": 800} {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			f.interruptRead(restartBase, restartTid, restartSys)
			f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
			f.feedNone(f.sleepEnter(restartBase+600, restartTid), "the handler's sleep enter")
			f.loseRecords(1)
			f.monitorPoll(restartBase + lossAt)
			outer := f.feedOne(f.sleepExit(restartBase+700, restartTid, -516), "the handler's sleep, interrupted")
			requireInterruptedRow(t, outer, restartSys)
			f.clockAt(restartBase + 950)
			rows := f.feed(f.restartEnter(restartBase+900, restartTid))
			f.clockAt(restartBase + 1250)
			rows = append(rows, f.feed(f.restartExit(restartBase+1200, restartTid, 0))...)
			if lossAt < 700 {
				if len(rows) != 1 || rows[0].name != "clock_nanosleep" || rows[0].ret != 0 || rows[0].duration != 600 {
					t.Fatalf("rows = %+v, want the handler's sleep folded with its restart_syscall", rows)
				}
				return
			}
			if len(rows) != 2 || rows[0].name != "clock_nanosleep" || rows[0].ret != -516 ||
				rows[1].name != "restart_syscall" || rows[1].ret != 0 || rows[1].enterTime != restartBase+900 {
				t.Fatalf("rows = %+v, want the handler's -516 sleep and restart_syscall as two rows", rows)
			}
		})
	}
}
