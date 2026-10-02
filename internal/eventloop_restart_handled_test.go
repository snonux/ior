package internal

import (
	"slices"
	"testing"

	"ior/internal/globalfilter"
)

// Tests for task t13 (eventloop_restart.go, "(1) restart_syscall"): a -516 row
// is folded only with a restart_syscall that BPF's RESUME record announced,
// never with one that merely is the tid's next record. The streams here are
// the ones the stream-only fold of task fs2 got wrong - a sleep that a HANDLED
// signal ended with EINTR, followed by the restart_syscall of a later call
// that left no record of its own - and the runs in which BPF's proof is not
// available. The streams that must still fold are in eventloop_restart_test.go.

// laterRestartSyscall feeds the restart_syscall of a later call B of the
// thread, from base+8000 to base+9000 and returning 0, with no RESUME record:
// B's own -516 exit was never emitted (its syscall is not traced, sampled out
// or aggregate-only), so BPF had nothing pending to announce. It returns the
// rows the two records emitted.
func (f *restartFixture) laterRestartSyscall(base uint64) []restartRow {
	f.t.Helper()
	rows := f.feed(f.restartEnter(base+8000, restartTid))
	return append(rows, f.feed(f.restartExit(base+9000, restartTid, 0))...)
}

// requireSleepThenLaterRestart fails unless rows are the sleep interrupted at
// base exactly as it was at its -516 exit, and the later call's
// restart_syscall (laterRestartSyscall) as a row of its own.
func requireSleepThenLaterRestart(t *testing.T, f *restartFixture, rows []restartRow, base uint64) {
	t.Helper()
	want := []restartRow{
		{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: base, duration: 500, sleepNs: restartSleepNs},
		{name: "restart_syscall", tid: restartTid, ret: 0, enterTime: base + 8000, duration: 1000, gap: 7500},
	}
	if !slices.Equal(rows, want) {
		t.Fatalf("rows = %+v, want the sleep with its own short duration and the later restart_syscall apart %+v",
			rows, want)
	}
	f.requireNothingHeld()
	if f.el.numSyscalls != 2 || f.el.numTracepointMismatches != 0 {
		t.Fatalf("numSyscalls=%d mismatches=%d, want 2 and 0", f.el.numSyscalls, f.el.numTracepointMismatches)
	}
}

// TestHandledSignalReleasesTheRestartBlockRow: a user handler delivered to a
// -516 call gives the program EINTR whatever its SA_RESTART flag says
// (handle_signal), so the HANDLER record releases the held row at once and
// unchanged. Nothing will resume the call: the row must not wait for the
// thread's next record, which may be the restart_syscall of another call.
func TestHandledSignalReleasesTheRestartBlockRow(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		for _, saRestart := range []bool{false, true} {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			row := f.feedOne(f.handlerRecord(restartBase+510, restartTid, saRestart), "HANDLER record")
			want := restartRow{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase,
				duration: 500, sleepNs: restartSleepNs}
			if row != want {
				t.Fatalf("SA_RESTART %t: released row = %+v, want the unchanged -516 sleep %+v", saRestart, row, want)
			}
			f.requireNothingHeld()
		}
	})
}

// TestRestartSyscallOfALaterSilentCallIsNotFolded is the defect of task t13.
// Sleep A is cut by a handled signal and returns EINTR after 500ns. The
// handler's records are silent (rt_sigreturn is not traced, or the handler
// left by siglongjmp), and so is a later call B of the thread that is stopped
// and continued: B's restart_syscall is the first record of the thread after
// A's -516 exit. The stream-only fold took it for A's continuation and
// reported one sleep of 9000ns returning 0, with no record lost and nothing
// sampled.
//
// With the HANDLER record the row is released before B's restart_syscall
// arrives. Without it - lost to a full ring buffer, the task's BPF entry
// evicted by a colliding tid before the signal, or a BPF object that predates
// the record - the row waits, but the restart_syscall carries no RESUME
// announcement and releases it instead of resuming it. Either way: two rows.
func TestRestartSyscallOfALaterSilentCallIsNotFolded(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		t.Run("HANDLER record arrives", func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			rows := f.feed(f.handlerRecord(restartBase+510, restartTid, false))
			rows = append(rows, f.laterRestartSyscall(restartBase)...)
			requireSleepThenLaterRestart(t, f, rows, restartBase)
		})
		t.Run("HANDLER record missing", func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			f.interrupt(restartBase, restartTid)
			if _, held := f.el.restarts.lookup(restartTid); !held {
				t.Fatal("the -516 row is not held; the test would prove nothing about the fold")
			}
			requireSleepThenLaterRestart(t, f, f.laterRestartSyscall(restartBase), restartBase)
		})
	})
}

// TestRestartSyscallHopWithoutResumeIsNotFolded: every hop of a call stopped
// several times needs its own announcement. The first restart_syscall is
// announced and folds; it is interrupted in turn (-516), a handled signal ends
// it there, and the restart_syscall that follows is a later silent call's. The
// row keeps what the first hop proved and the stranger stays a row of its own.
func TestRestartSyscallHopWithoutResumeIsNotFolded(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		f.interrupt(restartBase, restartTid)
		f.resume(restartBase+1000, restartTid)
		f.feedNone(f.restartEnter(restartBase+1000, restartTid), "first restart_syscall enter")
		f.feedNone(f.restartExit(restartBase+1500, restartTid, -516), "first restart_syscall -516 exit")
		rows := f.laterRestartSyscall(restartBase)
		want := []restartRow{
			{name: "clock_nanosleep", tid: restartTid, ret: -516, enterTime: restartBase, duration: 1500,
				sleepNs: restartSleepNs},
			{name: "restart_syscall", tid: restartTid, ret: 0, enterTime: restartBase + 8000, duration: 1000, gap: 6500},
		}
		if !slices.Equal(rows, want) {
			t.Fatalf("rows = %+v, want the sleep folded up to its second interruption and the stranger apart %+v",
				rows, want)
		}
		f.requireNothingHeld()
	})
}

// TestSampledOutRestartSyscallIsNotFoldedWithoutTheGuard shows what the RESUME
// record does for the stream of task s13 by itself, in a run whose sampling
// guard is off (holdable's restartSyscallSampled). BPF announces sleep A's
// restart_syscall before the sampling decision and stamps the record with that
// enter's time; the enter is then sampled out, and the restart_syscall that
// arrives is a later silent call's, with a later time. The time rule releases
// the row instead of resuming it. (The guard stays in place all the same, see
// "Sampling" in eventloop_restart.go.)
func TestSampledOutRestartSyscallIsNotFoldedWithoutTheGuard(t *testing.T) {
	eachRestartFixture(t, func(t *testing.T, newFixture restartFixtureMaker) {
		f := newFixture(t, globalfilter.Filter{})
		if f.el.restarts.restartSyscallSampled {
			t.Fatal("the fixture's run samples restart_syscall; the guard would hide what is tested here")
		}
		f.interrupt(restartBase, restartTid)
		f.resume(restartBase+1500, restartTid)
		requireSleepThenLaterRestart(t, f, f.laterRestartSyscall(restartBase), restartBase)
	})
}

// TestRestartBlockRowsAreNotHeldWithoutTheProbes is the fallback: when the
// signal_deliver or the sched_process_exit probe did not attach, a RESUME
// record is no proof (a handler the probe did not see may have ended the call
// and left by siglongjmp; a recycled tid may have inherited the entry), so the
// -516 row is not held at all. It is emitted at its own exit, and
// restart_syscall is a row of its own even when it is announced - the two rows
// ior showed before it folded anything. With or without a drop counter.
func TestRestartBlockRowsAreNotHeldWithoutTheProbes(t *testing.T) {
	makers := map[string]restartFixtureMaker{"no drop counter": newRestartFixture, "drop counter": newDropCountedFixture}
	for _, probes := range []struct {
		name         string
		signal, exit bool
	}{{"no probe", false, false}, {"no signal_deliver probe", false, true}, {"no sched_process_exit probe", true, false}} {
		for kind, newFixture := range makers {
			t.Run(probes.name+"/"+kind, func(t *testing.T) {
				f := newFixture(t, globalfilter.Filter{})
				f.el.foldProvenRestarts(probes.signal, probes.exit)
				f.feedNone(f.sleepEnter(restartBase, restartTid), "clock_nanosleep enter")
				rows := f.feed(f.sleepExit(restartBase+500, restartTid, -516))
				if len(rows) != 1 {
					t.Fatalf("the -516 exit emitted %+v, want the row at once: nothing can prove its continuation", rows)
				}
				f.requireNothingHeld()
				f.resume(restartBase+8000, restartTid)
				rows = append(rows, f.laterRestartSyscall(restartBase)...)
				requireSleepThenLaterRestart(t, f, rows, restartBase)
			})
		}
	}
}
