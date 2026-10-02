package internal

import (
	"testing"

	"ior/internal/globalfilter"
)

// Tests for task 723: a program run the kernel skipped loses a record
// without a ring-buffer drop, and where the kernel counts it the drop source
// adds it to the drops (recordLossSource). Everything that asks the drop
// watch - the two folds and the exec adoption - must then take a skipped run
// for what it takes a drop for. The counter itself is tested in
// skipped_run_counter_test.go.

// scriptedPrograms are the loaded programs of a fixture whose kernel counts
// skipped runs: one count per program fd, moved by the test (skip), and the
// number of reads made, which is what a sweep costs.
type scriptedPrograms struct {
	misses map[int]uint64
	reads  int
	err    error
	// unreported makes the kernel fill less than the field, as one that
	// does not know it does.
	unreported bool
}

func newScriptedPrograms(fds ...int) *scriptedPrograms {
	programs := &scriptedPrograms{misses: map[int]uint64{}}
	for _, fd := range fds {
		programs.misses[fd] = 0
	}
	return programs
}

func (p *scriptedPrograms) fds() []int {
	fds := make([]int, 0, len(p.misses))
	for fd := range p.misses {
		fds = append(fds, fd)
	}
	return fds
}

// read is the progRecursionMisses of the scripted kernel.
func (p *scriptedPrograms) read(fd int) (uint64, bool, error) {
	p.reads++
	if p.err != nil {
		return 0, false, p.err
	}
	return p.misses[fd], !p.unreported, nil
}

// skip is the kernel skipping n runs of the program behind fd.
func (p *scriptedPrograms) skip(fd int, n uint64) {
	p.misses[fd] += n
}

// The two programs of countSkippedRuns: stand-ins for the handlers of a
// syscall's enter and exit.
const (
	skippedEnterProg = 11
	skippedExitProg  = 12
)

// countSkippedRuns turns the fixture's scripted drop counter into the source
// of a kernel that counts skipped runs: the same ring counter, plus a
// skipped-run counter over two programs, dated by the fixture's clock. The
// monitor is rebuilt on the new source, as trace setup builds it.
func (f *restartFixture) countSkippedRuns() *scriptedPrograms {
	f.t.Helper()
	programs := newScriptedPrograms(skippedEnterProg, skippedExitProg)
	skipped, err := newSkippedRunCounter(programs.fds(), programs.read, f.el.readDropStampClock)
	if err != nil {
		f.t.Fatalf("newSkippedRunCounter: %v", err)
	}
	f.el.dropSrc = &recordLossSource{ring: f.el.dropSrc, skipped: skipped}
	f.drops.monitor = newRingbufDropMonitor(f.el.dropSrc)
	return programs
}

// TestASkippedRunRefusesTheRestartSyscallFold: with no ring-buffer drop at
// all, a program run skipped while the row is held refuses the fold as a
// drop does - the record it lost may be the one that tells a stranger's
// restart_syscall from this call's. The sleeps before it and after it fold:
// before, nothing was lost, and after, the loss lies before the interruption.
func TestASkippedRunRefusesTheRestartSyscallFold(t *testing.T) {
	for name, newFixture := range dropCountedFixtures() {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, globalfilter.Filter{})
			programs := f.countSkippedRuns()
			requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "no run was skipped")

			const second, third = restartBase + 10000, restartBase + 20000
			f.interrupt(second, restartTid)
			programs.skip(skippedExitProg, 1)
			requireSleepAndRestartRows(t, f.foldSleepFrom(second), second, second+1500, second+3000, 0)
			if f.drops.total != 0 {
				t.Fatalf("ring-buffer drops = %d, want 0: the refusal must come from the skipped run alone", f.drops.total)
			}
			requireFoldedSleep(t, f.foldSleep(third), third, "the skipped run lies before this call's interruption")
		})
	}
}

// TestASkippedRunSeenByTheMonitorRefusesTheFold: the periodic monitor is the
// other observer of the same sum. A skipped run it sees while the row is held
// is stamped after the interrupted exit and refuses the fold at RESUME.
func TestASkippedRunSeenByTheMonitorRefusesTheFold(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	programs := f.countSkippedRuns()
	f.interrupt(restartBase, restartTid)
	programs.skip(skippedEnterProg, 2)
	f.monitorPoll(restartBase + 600)
	f.clockAt(restartBase + 1550)
	rows := f.feed(f.resumeRecord(restartBase+1500, restartTid))
	if len(rows) != 1 {
		t.Fatalf("RESUME after the monitor saw a skipped run emitted %+v, want the released -516 row", rows)
	}
	if total, skipped := f.el.numRingbufDrops.Load(), f.el.numSkippedRuns.Load(); total != 2 || skipped != 2 {
		t.Fatalf("published loss = %d of which skipped %d, want 2 and 2", total, skipped)
	}
}

// TestASkippedExecProgramRunLetsTheExitAdopt: the exec record of a
// non-leader's exec goes missing because the kernel skipped the
// sched_process_exec program, not because the ring buffer was full. The
// successful execve exit under the leader tid adopts the caller's enter, as
// it does for a counted drop - and does not without the skipped run, where
// "nothing was lost" proves that the thread has not exec'd.
func TestASkippedExecProgramRunLetsTheExitAdopt(t *testing.T) {
	for name, skippedRuns := range map[string]uint64{"exec program skipped": 1, "nothing skipped": 0} {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			programs := f.countSkippedRuns()
			f.interruptRead(restartBase, restartTid, restartSys)
			f.feedNone(f.handlerRecord(restartBase+510, restartTid, true), "HANDLER record")
			f.feedNone(f.execEnter(restartBase+800, restartTid), "the handler's execve enter")
			// A sweep older than the skip, which the exit must not be
			// answered from: its own time is later.
			f.monitorPoll(restartBase + 900)
			programs.skip(skippedEnterProg, skippedRuns)
			f.clockAt(restartBase + 2900)
			rows := f.feed(f.execExit(restartBase+3000, restartPid, 0))
			adopted := len(rows) == 2 && rows[1] == reexecutedExecveRow
			if adopted != (skippedRuns > 0) {
				t.Fatalf("rows = %+v: adopted = %v with %d skipped runs", rows, adopted, skippedRuns)
			}
		})
	}
}

// TestAFoldBehindTheLastSweepDoesNotSweepAgain pins what keeps the skipped-run
// evidence affordable on the event loop: a fold whose records were stamped
// before the last sweep began is answered from that sweep, without one system
// call per program, and one whose records are newer sweeps.
func TestAFoldBehindTheLastSweepDoesNotSweepAgain(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	programs := f.countSkippedRuns()
	f.interrupt(restartBase, restartTid)
	f.monitorPoll(restartBase + 5000)
	swept := programs.reads
	requireFoldedSleep(t, f.foldSleepFrom(restartBase), restartBase, "a lagging loop folds from the monitor's sweep")
	if programs.reads != swept {
		t.Fatalf("the fold made %d program reads, want none: its records predate the last sweep", programs.reads-swept)
	}

	const second = restartBase + 10000
	requireFoldedSleep(t, f.foldSleep(second), second, "nothing was skipped")
	if got, want := programs.reads-swept, 2*len(programs.misses); got != want {
		t.Fatalf("the caught-up fold made %d program reads, want %d (one sweep at RESUME, one at the exit)", got, want)
	}
}

// TestASkippedRunBeforeTheLastSweepStillRefusesALaggingFold: the sweep a
// lagging fold is answered from holds every run skipped before it began, so
// a skip among the fold's records is not lost with the system calls.
func TestASkippedRunBeforeTheLastSweepStillRefusesALaggingFold(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	programs := f.countSkippedRuns()
	f.interrupt(restartBase, restartTid)
	programs.skip(skippedExitProg, 1)
	f.monitorPoll(restartBase + 5000)
	swept := programs.reads
	requireSleepAndRestartRows(t, f.foldSleepFrom(restartBase), restartBase, restartBase+1500, restartBase+3000, 0)
	if programs.reads != swept {
		t.Fatalf("the refused fold made %d program reads, want none", programs.reads-swept)
	}
}
