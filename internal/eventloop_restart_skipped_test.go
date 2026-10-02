package internal

import (
	"errors"
	"slices"
	"testing"

	"ior/internal/globalfilter"
)

// Tests for task 723: a program run the kernel skipped may lose a record
// without a ring-buffer drop, and where the kernel counts such runs the drop
// source reports them beside the drops (recordLossSource). What asks the drop
// watch must take a skipped run for what it is - evidence that a record MAY
// be missing, counted for every task on the host: the two folds are refused
// on it as on a drop, and the exec adoption adopts on it without taking the
// pair for a proof. The counter itself is tested in
// skipped_run_counter_test.go.

// scriptedPrograms are the programs of a fixture whose kernel counts skipped
// runs: one count per program fd, moved by the test (skip), the fds that are
// attached, which is what a sweep is told to read (fds), and the number of
// reads made, which is what a sweep costs.
type scriptedPrograms struct {
	misses   map[int]uint64
	attached []int
	reads    int
	err      error
	// unreported makes the kernel fill less than the field, as one that
	// does not know it does.
	unreported bool
}

// newScriptedPrograms returns the programs behind fds, all attached.
func newScriptedPrograms(fds ...int) *scriptedPrograms {
	programs := &scriptedPrograms{misses: map[int]uint64{}, attached: fds}
	for _, fd := range fds {
		programs.misses[fd] = 0
	}
	return programs
}

// fds is the libbpfAttachedProgramFDs of the scripted kernel.
func (p *scriptedPrograms) fds() []int {
	return slices.Clone(p.attached)
}

// detach is the probe of the program behind fd being switched off.
func (p *scriptedPrograms) detach(fd int) {
	p.attached = slices.DeleteFunc(p.attached, func(attached int) bool { return attached == fd })
}

// read is the progMissesReader of the scripted kernel.
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
// skipped-run counter over two attached programs, dated by the fixture's
// clock. The monitor is rebuilt on the new source, as trace setup builds it.
func (f *restartFixture) countSkippedRuns() *scriptedPrograms {
	f.t.Helper()
	programs := newScriptedPrograms(skippedEnterProg, skippedExitProg)
	skipped, err := newSkippedRunCounter(programs.fds, programs.read, f.el.readDropStampClock)
	if err != nil {
		f.t.Fatalf("newSkippedRunCounter: %v", err)
	}
	f.el.dropSrc = &recordLossSource{ring: f.el.dropSrc, skipped: skipped}
	f.drops.monitor = newRingbufDropMonitor(f.el.dropSrc)
	return programs
}

// TestASkippedRunRefusesTheRestartSyscallFold: with no ring-buffer drop at
// all, a program run skipped while the row is held refuses the fold as a
// drop does - the record it may have lost may be the one that tells a
// stranger's restart_syscall from this call's. The sleeps before it and
// after it fold: before, nothing was lost, and after, the loss lies before
// the interruption.
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
// other observer of the same count. A skipped run it sees while the row is held
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
	if drops, skipped := f.el.numRingbufDrops.Load(), f.el.numSkippedRuns.Load(); drops != 0 || skipped != 2 {
		t.Fatalf("published: %d ring-buffer drops and %d skipped runs, want 0 and 2: the two are not added up", drops, skipped)
	}
}

// TestASkippedRunTheMonitorSawEarlierLetsALaterFoldGo: a skipped run the
// periodic monitor observed before a call was interrupted lies before that
// call's records, and must not refuse its fold. That holds only because the
// monitor tells the watch of the skipped runs too, under their own stamp:
// were the loop's own read the first to see the count, it would date the
// skip after the interruption.
func TestASkippedRunTheMonitorSawEarlierLetsALaterFoldGo(t *testing.T) {
	f := newDropCountedFixture(t, globalfilter.Filter{})
	programs := f.countSkippedRuns()
	programs.skip(skippedEnterProg, 3)
	f.monitorPoll(restartBase - 500)
	requireFoldedSleep(t, f.foldSleep(restartBase), restartBase, "the skip was seen before the interruption")
}

// TestASkippedExecProgramRunLetsTheExitAdopt: the exec record of a
// non-leader's exec goes missing because the kernel skipped the
// sched_process_exec program, not because the ring buffer was full. The
// successful execve exit under the leader tid adopts the caller's enter, as
// it does for a counted drop - and does not without the skipped run, where
// "nothing was lost" proves that the thread has not exec'd. (What the
// adopted pair proves is TestAnAdoptionOnASkippedRunProvesNoExec.)
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

// TestAnAdoptionOnASkippedRunProvesNoExec is the difference between the two
// kinds of evidence. The kernel counts a skipped run for any task on the
// host, so one counted since a candidate's exec enter may be an unrelated
// task's: the exit adopts the enter - the alternative is an exec without a
// row - but the pair is no proof of an exec, and the row a LIVE thread of
// the process holds stays held with its kept enter. A counted ring-buffer
// drop, a record ior wanted, releases it
// (TestLostExecRecordAdoptionReleasesTheDeadThreadsRows); so does a skipped
// run that comes together with one.
func TestAnAdoptionOnASkippedRunProvesNoExec(t *testing.T) {
	for name, drops := range map[string]uint64{"a skipped run alone": 0, "with a ring-buffer drop": 1} {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			programs := f.countSkippedRuns()
			f.holdOtherThreadsRead()
			f.feedNone(f.execEnter(restartBase+800, restartTid), "the thread's execve enter")
			programs.skip(skippedExitProg, 3)
			f.loseRecords(drops)
			f.clockAt(restartBase + 2950)
			rows := f.feed(f.execExit(restartBase+2900, restartPid, 0))
			if len(rows) == 0 || rows[0].name != "execve" || rows[0].tid != restartTid {
				t.Fatalf("rows = %+v, want the adopted execve of tid %d first", rows, restartTid)
			}
			if drops > 0 {
				f.requireNothingHeld()
				return
			}
			f.requireHeldUnder(restartOtherTid)
			if held, _ := f.el.restarts.lookup(restartOtherTid); held.continuation == nil {
				t.Fatal("the live thread's kept read enter is gone: the adoption was taken for a proof")
			}
		})
	}
}

// watchSource is a drop source whose two counters and their failures the
// test sets directly.
type watchSource struct {
	drops, skipped       uint64
	dropsErr, skippedErr error
}

func (s *watchSource) Total() (uint64, error)       { return s.drops, s.dropsErr }
func (s *watchSource) SkippedRuns() (uint64, error) { return s.skipped, s.skippedErr }
func (s *watchSource) SkippedRunsAsOf(uint64) (uint64, error) {
	return s.skipped, s.skippedErr
}

// TestRestartDropWatchTellsTheKindsOfEvidenceApart pins the watch's answer
// by kind: each counter has its own total and stamp, a moved one is evidence
// for the questions about a time at or before its first observation, a
// counted drop outranks a skipped run, and a counter that cannot be read is
// evidence of its own kind - the ring buffer's of a counted loss, the
// skipped runs' of a possible one.
func TestRestartDropWatchTellsTheKindsOfEvidenceApart(t *testing.T) {
	var watch restartDropWatch
	src := &watchSource{}
	now := uint64(100)
	ask := func(since uint64) lossEvidence {
		return watch.evidenceSince(since, since, src, func() uint64 { return now })
	}
	if got := ask(50); got != noLossEvidence {
		t.Fatalf("two counters that never moved: %v, want no evidence", got)
	}
	src.skipped, now = 4, 200
	if got := ask(150); got != maybeSkippedRecord || watch.lostSince(201, 201, src, func() uint64 { return now }) {
		t.Fatalf("a skipped run first seen at 200: %v for 150, want a possible skip, and nothing for 201", got)
	}
	src.drops, now = 1, 300
	if got := ask(250); got != countedRecordLoss {
		t.Fatalf("a drop first seen at 300, after a skipped run: %v for 250, want a counted loss", got)
	}
	if got := ask(301); got != noLossEvidence {
		t.Fatalf("both seen before 301: %v, want no evidence", got)
	}
	src.skippedErr = errors.New("unreadable")
	if got := ask(9000); got != maybeSkippedRecord {
		t.Fatalf("skipped runs that cannot be read: %v, want a possible skip", got)
	}
	src.dropsErr = errors.New("unreadable")
	if got := ask(9000); got != countedRecordLoss {
		t.Fatalf("a drop counter that cannot be read: %v, want a counted loss", got)
	}
}
