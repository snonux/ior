package internal

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ior/internal/globalfilter"
	"ior/internal/probemanager"
	"ior/internal/tracepoints"
	"ior/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
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
// attached, which is what a sweep is told to read (fds), the tracepoint each
// is attached to, which is what a fold asks by (fdsOn), and the number of
// reads made, which is what a sweep costs.
type scriptedPrograms struct {
	misses   map[int]uint64
	attached []int
	on       map[int]string
	reads    int
	err      error
	// unreported makes the kernel fill less than the field, as one that
	// does not know it does.
	unreported bool
}

// newScriptedPrograms returns the programs behind fds, all attached, to no
// tracepoint a fold asks about until attachOn names one.
func newScriptedPrograms(fds ...int) *scriptedPrograms {
	programs := &scriptedPrograms{misses: map[int]uint64{}, attached: fds, on: map[int]string{}}
	for _, fd := range fds {
		programs.misses[fd] = 0
	}
	return programs
}

// attachOn attaches the program behind fd to tracepoint.
func (p *scriptedPrograms) attachOn(fd int, tracepoint string) {
	if _, known := p.misses[fd]; !known {
		p.misses[fd] = 0
		p.attached = append(p.attached, fd)
	}
	p.on[fd] = tracepoint
}

// fds is the libbpfAttachedProgramFDs of the scripted kernel.
func (p *scriptedPrograms) fds() []int {
	return slices.Clone(p.attached)
}

// fdsOn is the libbpfAttachedProgramFDsOn of the scripted kernel: the
// programs ever attached to one of tracepoints, detached since or not.
func (p *scriptedPrograms) fdsOn(tracepoints []string) []int {
	var fds []int
	for fd, tracepoint := range p.on {
		if slices.Contains(tracepoints, tracepoint) {
			fds = append(fds, fd)
		}
	}
	slices.Sort(fds)
	return fds
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

// The programs of countSkippedRuns, by the tracepoint each is attached to:
// restart_syscall's pair, the fixture's two interrupted syscalls' pairs
// (clock_nanosleep for -516, read for the re-executions), a hand probe, and
// a syscall none of the fixture's folds depends on.
const (
	skippedEnterProg = 11 + iota
	skippedExitProg
	skippedSleepEnterProg
	skippedSleepExitProg
	skippedReadEnterProg
	skippedReadExitProg
	skippedDeliverProg
	skippedWriteProg
)

// skippedProgramTracepoints are the tracepoints of countSkippedRuns's
// programs.
var skippedProgramTracepoints = map[int]string{
	skippedEnterProg:      "sys_enter_restart_syscall",
	skippedExitProg:       "sys_exit_restart_syscall",
	skippedSleepEnterProg: "sys_enter_clock_nanosleep",
	skippedSleepExitProg:  "sys_exit_clock_nanosleep",
	skippedReadEnterProg:  "sys_enter_read",
	skippedReadExitProg:   "sys_exit_read",
	skippedDeliverProg:    signalDeliverProbeName,
	skippedWriteProg:      "sys_enter_write",
}

// countSkippedRuns turns the fixture's scripted drop counter into the source
// of a kernel that counts skipped runs: the same ring counter, plus a
// skipped-run counter over the attached programs above, dated by the
// fixture's clock. The monitor is rebuilt on the new source, as trace setup
// builds it.
func (f *restartFixture) countSkippedRuns() *scriptedPrograms {
	f.t.Helper()
	programs := newScriptedPrograms()
	for fd := skippedEnterProg; fd <= skippedWriteProg; fd++ {
		programs.attachOn(fd, skippedProgramTracepoints[fd])
	}
	f.countSkippedRunsOf(programs.fds, programs.fdsOn, programs.read)
	return programs
}

// countSkippedRunsOf is countSkippedRuns over the given seam.
func (f *restartFixture) countSkippedRunsOf(fds func() []int, fdsOn func([]string) []int, read func(int) (uint64, bool, error)) {
	f.t.Helper()
	skipped, err := newSkippedRunCounter(fds, fdsOn, read, f.el.readDropStampClock)
	if err != nil {
		f.t.Fatalf("newSkippedRunCounter: %v", err)
	}
	f.el.dropSrc = &recordLossSource{ring: f.el.dropSrc, skipped: skipped}
	f.drops.monitor = newRingbufDropMonitor(f.el.dropSrc)
}

// countSkippedRunsOfLinks is countSkippedRuns over the real list of attached
// programs (libbpfAttached), for a module of the test's own: each program
// is listed by a libbpfLink, whose Destroy - libbpfgo's stubbed - is how
// the probe manager detaches it. The counts are scripted as before; the
// links are returned by program fd.
func (f *restartFixture) countSkippedRunsOfLinks() (*scriptedPrograms, map[int]*libbpfLink) {
	f.t.Helper()
	stubDestroyBPFLink(f.t, nil)
	module := &bpf.Module{}
	f.t.Cleanup(func() { libbpfAttached.forget(module) })
	programs := newScriptedPrograms()
	links := map[int]*libbpfLink{}
	for fd := skippedEnterProg; fd <= skippedWriteProg; fd++ {
		programs.misses[fd] = 0
		link := &libbpfLink{program: attachedProgram{module: module, fd: fd, tracepoint: skippedProgramTracepoints[fd]}}
		link.link.Store(markedBPFLink(f.t))
		libbpfAttached.add(link.program)
		links[fd] = link
	}
	f.countSkippedRunsOf(func() []int { return libbpfAttachedProgramFDs(module) },
		func(tracepoints []string) []int { return libbpfAttachedProgramFDsOn(module, tracepoints) },
		programs.read)
	return programs, links
}

// TestASkipOfAProgramDetachedBeforeTheProbeChangeRefusesTheFold: a probe
// switched off unlists each of its programs as attached once that link's
// Destroy returned, while the change is stamped for the folds
// (noteProbeChange, restartAcrossProbeChange) only after both links went
// and the manager reported. A lagging loop that folds in that window is not
// refused by the probe change, so it must still ask the detached program
// (attachedProgramSet): a run of it skipped before the detach refuses the
// fold. Without the skip the detach alone changes nothing: the fold goes.
func TestASkipOfAProgramDetachedBeforeTheProbeChangeRefusesTheFold(t *testing.T) {
	for _, fd := range []int{skippedExitProg, skippedSleepExitProg} {
		for _, skipped := range []uint64{1, 0} {
			t.Run(fmt.Sprintf("%s skipped %d", skippedProgramTracepoints[fd], skipped), func(t *testing.T) {
				f := newDropCountedFixture(t, globalfilter.Filter{})
				programs, links := f.countSkippedRunsOfLinks()
				f.interrupt(restartBase, restartTid)
				programs.skip(fd, skipped)
				if err := links[fd].Destroy(); err != nil {
					t.Fatalf("detach: %v", err)
				}
				rows := f.foldSleepFrom(restartBase)
				if skipped == 0 {
					requireFoldedSleep(t, rows, restartBase, "nothing was skipped")
					return
				}
				requireSleepAndRestartRows(t, rows, restartBase, restartBase+1500, restartBase+3000, 0)
			})
		}
	}
}

// TestASkipAFoldReadIsDatedForTheExecAdoption: a skip first seen by a fold's
// own read is told to the drop watch by that fold (lostSince, noteSkipped)
// and stamped then. An exec adoption that asks later about an enter after
// that fold must take the skip for one before its enter, and refuse as
// "nothing lost since" refuses. Were the skip stamped only by the
// adoption's own sweep, it would date after the enter, and the exit would
// adopt the enter (TestASkippedExecProgramRunLetsTheExitAdopt is that case
// with a skip after the enter).
func TestASkipAFoldReadIsDatedForTheExecAdoption(t *testing.T) {
	f := newReexecFixture(t, globalfilter.Filter{})
	programs := f.countSkippedRuns()
	f.interrupt(restartBase, restartTid)
	programs.skip(skippedExitProg, 1)
	requireSleepAndRestartRows(t, f.foldSleepFrom(restartBase), restartBase, restartBase+1500, restartBase+3000, 0)

	const later = restartBase + 10000
	f.interruptRead(later, restartTid, restartSys)
	f.feedNone(f.handlerRecord(later+510, restartTid, true), "HANDLER record")
	f.feedNone(f.execEnter(later+800, restartTid), "the handler's execve enter")
	f.clockAt(later + 2900)
	rows := f.feed(f.execExit(later+3000, restartPid, 0))
	// The adopted row's gap differs from reexecutedExecveRow's: the folds
	// before it moved the tid's baseline.
	if slices.ContainsFunc(rows, func(row restartRow) bool { return row.name == "execve" }) {
		t.Fatalf("rows = %+v: the exit adopted the enter on a skip a fold saw before it", rows)
	}
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
	// restart_syscall's pair, clock_nanosleep's and the hand probe: the
	// fold's own programs, once at RESUME and once at the exit.
	if got, want := programs.reads-swept, 2*5; got != want {
		t.Fatalf("the caught-up fold made %d program reads, want %d (its 5 programs at RESUME and at the exit)", got, want)
	}
}

// foldSkipCases says, per program of countSkippedRuns, whether its skipped
// run refuses the fold of a stopped clock_nanosleep (-516, continued by
// restart_syscall) and of a read re-executed after an SA_RESTART handler:
// a fold asks about its own syscall's pair, restart_syscall's for -516 and
// the hand probes (restartFoldTracepoints), and about nothing else.
var foldSkipCases = map[string]struct {
	fd                        int
	refusesSleep, refusesRead bool
}{
	"restart_syscall enter": {skippedEnterProg, true, false},
	"restart_syscall exit":  {skippedExitProg, true, false},
	"clock_nanosleep enter": {skippedSleepEnterProg, true, false},
	"clock_nanosleep exit":  {skippedSleepExitProg, true, false},
	"read enter":            {skippedReadEnterProg, false, true},
	"read exit":             {skippedReadExitProg, false, true},
	"signal_deliver":        {skippedDeliverProg, true, true},
	"write enter":           {skippedWriteProg, false, false},
}

// TestOnlyTheFoldsOwnProgramsRefuseIt: a run skipped while a row is held
// refuses its fold when it is one of the programs the fold depends on, and
// only then - a skip of another syscall's program leaves the fold to go on
// (restartFoldTracepoints argues why that is sound).
func TestOnlyTheFoldsOwnProgramsRefuseIt(t *testing.T) {
	for name, tc := range foldSkipCases {
		t.Run(name, func(t *testing.T) {
			f := newReexecFixture(t, globalfilter.Filter{})
			programs := f.countSkippedRuns()
			f.interrupt(restartBase, restartTid)
			programs.skip(tc.fd, 1)
			rows := f.foldSleepFrom(restartBase)
			folded := len(rows) == 1 && rows[0].ret == 0 && rows[0].duration == 3000
			if folded == tc.refusesSleep {
				t.Fatalf("sleep: rows = %+v, folded = %v, want the fold refused: %v", rows, folded, tc.refusesSleep)
			}
			const later = restartBase + 10000
			f.interruptRead(later, restartTid, restartSys)
			f.feedNone(f.handlerRecord(later+510, restartTid, true), "HANDLER record")
			programs.skip(tc.fd, 1)
			rows = f.foldReadFrom(later)
			folded = len(rows) == 1 && rows[0].ret == 1 && rows[0].duration == 3000
			if folded == tc.refusesRead {
				t.Fatalf("read: rows = %+v, folded = %v, want the fold refused: %v", rows, folded, tc.refusesRead)
			}
		})
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

// SkippedRunsSince is the question of a fold, which these tests do not
// ask (evidenceSince is the exec adoption's): it answers "skipped" so that
// a fold that asked would show.
func (s *watchSource) SkippedRunsSince([]string, uint64, uint64) (bool, uint64, error) {
	return true, s.skipped, s.skippedErr
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
	if got := ask(150); got != maybeSkippedRecord || ask(201) != noLossEvidence {
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

// namingProbeProgram records the tracepoint names it is attached to, classic
// or raw, in the list of its attacher.
type namingProbeProgram struct{ names *[]string }

func (p namingProbeProgram) AttachTracepoint(_, name string) (probemanager.Link, error) {
	*p.names = append(*p.names, name)
	return &fakeProbeLink{}, nil
}

func (p namingProbeProgram) AttachRawTracepoint(name string) (probemanager.Link, error) {
	*p.names = append(*p.names, name)
	return &fakeProbeLink{}, nil
}

// namingAttacher hands out namingProbeProgram for every program.
type namingAttacher struct{ names []string }

func (a *namingAttacher) GetProgram(string) (probemanager.Program, error) {
	return namingProbeProgram{names: &a.names}, nil
}

// TestRestartFoldTracepointsAreTheNamesProgramsAreAttachedUnder: a fold
// asks the list of attached programs by tracepoint name, and a name it
// spells differently from the attach finds nothing - silently, as a fold
// that depends on no program. The hand probes' names must be those the
// hand attaches use, and a syscall's those of tracepoints.List, which the
// probe manager attaches by.
func TestRestartFoldTracepointsAreTheNamesProgramsAreAttachedUnder(t *testing.T) {
	attacher := &namingAttacher{}
	log := bpfSetupLog{status: failOnLog(t), warn: failOnLog(t), teardown: failOnLog(t)}
	for _, attach := range []func(probemanager.Attacher, bpfSetupLog) func(){attachProcessExecProbe,
		attachProcessExitProbe, attachTaskNewtaskProbe, attachTaskRenameProbe, attachSignalDeliverProbe,
		attachRestartSigreturnProbe} {
		attach(attacher, log)()
	}
	slices.Sort(attacher.names)
	hand := slices.Sorted(slices.Values(restartFoldHandTracepoints))
	if !slices.Equal(attacher.names, hand) {
		t.Fatalf("hand probes attached under %v, a fold asks for %v", attacher.names, hand)
	}
	named := map[string]bool{}
	for id := range types.TraceId(4096) {
		if strings.HasPrefix(id.Name(), "unknown_trace_id") {
			continue
		}
		enter, exit := syscallTracepoints(id)
		named[enter], named[exit] = true, true
	}
	for _, tracepoint := range tracepoints.List {
		if !named[tracepoint] {
			t.Errorf("the probe manager attaches %s, which no trace ID's syscallTracepoints names", tracepoint)
		}
	}
}
