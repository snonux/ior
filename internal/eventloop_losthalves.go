package internal

import (
	"fmt"

	"ior/internal/event"
	"ior/internal/types"
)

// Lost halves (task c23).
//
// Every syscall ior traces is two records, the enter and the exit, and the
// kernel can lose either one alone: a record the full ring buffer refused
// (ring buffer drops), or a probe run the kernel skipped (task 723: an RT
// task preempting a traced one on its CPU makes the kernel skip probe runs,
// and each such call lost exactly one half). The mismatch count does not see
// that. It counts an exit paired with an enter of another syscall, and a lost
// half rarely ends that way: the enter whose exit was lost is superseded by
// its thread's next enter (pairTracker.set), and an exit whose enter was lost
// finds nothing parked and is dropped (tracepointExited). In the task 723
// reproduction the kernel skipped ~12600 runs and the statistics said "0
// mismatched enter/exit pairs".
//
// So the two ends are counted on their own, each with the cases that look the
// same but lose nothing taken out:
//
// An enter without an exit (numEntersWithoutExit) is an enter that is still
// parked, or shed by the raw enter filter with its exit not yet seen, when its
// thread enters its next syscall - parked, shed or noreturn - or when the
// thread execs from another tid (moveExecCaller). A thread enters a syscall
// only after it returned from the previous one, so that exit record is lost.
// Not counted, because nothing was lost:
//   - noreturn syscalls (exit, exit_group, rt_sigreturn): never parked, their
//     row is complete at enter (completeNoReturnEnter);
//   - an enter evicted with its task (sched_process_exit, a task_newtask of
//     the number, the dead leader of a non-leader exec): the task was killed
//     inside the syscall, which never returns (evictTid);
//   - the exec enter moveExecCaller moves to the leader tid, and the enters
//     the restart fold takes and keeps (they are not parked, and a released
//     row parks its kept enter again through syscallEntered);
//   - an enter the pending table's LRU trims (prune), and the enters still
//     parked when the trace stops: calls in flight, not lost;
//   - an enter not younger than the last runtime probe change, or older than
//     the end of the trace's own attach (judgeHalvesFrom): its syscall's exit
//     probe may not have been attached when it returned ("A runtime probe
//     change" below says what a detach leaves open).
//
// An exit without an enter (numExitsWithoutEnter) is an exit that finds no
// enter (enterOfExit) of a thread the tracker has seen enter a syscall before
// (lastEnters), unless it is the exit of the thread's shed enter. Not
// counted:
//   - the thread's first record: a call already in flight when the trace
//     started, the first return of a clone/fork child (task_newtask evicts
//     the number first), a recycled tid (its predecessor's exit record evicted
//     it);
//   - the exit of an enter the raw enter filter shed (-path/-comm on the open
//     kinds; lastEnter.shed);
//   - the exit of an enter the LRU trimmed (forgetTrimmed);
//   - an exit whose thread was last seen entering before the last runtime
//     probe change or before the end of the trace's own attach: the call may
//     have been entered while its enter probe was off;
//   - sampling never makes one: BPF emits an exit only when it emitted the
//     enter (internal/c/filter.c, "Enter state and its two fallbacks");
//   - a successful exec exit under the leader tid with no enter: the leader's
//     exit record evicted the tid, and a delivered exec record moved the
//     caller's enter there (adoptLostExecCaller covers a lost one).
//
// What is counted all the same: a call a seccomp filter answers itself. The
// filter runs before sys_enter and the skipped call still fires sys_exit, so
// its exit comes alone from a thread seen before. What it returns depends on
// the filter's action, and only two of the shapes can be recognised:
//   - SECCOMP_RET_ERRNO returns the errno the filter chose, SECCOMP_RET_TRACE
//     without a tracer -ENOSYS: a failed exit (an errno of 0 is allowed and
//     looks like a success);
//   - SECCOMP_RET_TRAP does not fail. It rolls the return register back to
//     the syscall number and raises SIGSYS, so the exit record carries the
//     call's own number as its return value (sched_getscheduler "returns"
//     145 on x86_64; seen on a desktop under a browser's sandbox, which
//     emulates the call in its SIGSYS handler);
//   - SECCOMP_RET_USER_NOTIF returns whatever the supervisor answered, a
//     success included, and cannot be told from a lost enter.
//
// A ptrace tracer does not make one, with one exception: a tracer that
// cancels a call by setting the syscall number to -1 silences both halves
// (the tracepoints see no syscall), and only PTRACE_SYSEMU skips the call
// before sys_enter and leaves the exit alone.
//
// So the exits of the two recognisable shapes are counted apart as well
// (numFilterLikeExitsWithoutEnter, looksLikeSeccompAnswer), and a count made
// of those only points at a filter rather than at loss. It is a hint in both
// directions: a call that lost its enter record can fail too, or return its
// own number (on x86_64 a read of 0 bytes, a write of 1), and a filter can
// answer in a shape that is not recognised. The syscall number is known for
// x86_64 only (types.TraceId.SyscallNumber); elsewhere only the failed exits
// are recognised.
//
// What the two counts miss (they are lower bounds, and no measure of the
// kernel's own figures, the ring buffer drops and the skipped probe runs):
//   - a lost exit is found only when its thread enters another traced
//     syscall, so the lost exit of a thread's last traced call (or of a call
//     whose thread dies next) is never counted;
//   - a thread that loses the exit of one call and then the enter of its
//     next call of the SAME syscall pairs the first enter with the second
//     exit: one wrong row and no count (with different syscalls it is a
//     mismatch);
//   - a call that loses both halves leaves nothing to count, and a lost
//     enter of a thread not seen before (or forgotten: lastEnterLimit, a
//     trimmed enter, an evicted tid) passes as the thread's first record.
//     With ring buffer drops whole runs of records go, so the counts stay
//     far below the drop count;
//   - the TUI shows neither count: the statistics block is printed at the
//     end of a headless run only (startTraceShutdownWatcher);
//   - a syscall that is sampled or aggregate-only emits no exit without an
//     enter (internal/c/filter.c, ior_stateless_exit_emits), so neither a
//     lost enter nor a filter's answer of such a syscall is seen.
//
// A runtime probe change (the TUI's probes dialog) is covered as far as its
// report reaches: a half whose thread was last seen at or before the change's
// stamp, or while an attach is in flight, is not judged. A detach has no
// in-flight count (restartProbeWatch: it needs none for the folds), and the
// probe manager reports it only after both links are gone, so a thread whose
// exit goes unseen while the detach is under way and whose next enter the
// loop processes before the report is counted as a lost exit although the
// kernel lost nothing. That is left as it is: the counts are printed only by
// headless runs, whose probe set never changes after the initial attach.
//
// The bookkeeping is one map read and one map write per enter (noteEnter),
// allocation-free once the map has grown, and a lookup per exit that found no
// enter; the probe-change question is asked only on a candidate loss.

// lastEnter is what the pair tracker remembers of a thread's latest enter
// record, parked or not (pairTracker.lastEnters).
type lastEnter struct {
	// time is the enter's timestamp, or that of the unpaired exit that made
	// the thread known (unpairedExit).
	time uint64
	// shed is the enter's trace ID when the kind's raw enter filter shed it
	// and its exit has not been seen; 0 otherwise. Trace IDs are kernel
	// tracepoint IDs, never 0.
	shed types.TraceId
}

// lastEnterLimitFactor bounds lastEnters at this many times the pending-enter
// limit. It holds one entry per thread seen, and a thread's exit record drops
// it (evictTid); only lost exit records leave entries behind. A table over
// the bound is cleared as a whole, which makes every thread unknown, so the
// cost of the bound is an undercount (unpairedExit lets the next unpaired
// exit of each thread pass), never a false loss.
const lastEnterLimitFactor = 4

func (p *pairTracker) lastEnterLimit() int {
	return lastEnterLimitFactor * p.limit()
}

// rememberEnter stores last as tid's latest enter and returns what was
// remembered before, if anything.
func (p *pairTracker) rememberEnter(tid uint32, last lastEnter) (prev lastEnter, known bool) {
	if p.lastEnters == nil {
		p.lastEnters = make(map[uint32]lastEnter)
	}
	prev, known = p.lastEnters[tid]
	if !known && len(p.lastEnters) >= p.lastEnterLimit() {
		clear(p.lastEnters)
	}
	p.lastEnters[tid] = last
	return prev, known
}

// noteEnter remembers enterEv as its thread's latest enter, shed by the raw
// enter filter when shed is its trace ID (0 otherwise), and reports a shed
// enter of the thread whose exit never came: that one is superseded now.
func (p *pairTracker) noteEnter(enterEv event.Event, shed types.TraceId) (at uint64, superseded bool) {
	prev, known := p.rememberEnter(enterEv.GetTid(), lastEnter{time: enterEv.GetTime(), shed: shed})
	return prev.time, known && prev.shed != 0
}

// passEnter is set for an enter that is not parked: one the raw enter filter
// shed (shed is its trace ID) or a noreturn one (shed 0), whose row is
// complete at enter. Whatever its thread still has parked is recycled, for
// the reason set recycles it, and reported the same way.
func (p *pairTracker) passEnter(enterEv event.Event, shed types.TraceId) (at uint64, superseded bool) {
	at, superseded = p.noteEnter(enterEv, shed)
	if prev, ok := p.consume(enterEv.GetTid()); ok && prev != nil {
		at, superseded = prev.EnterEv.GetTime(), true
		prev.Recycle()
	}
	return at, superseded
}

// unpairedExit is told of an exit that found no enter. lost reports whether
// its enter record must have been lost: the thread was seen entering a
// syscall before, and this is not the exit of its shed enter. since is the
// time of that earlier enter, which the caller judges the loss by
// (countUnpairedExit). The thread is known from here on either way.
func (p *pairTracker) unpairedExit(exitEv event.Event) (since uint64, lost bool) {
	prev, known := p.rememberEnter(exitEv.GetTid(), lastEnter{time: exitEv.GetTime()})
	ownShedExit := prev.shed != 0 && prev.shed-1 == exitEv.GetTraceId()
	return prev.time, known && !ownShedExit
}

// forgetTrimmed is prune's cleanup for one trimmed pending enter, parked
// under tid: the pair goes back to the pool, and its thread becomes unknown,
// so the trimmed call's exit, should it still come, is no lost half
// (unpairedExit). The thread is named by the table's key, not by the enter's
// own tid: an exec enter moveExecCaller moved sits under the leader's tid,
// where its exit will arrive, and still carries the caller's.
func (p *pairTracker) forgetTrimmed(tid uint32, pair *event.Pair) {
	delete(p.lastEnters, tid)
	if pair != nil {
		pair.Recycle()
	}
}

// judgeHalvesFrom tells the loop the boot-clock time from which every syscall
// probe of the run's initial set is attached (trace setup, after the attach
// and before the loop starts). A half of a call that may have begun before
// then is not judged: the trace attaches enter and exit tracepoints one by
// one, so a call made during the attach can show one half only. A loop
// nobody tells (tests) judges every half.
func (e *eventLoop) judgeHalvesFrom(bootNs uint64) {
	e.lostHalvesFrom = bootNs
}

// halfMayBeUnseen reports whether a call of a thread last seen at since may
// have run with a probe of its syscall off: since is before the trace's own
// attach was over, or a runtime probe change came at or after it.
func (e *eventLoop) halfMayBeUnseen(since uint64) bool {
	return since < e.lostHalvesFrom || e.restarts.probes.changedSince(since)
}

// countSupersededEnter counts an enter set, passEnter or moveExecCaller
// superseded (superseded), unless its call may have returned unseen (at is
// its time).
func (e *eventLoop) countSupersededEnter(at uint64, superseded bool) {
	if superseded && !e.halfMayBeUnseen(at) {
		e.numEntersWithoutExit++
	}
}

// countUnpairedExit counts an exit that found no enter when its enter record
// must have been lost (pairTracker.unpairedExit), and apart those that have
// the shape of a seccomp filter's answer.
func (e *eventLoop) countUnpairedExit(exitEv event.Event) {
	since, lost := e.pairs.unpairedExit(exitEv)
	if !lost || e.halfMayBeUnseen(since) {
		return
	}
	e.numExitsWithoutEnter++
	if looksLikeSeccompAnswer(exitEv) {
		e.numFilterLikeExitsWithoutEnter++
	}
}

// looksLikeSeccompAnswer reports whether an exit without an enter returned
// what a call a seccomp filter answered returns: an error (SECCOMP_RET_ERRNO,
// or SECCOMP_RET_TRACE without a tracer) or the syscall's own number
// (SECCOMP_RET_TRAP rolls the return register back to it). An exit kind
// without a return value, or a syscall whose number is not known on this
// architecture, is recognised by neither.
func looksLikeSeccompAnswer(exitEv event.Event) bool {
	carrier, ok := exitEv.(event.RetCarrier)
	if !ok {
		return false
	}
	ret := carrier.GetRet()
	if ret < 0 {
		return true
	}
	nr, known := exitEv.GetTraceId().SyscallNumber()
	return known && ret == nr
}

// lostHalfStatLines renders the two lost-half lines of the statistics. They
// are always printed, so a 0 states that no half was found lost. Each line
// begins with its count, and the second names its filter-like share as
// "N look like", which integrationtests.ParseKernelLoss reads.
func (e *eventLoop) lostHalfStatLines() string {
	return fmt.Sprintf(
		"\tenters without an exit: %d (superseded by the thread's next enter: exit record lost)\n"+
			"\texits without an enter: %d (thread seen before: enter record lost, or a call a seccomp filter answered; "+
			"%d look like a filter's answer: an error or the syscall's own number)\n",
		e.numEntersWithoutExit, e.numExitsWithoutEnter, e.numFilterLikeExitsWithoutEnter)
}
