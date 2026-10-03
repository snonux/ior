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
//   - an enter older than the last runtime probe change, or older than the
//     end of the trace's own attach (judgeHalvesFrom): its syscall's exit
//     probe may not have been attached when it returned.
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
// What is counted all the same: a call a seccomp filter denies (or a ptrace
// tracer skips) never fires sys_enter, so its exit comes alone from a thread
// seen before. Those calls return an error (-EPERM, -ENOSYS, ...), so the
// failed exits are counted apart as well (numFailedExitsWithoutEnter), and a
// count made of failed exits only points at a filter rather than at loss.
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

// forgetTrimmed is prune's cleanup for one trimmed pending enter: the pair
// goes back to the pool, and its thread becomes unknown, so the trimmed
// call's exit, should it still come, is no lost half (unpairedExit).
func (p *pairTracker) forgetTrimmed(pair *event.Pair) {
	if pair == nil {
		return
	}
	if pair.EnterEv != nil {
		delete(p.lastEnters, pair.EnterEv.GetTid())
	}
	pair.Recycle()
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
// must have been lost (pairTracker.unpairedExit), and those that returned an
// error apart, the shape a seccomp-denied call has too.
func (e *eventLoop) countUnpairedExit(exitEv event.Event) {
	since, lost := e.pairs.unpairedExit(exitEv)
	if !lost || e.halfMayBeUnseen(since) {
		return
	}
	e.numExitsWithoutEnter++
	if carrier, ok := exitEv.(event.RetCarrier); ok && carrier.GetRet() < 0 {
		e.numFailedExitsWithoutEnter++
	}
}

// lostHalfStatLines renders the two lost-half lines of the statistics. They
// are always printed, so a 0 states that no half was found lost.
func (e *eventLoop) lostHalfStatLines() string {
	return fmt.Sprintf(
		"\tenters without an exit: %d (superseded by the thread's next enter: exit record lost)\n"+
			"\texits without an enter: %d (thread seen before: enter record lost, or a seccomp-denied call; %d returned an error)\n",
		e.numEntersWithoutExit, e.numExitsWithoutEnter, e.numFailedExitsWithoutEnter)
}
