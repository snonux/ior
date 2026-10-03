package internal

import (
	"ior/internal/event"
	"ior/internal/types"
)

// rekeyExecCaller applies the tid change of an execve by a non-leader thread.
//
// When a thread other than the group leader calls execve, de_thread() kills
// every other thread, waits for the leader to become a zombie and then hands
// the exec'ing task the leader's tid (== tgid). The execve entered under the
// caller's own tid (ev.OldTid), but its sys_exit record arrives under the
// leader's (ev.Tid). tracepointExited consumes the parked enter by the exit's
// tid, so without this the enter stayed parked under a tid that no longer
// exists - leaked until LRU trimming or tid reuse, where a recycled owner's
// exit could even consume it - and the exit found nothing: the execve row was
// lost. The BPF side moves its in-flight enter state the same way
// (ior_on_exec_tid_change in internal/c/filter.c).
//
// The ring buffer delivers the leader's sched_process_exit record, then this
// record, then the execve's exit, so by now the leader's own state is already
// evicted and the move lands before the exit looks for it
// (applyExecTidChange also drops leftovers of a lost leader exit record).
//
// If this record itself is lost (ring-buffer backpressure after the BPF move
// already happened), the exit still arrives under the leader tid with its
// enter parked under the caller's - or kept with a row held there, when the
// execve was interrupted and re-executed; adoptLostExecCaller recovers that
// pair.
//
// OldTid 0 never comes from the kernel (old_pid is a real task's tid) and is
// treated as "tid kept", so records built without the field (tests, synthetic
// replays) keep their old meaning (execChangedTid).
func (e *eventLoop) rekeyExecCaller(ev *types.ProcessExecEvent) {
	if !execChangedTid(ev) {
		return
	}
	e.applyExecTidChange(ev.OldTid, ev.Tid)
}

// execChangedTid reports whether ev is the exec of a non-leader thread, which
// continues under another tid (the leader's) than the one it ran as.
func execChangedTid(ev *types.ProcessExecEvent) bool {
	return ev.OldTid != 0 && ev.OldTid != ev.Tid
}

// releaseExecCallerRestart releases the interrupted row a non-leader exec's
// caller still holds under its pre-exec tid (eventloop_restart.go, task 103).
//
// A held row waits for the next record of its tid, and routeHeldRestart finds
// it by the record's tid. This record carries the leader's tid, the exec'ing
// thread gets no sched_process_exit under its old tid (it lives on as the
// leader), and no record will ever name the old tid again - so the exec record
// is the last chance to settle the row, and its OldTid is the only thing that
// points at it. Two rows can be waiting there:
//
//   - the execve itself, interrupted with -ERESTARTNOINTR (a signal arrived
//     while it waited for cred_guard_mutex: a concurrent exec in the group, a
//     ptrace attach) and re-executed, with the re-executed enter taken for the
//     fold (heldRestart.continuation). Left alone, the row stayed held under
//     the vanished tid, moveExecCaller found no parked enter to carry over, and
//     the successful execve's exit under the leader tid paired with nothing:
//     the exec had no row at all. The release completes the -513 row and parks
//     the enter again under the old tid, from where rekeyExecCaller moves it
//     like any execve in flight.
//   - another call (a read, a wait) whose restarting signal handler exec'd
//     instead of returning. The call will never be re-executed.
//
// Only an exec enter is parked again: it is the execve the thread is inside.
// A row whose kept enter is any other call's - re-executed, its exit record
// lost, and the thread has exec'd since - is released with that enter
// recycled (task v13): no exit will pair with it, the tid change below
// recycled it within the same record anyway (moveExecCaller), and parking it
// first could push the oldest live enters out of a full pending-enter table.
//
// It runs first of all in handleProcessExecEvent: before rekeyExecCaller, so
// the enter parked again is there to be moved, and before the FD_CLOEXEC
// eviction, so that enter's target is resolved against the descriptors the
// process had when it entered the execve (storeEnter).
func (e *eventLoop) releaseExecCallerRestart(ev *types.ProcessExecEvent, ch chan<- *event.Pair) {
	if !execChangedTid(ev) {
		return
	}
	held, ok := e.restarts.take(ev.OldTid)
	if !ok {
		return
	}
	if _, isExec := held.continuation.(*types.ExecEvent); !isExec {
		// Not the execve the thread is inside: its call is over.
		held.dropContinuation()
	}
	e.releaseTakenRestart(held, ch)
}

// noteExecRecord tells the restart fold that ev proves an exec of its process
// (restartTracker.noteExec), so the rows still held under the threads that
// exec ended are released behind the record. Only a record that names the
// thread that exec'd does: with OldTid, the caller's own row is either the
// one under the record's tid (the leader exec'd) or was released just before
// (releaseExecCallerRestart). A record without the field - an object that
// predates it, a synthetic replay - may be a non-leader's, whose row and kept
// execve enter are still to be found by the execve's exit
// (adoptLostExecCaller) and must not be taken for a dead thread's. A record
// whose tid is not the pid does not come from the kernel and proves nothing.
//
// A record without the field also ends the trust in exec records
// (trustExecRecords) for the rest of the run: whatever wrote it names no
// caller, so no exec record of this run moves a non-leader's enter, every
// such exec depends on the adoption, and a missing record with no counted
// drop is then the rule, not a sign that no exec happened. The exit adopts
// unchecked from then on and proves nothing (lostExecRecord).
func (e *eventLoop) noteExecRecord(ev *types.ProcessExecEvent) {
	if ev.OldTid == 0 {
		e.execRecordsTrusted = false
		return
	}
	if ev.Tid == ev.Pid {
		e.restarts.noteExec(ev.Pid)
	}
}

// trustExecRecords tells the loop whether the sched_process_exec probe
// attached for this run (trace setup, before the loop starts). Exec records
// count as complete only when ring-buffer drops are counted too (dropSrc):
// then an exec that left no record is a counted drop or did not happen, which
// is what lets a successful exec exit without an enter be told from a call a
// seccomp filter answered (lostExecRecord). A run of the exec program the
// kernel skipped is no counted drop, though it loses the record as well;
// lostExecRecord says what the gate makes of it where the kernel counts such
// runs, and what it costs where it does not. The probe is attached before any
// syscall probe (attachTraceProbes), so no exec whose enter the trace saw can
// have passed the tracepoint unseen. False in a loop nobody told and whenever
// either is missing; adoptLostExecCaller then adopts unchecked, as it did
// before task v13.
func (e *eventLoop) trustExecRecords(execProbeAttached bool) {
	e.execRecordsTrusted = execProbeAttached && e.dropSrc != nil
}

// lostExecRecord answers the two questions adoptLostExecCaller has about a
// candidate caller whose exec enter is stamped entered: may the exit under
// the leader tid adopt that enter (adopt), and does the adopted pair prove
// an exec of the process (proven, restartTracker.noteExec)?
//
// The exec record of a real exec by that thread was reserved after the enter
// and before the exit. While exec records are trusted (trustExecRecords) it
// is therefore missing only if a record was lost since the enter, and the
// drop watch is asked as a fold asks it (restartDropWatch.evidenceSince), but
// from the candidate's enter on, not from an interrupted exit, and up to the
// exit that asks (exited), which every record in question precedes. That is
// one read of the drop counter per exit, paid only by a successful exec exit
// without an enter that found a candidate: lostExecCaller asks about one
// candidate and never about a second. The answer has three values:
//
//   - no evidence of a loss is a proof: the thread has not exec'd, the exit
//     is not its execve's, nothing is adopted and nothing is proven.
//   - a counted loss (a ring-buffer drop first observed after the enter, a
//     first read of a moved drop counter, a drop counter that cannot be
//     read) is weaker than that, but it is a record ior wanted and did not
//     get, and the only evidence there is: it adopts and proves.
//   - a skipped program run (task 723) adopts and proves NOTHING. The kernel
//     counts a skipped run for every task on the host, whatever ior's
//     filter, so on a host where a real-time task keeps preempting BPF
//     programs the count moves all the time without one record of the trace
//     missing. Adopting on it is right: the alternative is an exec without
//     a row whenever its record really was skipped. Taking the pair for
//     proof of an exec is not: the proof releases the held rows of the
//     process's other threads (restartTracker.noteExec), and an unrelated
//     task's skip would do that to live threads. A wrong adoption on a
//     skipped run costs the one wrong execve row an unchecked adoption
//     always cost.
//
// What the gate cannot see. The two counters count the records the ring
// buffer refused and the program runs the kernel skipped, and an exec record
// can go missing in other ways:
//
//   - it reached userspace and was discarded there, before it moved the
//     caller's enter: a record that does not decode, or a panic in
//     handleProcessExecEvent ahead of the re-key (rekeyExecCaller);
//   - the boottime offset of ior's time namespace is unknown
//     (warnUnknownBootClock) and puts the watch's stamps in the records'
//     past, so that a drop first observed after the enter passes for one
//     seen before it (restartDropWatch);
//   - the kernel skipped the tracepoint program on a kernel that does not
//     count the skip for this kind of program (before Linux 6.7). It happens
//     to this probe: sched_process_exec is a classic tracepoint, skipped
//     while a task preempted in the middle of a bpf(2) map operation has
//     left bpf_prog_active raised on the CPU (skippedRunCounter).
//
// Each of the three makes the gate refuse, never adopt wrongly: the exit
// finds no evidence and stays unpaired, and the exec has no row - a
// missing execve row, what a lost exec record cost before there was an
// adoption (task r13 for a re-executed execve) - while the caller's enter
// stays parked, or kept with its held row.
//
// An unknown offset that puts the stamps in the records' future errs the
// other way and loses no exec: a drop seen up to that long before the enter
// cannot be placed before it, which widens the residual adoptLostExecCaller
// names by that much.
//
// Without that trust (no counter, the exec probe not attached, records that
// name no caller) a missing exec record says nothing either way. The enter is
// adopted, since otherwise such a run lost the row of every non-leader exec,
// but the pair proves nothing: a wrong adoption then costs the one wrong
// execve row it always cost, and not the rows of live threads.
func (e *eventLoop) lostExecRecord(entered, exited uint64) (adopt, proven bool) {
	if !e.execRecordsTrusted {
		return true, false
	}
	evidence := e.restarts.drops.evidenceSince(entered, exited, e.dropSrc, e.readDropStampClock)
	return evidence != noLossEvidence, evidence == countedRecordLoss
}

// applyExecTidChange moves a non-leader exec's per-tid state from the caller's
// tid (oldTid) to the leader tid (newTid) it continues under.
//
// The parked execve enter and its gap baseline move (pairTracker.moveExecCaller);
// the row keeps the caller's tid (the enter's), since that is the thread that
// made the call, and only the pairing key changes. Everything else is
// dropped for both tids rather than moved. Under oldTid: its comm is the
// pre-exec name, which the exec record replaces for newTid anyway, and a
// handle parked by a name_to_handle_at whose exit record never came belongs
// to no call any more. Under newTid: whatever is still there belongs to the
// dead leader (its exit record normally evicted it; this covers a lost one).
// No thread will ever report under oldTid again - the number was released
// with the dead leader - so leaving entries behind would only wait for a
// recycled owner. (The handle NAMES are not per-tid state and stay, the
// scoped ones of the process included: a handle is as valid after the exec
// as before, see handleTracker and dropProcessState.)
//
// A non-exec enter still parked under oldTid lost its exit and is counted as
// an enter without an exit (moveExecCaller, countSupersededEnter).
func (e *eventLoop) applyExecTidChange(oldTid, newTid uint32) {
	e.countSupersededEnter(e.pairs.moveExecCaller(oldTid, newTid))
	e.evictCachedComm(oldTid)
	handles := e.handleState()
	handles.dropTaken(oldTid)
	handles.dropTaken(newTid)
	// The exec emptied the caller's registered-ring table, and the dead
	// leader's went with it (handleProcessExecEvent drops newTid's as well,
	// for the exec that keeps its tid).
	e.ringState().dropThread(oldTid)
}

// adoptLostExecCaller is the fallback pairing for a non-leader execve whose
// sched_process_exec record never reached userspace (bpf_ringbuf_reserve()
// failed; counted in ringbuf_drop_map). BPF has already moved its enter state
// before reserving the record, so the exit is emitted under the leader tid
// while the parked enter still sits under the caller's tid.
//
// Only an exit that looks exactly like that is considered: a successful
// (ret 0) execve/execveat exit under tid == pid with no enter of its own.
// A non-leader exec is the only way a successful execve returns under a tid
// other than the one it entered under, and it always returns under the
// leader's. The candidate enter is found through the pair tracker's per-pid
// index of parked non-leader exec enters (pairTracker.parkedExecCaller), so
// the lookup is O(1) rather than a scan of all parked enters. On a hit the
// same state change as the lost record would have made is applied and the
// pair is consumed under the leader tid.
//
// Concurrent callers: several threads of one process can sit in execve at
// once; one wins, and de_thread kills the others, whose exit records evict
// their enters (and index hints) before the winner's exit arrives. The index
// keeps every caller per pid, so one loser's eviction no longer hides the
// winner's hint. Residual ambiguity: a wrong adoption needs the winner's exec
// record AND a loser's exit record to be lost, with the lookup (which prefers
// the most recently parked caller) landing on that loser. The row then
// carries the loser's tid and filename and the winner's enter stays parked
// until LRU trimming; two lost records in one exec are accepted for that
// over losing every non-leader exec whose record was dropped.
//
// The adoption retires the caller's tid as the lost record would have, so it
// also releases an interrupted row still held under it (sent on ch before the
// adopted pair), exactly as releaseExecCallerRestart does for a delivered
// record. Two rows can be waiting there, and they are found in different
// places:
//
//   - a call whose restarting signal handler exec'd. The handler's execve
//     enter is parked under the caller's tid, so the index above finds it.
//   - the execve itself, interrupted with -ERESTARTNOINTR and re-executed
//     (task r13). Its re-executed enter was taken for the fold and is kept
//     with the held row, not parked, so the index has no hint for it; when no
//     parked caller is found, the held rows are asked instead
//     (restartTracker.reexecutingExecCaller). The release completes the -513
//     row and parks the kept enter again under the caller's tid, from where
//     the tid change below moves it like any execve in flight. Before, this
//     exit was dropped unpaired - no row for the successful execve, not
//     counted - and the -513 row stayed held under the vanished tid until the
//     loop stopped or a new task was handed the number.
//
// The result is the two rows the delivered record produces as well, the -513
// row and the successful execve from its re-executed enter, not one folded
// row: a record of this very exec is known to be lost, which is what refuses a
// fold (restartProofLost). The enter always survives being parked again: exec
// enters are registered without a raw enter filter (eventloop_kinds.go), so
// nothing on that path can shed it.
//
// A parked caller is preferred over a held row when both exist: only one
// thread can have won the exec, and the other's exit record is missing either
// way. Preferred means asked alone (lostExecCaller): when the parked caller is
// refused, the held row is not asked in its place. The refusal says that
// nothing was dropped since the parked caller's enter, and that proves more
// than "this thread did not exec": the parked caller was alive at its enter,
// so an exec by any thread of the process that this exit could complete passed
// de_thread, and reserved its exec record, after that enter. Not dropped, that
// record would have moved the exec'ing thread's enter under the leader tid,
// and the exit would have found it. So no thread exec'd, and the exit is a
// filter's answer. Falling through adopted the held thread's enter whenever
// that enter predated a drop the watch had first seen before the parked
// caller's: a wrong execve row, its -513 row, and - the pair counting as a
// proof - the held rows of the process's live threads released.
//
// The held-row lookup has the residual of the parked one: adopting the
// wrong thread needs the exec record AND a killed sibling's exit record to be
// lost, or a leader's own successful execve exit that finds no parked enter
// (its enter record lost to backpressure, the enter trimmed from the pending
// table, or the execve already in flight when the probes attached) while a
// killed sibling's row is still held for want of its exit record. A displaced
// enter is not such a case: the enter that displaced it pairs with the exit
// (a trace-ID mismatch), and this function is not asked.
//
// Records are routed by their own tid first (routeHeldRestart), so when the
// dead leader still holds a row with a kept continuation enter - its exit
// record lost as well as the exec record, and the exit of the call it was
// re-executing - the execve's exit under the leader tid is taken for that
// row's business before it gets here. It is no step of that fold and releases
// the row; the kept enter is recycled, not parked again, because a successful
// exec exit ends every other call entered under its tid
// (continuationCutShortBy, task v13), and the exit then arrives here without
// an enter, like any other. Before, the dead leader's enter was parked again
// and the exit paired with it: a trace-ID mismatch and no row for the exec,
// and the real caller's -513 row stayed held.
//
// One such stream is not decided by anything in it, and goes to the leader:
// the leader's kept enter is an exec enter of the exit's own syscall, and a
// non-leader thread holds a re-executed exec as well (or has one parked).
// Either may have won. The leader, with the other's -513 exit, the other's
// exit record and the exec record lost; or the other, with the leader's -513
// exit, the leader's exit record and the exec record lost: three records each
// way, the same three kinds, and no record that arrives tells the two apart.
// The exit is the next step of the leader's fold and is taken as that - one
// row when nothing is known to be lost, the -513 row and the execve's own row
// when the fold is refused - and this function is not asked. If the other
// thread was the caller, that is a successful execve under the dead leader's
// enter, with the leader's filename. The other thread's row is released
// behind the exit either way (releaseRestartsBehindExec): whoever won, that
// thread is gone.
//
// The exit alone says nothing: an execve of the leader that a seccomp filter
// answered with 0 leaves exactly this record (completedExec) while the
// process and its threads live on, and one of them may be a non-leader thread
// inside a real execve - a candidate. Adopting its enter gave a wrong execve
// row (the filter's "success" under that thread's tid and filename, and the
// thread's real execve then without its enter), which was so before task
// v13; since v13 the adopted pair also counts as a proof of the exec
// (noteExec), which released the held rows of every live thread of the
// process, recycled their kept enters and retired their tids, so that their
// calls came back without a row and uncounted. The adoption therefore asks
// for what it presupposes, a lost exec record (lostExecRecord): where exec
// records are trusted it adopts, and proves, only when a record may have
// been dropped since the candidate's enter, and the exit is otherwise
// dropped unpaired like any filter-answered call, the candidate left where
// it was. Where they are not trusted it adopts as before and proves nothing.
// What stays: the filter's answer, a thread inside a real execve and a drop
// the watch cannot place before that thread's enter, all at once.
//
// proven reports whether the pair may stand as a proof of the exec.
func (e *eventLoop) adoptLostExecCaller(exitEv event.Event, ch chan<- *event.Pair) (ep *event.Pair, proven, ok bool) {
	ret, ok := completedExec(exitEv)
	if !ok {
		return nil, false, false
	}
	callerTid, proven, ok := e.lostExecCaller(ret)
	if !ok {
		return nil, false, false
	}
	e.releaseHeldRestart(callerTid, ch)
	e.applyExecTidChange(callerTid, ret.Tid)
	ep, ok = e.pairs.consume(ret.Tid)
	return ep, proven, ok
}

// lostExecCaller finds the thread whose exec enter the exit adopts
// (adoptLostExecCaller). One candidate is asked about, in this order:
//
//   - the most recently parked non-leader exec caller of the process, if
//     there is one. It is adopted when its exec record may be lost
//     (lostExecRecord, which also says whether the pair will prove the
//     exec). When it is refused there is no caller at all, and a thread
//     whose re-executed exec is kept with a held row is not asked: the
//     parked caller entered alive, so the exec record of any exec since
//     was reserved after its enter and was not dropped
//     (adoptLostExecCaller). The refused caller keeps its hint in
//     the index, which the lookup took out: its execve is still in flight,
//     and the exit that completes it may need the hint.
//   - only when no caller is parked: the thread whose re-executed exec is
//     kept with a held row, judged the same way by that kept enter's time.
//     The exec record is reserved after the enter the exec ran from, which
//     is the re-executed one, not after the row's -513 exit.
func (e *eventLoop) lostExecCaller(exit *types.RetEvent) (tid uint32, proven, ok bool) {
	if tid, ok = e.pairs.parkedExecCaller(exit.Pid); ok {
		parked, _ := e.pairs.pending(tid)
		if ok, proven = e.lostExecRecord(parked.EnterEv.GetTime(), exit.GetTime()); !ok {
			e.pairs.indexExecCaller(parked.EnterEv)
			return 0, false, false
		}
		return tid, proven, true
	}
	if tid, ok = e.restarts.reexecutingExecCaller(exit); !ok {
		return 0, false, false
	}
	held, _ := e.restarts.lookup(tid)
	ok, proven = e.lostExecRecord(held.continuation.GetTime(), exit.GetTime())
	return tid, proven, ok
}

// completeUntracedExec finishes a traced thread's successful execve whose
// exit ior will never see, using the sched_process_exec record as its exit.
//
// BPF sets ExitUntraced only under -tid <non-leader> when that very thread
// exec'd (ior_exec_record_scope in internal/c/exec.c): the execve entered
// under the traced tid, but after de_thread() it returns under the leader's
// tid, which the kernel-side tid filter rejects, so no sys_exit record
// arrives. Without this the enter stayed parked until LRU trimming and the
// thread's last traced syscall was never shown; at a sampling rate N the
// emitted invocation was not counted anywhere either, since BPF leaves an
// emitted enter to userspace (ior_on_exec_tid_change).
//
// sched_process_exec only fires once the exec is past its point of no return,
// so the execve returns 0; its record's timestamp stands in for the exit's.
// The duration therefore ends at the tracepoint, a little before the syscall
// actually returns (the remaining tail is bprm teardown and the return to
// user mode). rekeyExecCaller has already moved the enter to ev.Tid, so the
// synthetic exit carries that tid and takes the ordinary exit path: exec
// target handling, pair filters, gap bookkeeping. The row keeps the caller's
// tid from the enter, like every non-leader execve row.
//
// Only a parked execve/execveat enter is completed. If there is none (execve
// not traced, the enter filtered or trimmed), there is nothing to report.
// Tracing of the thread ends here: its post-exec syscalls run under the
// filtered leader tid.
func (e *eventLoop) completeUntracedExec(ev *types.ProcessExecEvent, ch chan<- *event.Pair) {
	pair, ok := e.pairs.pending(ev.Tid)
	if !ok {
		return
	}
	exitTraceID, ok := execExitTraceID(pair.EnterEv.GetTraceId())
	if !ok {
		return
	}
	e.tracepointExited(&types.RetEvent{
		EventType: types.EXIT_RET_EVENT,
		TraceId:   exitTraceID,
		Time:      ev.Time,
		Ret:       0,
		Pid:       ev.Pid,
		Tid:       ev.Tid,
		RetType:   types.UNCLASSIFIED,
	}, ch)
}

// execExitTraceID maps an exec-family enter trace id to its exit's. Any other
// syscall reports false: only an execve/execveat can be completed by an exec
// record.
func execExitTraceID(enter types.TraceId) (types.TraceId, bool) {
	switch enter {
	case types.SYS_ENTER_EXECVE:
		return types.SYS_EXIT_EXECVE, true
	case types.SYS_ENTER_EXECVEAT:
		return types.SYS_EXIT_EXECVEAT, true
	default:
		return 0, false
	}
}
