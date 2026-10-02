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
// It runs first of all in handleProcessExecEvent: before rekeyExecCaller, so
// the enter parked again is there to be moved, and before the FD_CLOEXEC
// eviction, so that enter's target is resolved against the descriptors the
// process had when it entered the execve (storeEnter).
func (e *eventLoop) releaseExecCallerRestart(ev *types.ProcessExecEvent, ch chan<- *event.Pair) {
	if !execChangedTid(ev) {
		return
	}
	e.releaseHeldRestart(ev.OldTid, ch)
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
// recycled owner. (The handle NAMES are not per-tid state and stay: a handle
// is as valid after the exec as before, see handleTracker.)
func (e *eventLoop) applyExecTidChange(oldTid, newTid uint32) {
	e.pairs.moveExecCaller(oldTid, newTid)
	e.evictCachedComm(oldTid)
	handles := e.handleState()
	handles.dropTaken(oldTid)
	handles.dropTaken(newTid)
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
// way. The held-row lookup has the residual of the parked one: adopting the
// wrong thread needs the exec record AND a killed sibling's exit record to be
// lost, or a leader's own successful execve exit that finds no parked enter
// (its enter record lost to backpressure, the enter trimmed from the pending
// table, or the execve already in flight when the probes attached) while a
// killed sibling's row is still held for want of its exit record. A displaced
// enter is not such a case: the enter that displaced it pairs with the exit
// (a trace-ID mismatch), and this function is not asked.
//
// One stream never gets here at all. Records are routed by their own tid
// first (routeHeldRestart), so when the dead leader still holds a row with a
// kept continuation enter - its exit record lost as well as the exec record -
// the execve's exit under the leader tid is taken for that row's business:
// the leader's enter is parked again and the exit pairs with it. That is a
// trace-ID mismatch (no row for the exec), or, when the leader's kept enter
// is an execve too, a successful execve row under the dead leader's enter;
// either way the exit has an enter, this fallback is not asked, and the real
// caller's -513 row stays held until the loop stops or its tid is reused.
// Accepted: it takes two lost records and a leader interrupted mid-fold.
func (e *eventLoop) adoptLostExecCaller(exitEv event.Event, ch chan<- *event.Pair) (*event.Pair, bool) {
	ret, ok := exitEv.(*types.RetEvent)
	if !ok || ret.Ret != 0 || ret.Tid != ret.Pid {
		return nil, false
	}
	if ret.TraceId != types.SYS_EXIT_EXECVE && ret.TraceId != types.SYS_EXIT_EXECVEAT {
		return nil, false
	}
	callerTid, ok := e.pairs.parkedExecCaller(ret.Pid)
	if !ok {
		callerTid, ok = e.restarts.reexecutingExecCaller(ret)
	}
	if !ok {
		return nil, false
	}
	e.releaseHeldRestart(callerTid, ch)
	e.applyExecTidChange(callerTid, ret.Tid)
	return e.pairs.consume(ret.Tid)
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
