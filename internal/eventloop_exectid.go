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
// enter parked under the caller's; adoptLostExecCaller recovers that pair.
//
// OldTid 0 never comes from the kernel (old_pid is a real task's tid) and is
// treated as "tid kept", so records built without the field (tests, synthetic
// replays) keep their old meaning.
func (e *eventLoop) rekeyExecCaller(ev *types.ProcessExecEvent) {
	if ev.OldTid == 0 || ev.OldTid == ev.Tid {
		return
	}
	e.applyExecTidChange(ev.OldTid, ev.Tid)
}

// applyExecTidChange moves a non-leader exec's per-tid state from the caller's
// tid (oldTid) to the leader tid (newTid) it continues under.
//
// The parked execve enter and its gap baseline move (pairTracker.moveExecCaller);
// the row keeps the caller's tid (the enter's), since that is the thread that
// made the call, and only the pairing key changes. Everything else is
// dropped for both tids rather than moved. Under oldTid: its comm is the
// pre-exec name, which the exec record replaces for newTid anyway, and a
// pathname parked by name_to_handle_at belongs to the old program. Under
// newTid: whatever is still there belongs to the dead leader (its exit record
// normally evicted it; this covers a lost one), and a leader's parked
// name_to_handle_at pathname must not be consumed by the new program's first
// open_by_handle_at. No thread will ever report under oldTid again - the number
// was released with the dead leader - so leaving entries behind would only
// wait for a recycled owner to inherit them.
func (e *eventLoop) applyExecTidChange(oldTid, newTid uint32) {
	e.pairs.moveExecCaller(oldTid, newTid)
	e.evictCachedComm(oldTid)
	handles := e.pendingHandleState()
	handles.delete(oldTid)
	handles.delete(newTid)
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
func (e *eventLoop) adoptLostExecCaller(exitEv event.Event) (*event.Pair, bool) {
	ret, ok := exitEv.(*types.RetEvent)
	if !ok || ret.Ret != 0 || ret.Tid != ret.Pid {
		return nil, false
	}
	if ret.TraceId != types.SYS_EXIT_EXECVE && ret.TraceId != types.SYS_EXIT_EXECVEAT {
		return nil, false
	}
	callerTid, ok := e.pairs.parkedExecCaller(ret.Pid)
	if !ok {
		return nil, false
	}
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
