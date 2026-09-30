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
// Residual ambiguity: two threads of one process parked in execve at once
// (one of them loses the race and is killed by de_thread) with the winner's
// own enter lost too could adopt the loser's enter. That needs two lost
// records in one exec and yields a row with the loser's filename; it is
// accepted over losing every non-leader exec whose record was dropped.
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
