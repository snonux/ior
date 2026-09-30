package internal

import "ior/internal/types"

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
// (pairTracker.moveExecCaller also drops a leftover for a lost exit record).
//
// The row keeps the caller's tid (the enter's), since that is the thread that
// made the call; only the pairing key moves. Everything else keyed by the
// pre-exec tid is dropped rather than moved: its comm is the pre-exec name,
// which this record replaces for ev.Tid anyway, and a pathname parked by
// name_to_handle_at belongs to the old program. No thread will ever report
// under ev.OldTid again - the number was released with the dead leader - so
// leaving the entries behind would only wait for a recycled owner to inherit
// them.
//
// OldTid 0 never comes from the kernel (old_pid is a real task's tid) and is
// treated as "tid kept", so records built without the field (tests, synthetic
// replays) keep their old meaning.
func (e *eventLoop) rekeyExecCaller(ev *types.ProcessExecEvent) {
	if ev.OldTid == 0 || ev.OldTid == ev.Tid {
		return
	}
	e.pairs.moveExecCaller(ev.OldTid, ev.Tid)
	e.evictCachedComm(ev.OldTid)
	e.pendingHandleState().delete(ev.OldTid)
}
