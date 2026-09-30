package internal

import "ior/internal/types"

// handleTaskNewtaskEvent seeds the comm cache with the name a freshly created
// task (a forked process or a new thread) inherited, as reported by the
// kernel's task:task_newtask tracepoint (internal/c/exec.c).
//
// Before this record a new tid's comm was resolved on first use from an
// asynchronous /proc/<tid>/comm read, which loses the race against short-lived
// tasks in two ways. A thread that has exited by the time a lookup worker gets
// to it has no /proc entry, so every row it produced was labelled with an empty
// comm; and even a thread that lives on had its first rows (whatever the event
// loop emitted before the lookup landed) labelled empty. Under -comm the loss
// was silent and total: a tid with no cached comm carries "" into the exit-side
// comm check, which matches no -comm pattern, so those rows never reached any
// output (before task dr2 the enter of a non-open/exec syscall was dropped
// outright, which also lost the thread's fd-table changes).
//
// The record is emitted from the creating task's context before the child is
// first woken, so it precedes every syscall the child can make; the ring buffer
// delivers records in reservation order to a single consumer goroutine, which is
// what makes the cache write land before the child's first pair (the same
// argument as for handleProcessExecEvent).
//
// The seeded name is provisional, not authoritative (setCachedProvisional). It
// is the *creator's* name, and a new thread very often renames itself at once
// (prctl(PR_SET_NAME), pthread_setname_np: tokio, Java, Chrome and Bun worker
// pools), which no tracepoint reports. Writing it as authoritative bumped the
// tid's rename generation and so discarded every later procfs result, pinning
// the parent's name on such a thread for good - and hiding its rows from
// -comm <renamed>. As a provisional entry it is flagged stale instead: the
// first use of the tid queues one /proc/<tid>/comm read whose result replaces
// it, so a thread that renamed itself before its first traced syscall is
// labelled with its own name from then on. Rows emitted before that read lands
// still carry the inherited name (and under -comm are matched against it), which
// is what the base behaviour had too: it had no name at all until the read
// landed. An exec or open record that arrives meanwhile is authoritative and
// still outranks the read. A rename that happens later than the first traced
// syscall is not observed by anything (task lr2).
//
// A fork that then execve()s is renamed by the sched_process_exec record, which
// arrives after this one and needs no read at all.
//
// The record also says the tid is a brand-new task, so whatever the cache and
// the trackers still hold for that number belongs to a dead owner whose exit
// record was lost (ring-buffer backpressure) - the same state
// handleProcessExitEvent retires: the cached name (which also retires a procfs
// lookup already in flight for the old owner), a parked syscall enter that the
// new owner's own exit would otherwise pair with (a row for a syscall that never
// happened, with a fabricated latency), the -gap baseline of the previous
// owner's last syscall, and an unconsumed name_to_handle_at pathname. It is
// retired before the seed is written, and regardless of whether the record
// carries a usable comm.
//
// An empty comm carries no name: nothing is seeded and the tid falls back to
// the procfs lookup on first use. A lost record or a failed probe attach
// degrades the same way, i.e. exactly the behaviour before this record existed.
//
// ev.CloneFlags is not consumed here yet: it is carried so fd-table
// inheritance and shared-table tracking can be built on the same record.
func (e *eventLoop) handleTaskNewtaskEvent(ev *types.TaskNewtaskEvent) {
	defer ev.Recycle()
	e.retireRecycledTid(ev.Tid)
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		return
	}
	e.setCachedCommProvisional(ev.Tid, comm)
}

// retireRecycledTid drops the per-tid state a previous owner of tid left behind
// when its exit record never arrived (see handleProcessExitEvent for what each
// piece is and why it must not reach the next owner).
func (e *eventLoop) retireRecycledTid(tid uint32) {
	e.evictCachedComm(tid)
	e.pairs.evictTid(tid)
	e.pendingHandleState().delete(tid)
}
