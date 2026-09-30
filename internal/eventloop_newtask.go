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
// was silent and total: tracepointEntered recycles a non-open/exec enter whose
// tid has no cached comm yet, so those rows never reached any output.
//
// The record is emitted from the creating task's context before the child is
// first woken, so it precedes every syscall the child can make; the ring buffer
// delivers records in reservation order to a single consumer goroutine, which is
// what makes the cache write land before the child's first pair (the same
// argument as for handleProcessExecEvent). The write goes through
// setCachedCommFromKernel, so it is authoritative: it bumps the tid's rename
// generation, retiring a procfs lookup already in flight for a recycled tid
// whose earlier owner's exit record was lost, and replaces a stale entry that
// owner left behind.
//
// The inherited name is the parent's. A fork that then execve()s is renamed by
// the sched_process_exec record, which arrives after this one; a bare thread
// keeps the name until it renames itself (prctl(PR_SET_NAME)), which no
// tracepoint reports - the same limitation the cache always had.
//
// An empty comm carries no information and is ignored, keeping whatever is
// cached. A lost record (ring-buffer backpressure, counted in ringbuf_drop_map)
// or a failed probe attach degrades to the old procfs lookup, i.e. exactly the
// behaviour before this record existed.
//
// ev.CloneFlags is not consumed here yet: it is carried so fd-table
// inheritance and shared-table tracking can be built on the same record.
func (e *eventLoop) handleTaskNewtaskEvent(ev *types.TaskNewtaskEvent) {
	defer ev.Recycle()
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		return
	}
	e.setCachedCommFromKernel(ev.Tid, comm)
}
