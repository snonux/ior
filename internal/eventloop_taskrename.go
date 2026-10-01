package internal

import "ior/internal/types"

// handleTaskRenameEvent applies a rename a task performed on itself (or that a
// sibling thread performed on it) to the comm cache, as reported by the kernel's
// task:task_rename tracepoint (internal/c/exec.c).
//
// Before this record only three things ever changed a cached name after it was
// first resolved: the exec record, an open event's payload comm and a failed
// execve's payload comm. A rename through prctl(PR_SET_NAME) or
// pthread_setname_np (a write to /proc/<pid>/task/<tid>/comm) is none of them, so
// the cache kept serving the old name until an openat of that thread happened to
// heal it. Every row in between carried the wrong comm, and under -comm the
// filter inverted: -comm <new name> dropped the renamed thread's rows, and
// -comm <old name> kept admitting them. An openat dropped at the enter-side gate
// could not heal the cache either, so the wrong name could outlive the thread.
//
// The record is emitted by the renaming syscall itself (or the /proc write), in
// ring-buffer order with that task's syscall records, so it applies after the
// rows the task produced under its old name and before the ones it produces
// under the new one (the same argument as for handleProcessExecEvent). The
// prctl syscall's own row pairs after the record and is therefore labelled with
// the new name, which is also what the kernel's task->comm reads from then on.
//
// The write goes through setCachedCommFromKernel, so it is authoritative: it
// bumps the tid's rename generation and a procfs lookup that read the old name
// and lands later cannot undo it, and it clears the stale flag of a provisional
// entry (setCachedCommProvisional) because the fresh name makes the one
// corrective /proc read pointless. The tid is the *renamed* task's - a
// /proc/<tid>/comm write renames a sibling thread, not the writer.
//
// The kernel also fires task_rename inside execve (begin_new_exec); that
// repeats, before the sched_process_exec record, the name the exec record is
// about to set, so applying both is harmless.
//
// An empty comm carries no name and is ignored, keeping whatever is cached. A
// lost record (ring-buffer backpressure, counted in ringbuf_drop_map) or a failed
// probe attach degrades to the previous behaviour: the old name is served until
// something else corrects it.
func (e *eventLoop) handleTaskRenameEvent(ev *types.TaskRenameEvent) {
	defer ev.Recycle()
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		return
	}
	e.setCachedCommFromKernel(ev.Tid, comm)
}
