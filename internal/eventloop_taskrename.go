package internal

import "ior/internal/types"

// handleTaskRenameEvent applies a rename a task performed on itself (or that a
// sibling thread performed on it) to the comm cache, as reported by the kernel's
// task:task_rename tracepoint (internal/c/exec.c).
//
// Before this record only two things ever changed a cached name after it was
// first resolved: the exec record and the payload comm of an open or exec
// enter. A rename through prctl(PR_SET_NAME) or pthread_setname_np (a write to
// /proc/<pid>/task/<tid>/comm) is neither, so
// the cache kept serving the old name until an openat of that thread happened to
// heal it. Every row in between carried the wrong comm, and under -comm the
// filter inverted: -comm <new name> dropped the renamed thread's rows, and
// -comm <old name> kept admitting them. An openat dropped at the enter-side gate
// could not heal the cache either, so the wrong name could outlive the thread.
//
// The record is emitted by the renaming syscall itself (or the /proc write), in
// ring-buffer order with that task's syscall records (the same argument as for
// handleProcessExecEvent), so a row's label depends on when the row is labelled:
//
//   - Most kinds take the label when the pair completes, at the syscall's exit
//     (ep.Comm = e.comm(tid)). A syscall that entered before the rename record
//     and exits after it is therefore labelled with the NEW name, which is also
//     what task->comm reads at its exit. The prctl syscall's own row pairs after
//     the record, so it carries the new name too.
//   - The open kinds and execve carry the kernel's comm from their ENTER record
//     (ep.Comm = openEv.Comm / execEv.Comm): an open that entered before the
//     rename keeps the old name on its own row even when it exits after it.
//   - The cache itself always ends up with the newest name in ring order: the
//     enter payload is applied when the enter is consumed
//     (seedCommFromEnterPayload), not at the exit, so a rename between an
//     open's enter and exit is not overwritten with the pre-rename payload.
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
