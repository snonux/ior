package internal

import "ior/internal/types"

// The clone(2) flags that decide what a new task shares with its creator
// (include/uapi/linux/sched.h); the same values the BPF handler tests
// (IOR_CLONE_THREAD in internal/c/exec.c).
const (
	cloneFlagFiles  = 0x00000400 // CLONE_FILES: share the descriptor table
	cloneFlagThread = 0x00010000 // CLONE_THREAD: join the creator's thread group
)

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
// comm check, which matches no ordinary -comm pattern (only ^$, ^ and $ match
// an empty comm), so those rows never reached any output (before task dr2 the
// enter of a non-open/exec syscall was dropped outright, which also lost the
// thread's fd-table changes).
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
// The record also carries what a new *process* inherits (inheritFdTable, task
// gr2): the fd table is keyed by tgid, so a fork()ed child used to start empty
// and every inherited descriptor fell back to procfs, which renames it. A record
// flagged ChildOutOfScope (task hr2) is handled before any of the above: it
// stands for a task the trace does not follow and only blinds the creator's
// table.
func (e *eventLoop) handleTaskNewtaskEvent(ev *types.TaskNewtaskEvent) {
	defer ev.Recycle()
	if ev.ChildOutOfScope() {
		// Not a task of this trace: only its effect on the creator's table matters
		// (see inheritFdTable). Nothing of the child's - comm, per-tid state -
		// is cached, and its tid is not retired: the filter never lets any of its
		// records through, so there is nothing to seed or to keep from leaking.
		if ev.CreatorPid != 0 {
			e.fdState().markBlind(ev.CreatorPid)
		}
		return
	}
	e.retireRecycledTid(ev.Tid)
	e.inheritFdTable(ev)
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

// inheritFdTable models what the kernel does with the descriptor table of a new
// task, from the record's clone flags:
//
//   - CLONE_THREAD: the thread joins its creator's process and shares its
//     table. The table is keyed by tgid, so the thread already reads and writes
//     the creator's entries; nothing to do, and above all nothing to drop (the
//     child's pid is the live creator's).
//   - a new process without CLONE_FILES (fork, vfork, plain clone): the child
//     gets a *copy* of the creator's table, made by the kernel inside clone, so
//     the creator's entries as of this record (ring-buffer order) are the
//     child's entries (fdTracker.inherit; only for a parent tracking at most
//     maxInheritedEntries entries, a larger table costs too much per fork and
//     its children fall back to procfs). This is the case gr2 fixed: without it
//     the child's inherited descriptors degrade to procfs names (pipe:0:3:4 ->
//     pipe:[N], memfd:x -> /memfd:x (deleted)) and, once the child has exited
//     before the lazy read, to E:name.
//   - a new process with CLONE_FILES: the table is *shared* between two tgids
//     (task hr2): the child is pointed at the creator's table (shareTable), so
//     what either process opens, closes or dup2()s is what both see. Until hr2
//     the child started with no entries, and the creator's entries went stale on
//     the child's first close/open of a shared number, mislabelling every later
//     row of that number. It is rare (a clone without fork semantics, never
//     plain fork()/vfork()/posix_spawn()).
//
// A record with no creator (CreatorPid 0: an object that predates the field, see
// NewTaskNewtaskEventFast) cannot name the table to copy or share: the child
// starts empty, the old behaviour. A new process's stale entries from a dead
// previous owner of its tgid are dropped in every non-thread case.
//
// Scope: a record is emitted for a child that is in scope (see
// ior_newtask_in_scope), so under -pid the fork()ed children of the target, which
// are not traced, cost nothing here. The one record for an out-of-scope child
// (ChildOutOfScope) never reaches this function: handleTaskNewtaskEvent turns it
// into fdTracker.markBlind on the creator.
func (e *eventLoop) inheritFdTable(ev *types.TaskNewtaskEvent) {
	if ev.CloneFlags&cloneFlagThread != 0 {
		return
	}
	fds := e.fdState()
	switch {
	case ev.CreatorPid == 0:
		// Only the dead previous owner's entries are dropped: nothing to copy.
		fds.deletePid(ev.Pid)
	case ev.CloneFlags&cloneFlagFiles != 0:
		fds.shareTable(ev.Pid, ev.CreatorPid)
	default:
		fds.inherit(ev.CreatorPid, ev.Pid)
	}
}
