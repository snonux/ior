package internal

import (
	"ior/internal/types"
)

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
// pools). The task_rename record (handleTaskRenameEvent, task lr2) reports such
// a rename authoritatively and in ring-buffer order, which is what normally
// names the thread correctly from its first row. The seed still has to be
// correctable without it, because that record can be lost or its probe may not
// have attached, and writing the seed as authoritative would bump the tid's
// rename generation, discard every later procfs result and pin the parent's
// name on such a thread for good - hiding its rows from -comm <renamed>. As a
// provisional entry it can be flagged stale instead: the first use of the tid
// then queues one /proc/<tid>/comm read whose result replaces it. Rows emitted
// before that read lands still carry the inherited name (and under -comm are
// matched against it), which is what the base behaviour had too: it had no name
// at all until the read landed. An exec, rename or open record that arrives
// meanwhile is authoritative and still outranks the read. Whether the read is
// needed at all is provisionalSeedNeedsRecheck's call (task xr2): when a
// rename is reported or its loss detected as a drop, it is skipped (with the
// exceptions listed there).
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
// owner's last syscall, and a name_to_handle_at handle still parked for its
// exit record. It is retired before the seed is written, and regardless of
// whether the record carries a usable comm.
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
		// A row a dead previous owner of the tid still held has been released by
		// now, without parking its continuation's enter under the tid
		// (routeHeldRestart, reportsTaskGone): nothing here would evict it.
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
	e.setCachedCommProvisional(ev.Tid, comm, e.provisionalSeedNeedsRecheck(ev.Time))
}

// provisionalSeedNeedsRecheck decides whether the inherited name a task_newtask
// record seeds (recorded at seedTime, the record's bpf_ktime_get_boot_ns) needs
// the one corrective /proc/<tid>/comm read (task xr2).
//
// The read exists for a rename that userspace would otherwise never hear of.
// With renameRecordsTrusted (the task_rename probe attached and the ring-buffer
// drop counter monitored, see trustRenameRecords) such a rename normally
// arrives as a record, which outranks the seed, or its record was lost, which
// the drop monitor detects and answers with a markAllStale sweep that flags
// the seed for the same one read. Skipping the read then saves exactly what
// churn workloads paid for it - one lookup per new thread, which almost always
// failed with ENOENT because the thread had already exited.
//
// Three cases keep the read even then:
//
//   - The drop counter's latest read failed (ringbufDropReadFailed). A lost
//     rename could not show up as a drop while the counter stays unreadable, so
//     nothing would sweep the seed. A one-off failure costs only the reads of
//     the seeds consumed meanwhile: the counter is cumulative, so the next
//     successful poll reports the drops of the failed interval and stamps
//     lastDropSeenBootNs past their records.
//   - The seed may predate a reported drop. The sweep only flags entries that
//     exist when the event loop applies it, but the loop consumes a backlog: a
//     newtask record reserved *before* a drop the monitor has already reported
//     can still be in the ring when the sweep runs, and its seed, written
//     afterwards, would escape it while the lost record (a rename of that very
//     thread) is gone for good. lastDropSeenBootNs is the boot-clock time of
//     the newest poll that saw drops, taken after the counter read, so every
//     record lost before it was reserved earlier still; a seed whose record is
//     no newer than that keeps the read. A seed recorded after that poll is
//     covered by the next poll's sweep, or by this check once that poll has
//     moved lastDropSeenBootNs past it.
//   - Trust is off (probe not attached, or no drop monitor).
//
// What the trust does not cover (all rare; the wrong name stays until the
// thread execs, renames again, or makes an open/exec syscall whose payload
// comm contradicts the cache):
//
//   - Two microsecond-wide windows inside copy_process: a third thread writing
//     /proc/<tid>/comm of the child between attach_pid and trace_task_newtask
//     emits its rename record before the newtask record, whose seed then
//     overwrites the newer name with the creator's; and a sibling renaming the
//     creator between dup_task_struct and the tracepoint makes the record carry
//     a name the child never had. Before task xr2 the corrective read healed
//     both.
func (e *eventLoop) provisionalSeedNeedsRecheck(seedTime uint64) bool {
	if !e.renameRecordsTrusted || e.ringbufDropReadFailed.Load() {
		return true
	}
	// Record time vs a user-space boot-clock reading. bootClockNs takes a
	// time namespace's boottime offset out of the reading, so both are on the
	// host's boot clock (bootclock.go; fdTracker.cacheReadBefore likewise).
	return seedTime <= e.lastDropSeenBootNs.Load()
}

// trustRenameRecords tells the loop whether the task_rename probe attached for
// this run (trace setup, before the loop starts). Rename records count as
// complete only when ring-buffer drops are monitored too (dropSrc): a lost
// record is then detected and swept (markAllStale), whereas without the
// monitor it would be lost silently. See provisionalSeedNeedsRecheck.
func (e *eventLoop) trustRenameRecords(renameProbeAttached bool) {
	e.renameRecordsTrusted = renameProbeAttached && e.dropSrc != nil
}

// retireRecycledTid drops the per-tid state a previous owner of tid left behind
// when its exit record never arrived (see handleProcessExitEvent for what each
// piece is and why it must not reach the next owner).
func (e *eventLoop) retireRecycledTid(tid uint32) {
	e.evictCachedComm(tid)
	e.pairs.evictTid(tid)
	e.handleState().dropTaken(tid)
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
// ior_task_in_scope), so under -pid the fork()ed children of the target, which
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
