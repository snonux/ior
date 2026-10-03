package internal

import (
	"ior/internal/statsengine"
	"ior/internal/types"
)

// handleProcessExitEvent applies a sched:sched_process_exit control record to
// the pieces of state that would otherwise outlive the task the kernel just
// reported dead, and reports whole-process exits to the stats engine.
//
// The fd table: when the record says the whole thread group is dead
// (ev.IsGroupDead), every (pid, fd) entry of tgid ev.Pid is dropped from the
// fdTracker and its procfs cache. Without this, descriptors of dead processes
// lingered in the table until LRU eviction - stale garbage for any fd number
// they ever held, and unbounded growth on process-churning traces (see the
// note on defaultMaxFdTableEntries). A record for a thread whose siblings
// still live leaves the table alone: the descriptors belong to the process,
// which still holds them.
//
// The scoped handle names: a name a name_to_handle_at filed for the opens of
// its own process only (a relative pathname, a descriptor name; see
// handleTracker) is keyed by that tgid, and goes with the fd table, on the
// same record and for the same reason: the next process handed the number
// would be named by it (dropProcessState).
//
// The comm cache: it is keyed by tid, and tids are recycled, so the entry for
// ev.Tid would otherwise label the *next* process handed that tid number with
// the dead one's program name until it exec'd or aged out of the LRU
// (commResolver.evictTid).
//
// The pair tracker: pairTracker.enters and pairTracker.prevTimes are keyed by
// tid too, and the enter is the sharper of the two. A task killed inside a
// syscall never gets its sys_exit, so its enter stays parked; the next task
// handed that tid number then has its own exit consume that enter, and the
// emitted row carries the dead task's filename, arguments and enter timestamp
// under the new owner's identity - a row for a syscall that never happened,
// with a latency as long as the gap between the two tasks. The enter/exit
// trace-ID guard in tracepointExited does not catch it, because a recycled tid
// running the same syscall produces perfectly matching IDs. prevTimes is the
// milder half: it gives the new owner's first pair a DurationToPrev measured
// from the dead task's last syscall, which -gap filters on
// (pairTracker.evictTid drops both).
//
// The parked enter is dropped, not emitted as an unpaired or synthetic row.
// There is nothing truthful to emit: the syscall never returned, so it has no
// return value, no transferred bytes and no latency, and every consumer
// downstream of the event loop reads Pair.ExitEv. The nearest available
// timestamp is this record's own - the moment the task died, not the moment
// the syscall completed - and using it would manufacture exactly the fabricated
// latency this eviction exists to prevent. An unfinished syscall is genuinely
// absent from the trace, the same way it already is when the enter falls off
// the pending-enter LRU or when the run ends with enters still parked.
//
// The drop is deliberately not counted anywhere. Nothing already tallied
// disappears: numTracepoints counted the enter record when it was seen, and
// numSyscalls is only reached by a pair that found its enter. Nor is it an
// enter without an exit (numEntersWithoutExit, task c23): that counts exit
// records the kernel lost, and this exit never existed.
//
// It is emphatically not a mismatch. numTracepointMismatches means the tracker
// paired two records that do not belong together, and a task killed inside a
// syscall is ordinary kernel behaviour - counting it there would inflate the
// health percentage stats() prints and mask a real pairing regression behind
// routine traffic. This eviction in fact *removes* false positives from that
// counter, which is the strongest argument for keeping them apart: a killed
// task's enter that survived would be consumed by the recycled tid's exit of
// a *different* syscall whenever that tid's own enter was lost (ring-buffer
// loss, below), and be counted as a mismatch. Routing eviction drops into the
// same counter would have cancelled that improvement rather than measured
// anything. (The noreturn syscalls exit/exit_group/rt_sigreturn used to be the
// common source of such parked enters - they have no exit handler at all - but
// they are no longer parked: completeNoReturnEnter emits their row at enter,
// task pr2. That row is not the synthetic row this eviction refuses to
// fabricate: a noreturn syscall is complete at enter by definition and its
// row carries the enter's own timestamp and no latency, whereas the enter
// dropped here belongs to a call that was cut short and never completed.)
//
// An enter can die unpaired four ways - here, superseded in set() when an exit
// record is lost, trimmed from the pending-enter LRU, and left parked at end
// of run. Only the second is counted, as an enter without an exit
// (eventloop_losthalves.go): a sum of all four would mix a kernel fact (tasks
// die inside syscalls, calls are in flight at the stop) and the tracer's own
// bound with a tracer symptom (records were lost), and a reader could not act
// on it.
//
// sched_process_exit fires per *task*, which lands differently on the four:
//   - For the fd table, keyed by tgid, per-task is the wrong granularity, so
//     the BPF handler flags the exit that ends the thread group (group_dead,
//     see ior_exit_group_dead in internal/c/exec.c) and only that one
//     evicts. Evicting on every thread exit, as this used to, was not merely
//     degraded: the next syscall on a surviving descriptor went through the
//     procfs fallback (/proc/<pid>/fd), which renames it (pipe:0:3:4 becomes
//     pipe:[N], splitting one fd's rows across names in aggregates and -path
//     filters), yields nothing for an fd closed in the meantime, and under
//     event-loop lag can resolve a reused fd number to the wrong file.
//   - For the comm cache, the pair tracker and the handle tracker's parked
//     handles, all keyed by tid, per-task is exactly the right granularity:
//     only the name, parked enter, gap baseline and parked name_to_handle_at
//     handle of the thread that actually died are dropped, and its siblings
//     keep theirs.
//
// The stats engine: a group-dead exit also ends the process's row in the
// Processes table (retireStatsProcess), so a later process handed the same
// PID gets a row and label of its own. A thread exit does not, for the same
// reason it does not evict fds.
//
// The traced target (tasks vr2, os2): in a headless run the record can also
// end the trace. Last of all, once every tid-keyed piece above is retired,
// endTraceOnTargetThreadExit ends a -tid trace on the traced thread's own
// exit record, or on the group-dead record of the process whose leader tid is
// traced, unless the BPF side flagged the tid as inherited by a sibling's
// execve (TidInherited: the exec'd program runs on under the traced tid). The
// -pid process's group-dead record ends the trace from applyProcessDeath. The
// TUI is never ended this way.
//
// A legacy record from a pre-group_dead IOR_BPF_OBJECT override does not say
// whether the process died (ev.IsGroupDeadKnown is false); see
// applyProcessDeath for how the two halves treat it.
//
// A record lost to ring-buffer backpressure simply never evicts (counted in
// ringbuf_drop_map like every other record); the stale entries linger until
// the LRU cap trims them, which is the same trade the procfs cache already
// makes per (pid, fd). Losing the one group-dead record of a process has the
// same effect for its fd entries.
func (e *eventLoop) handleProcessExitEvent(ev *types.ProcessExitEvent) {
	defer ev.Recycle()
	e.applyProcessDeath(ev)
	e.evictCachedComm(ev.Tid)
	// Neither of these guards tid == 0 the way commResolver.evictTid does:
	// there the guard exists because a zero tid is the resolver's "unknown"
	// sentinel, while here it is simply a key no live task uses, so deleting
	// it is a no-op rather than a hazard.
	e.pairs.evictTid(ev.Tid)
	// A handle a name_to_handle_at of this task returned is parked under the
	// tid until the call's exit record claims it; if that record was lost the
	// entry would wait for the recycled tid. It could not mislabel anything
	// there - a claim needs the exit record's exact time - so this is
	// hygiene. The handle NAMES are not this thread's: an absolute one is
	// keyed by the handle alone, which a task routinely takes for another
	// thread or process to open and which stays valid after the task that
	// took it is gone, and a scoped one belongs to the process and goes when
	// the whole thread group has (applyProcessDeath, dropProcessState).
	e.handleState().dropTaken(ev.Tid)
	// The registered-ring table is the thread's and ends with it (the kernel
	// releases it in do_exit); kept, it would name the rows of the tid's
	// next owner.
	e.ringState().dropThread(ev.Tid)
	// Last: every piece of state the exit retires is gone before a -tid trace
	// is told to end, so the shutdown statistics see the final picture (the
	// -pid half does the same at the end of applyProcessDeath). An inherited
	// tid (a sibling's execve took it over) ends nothing; see
	// endTraceOnTargetThreadExit.
	e.endTraceOnTargetThreadExit(ev)
}

// applyProcessDeath performs the tgid-keyed half of an exit record: eviction
// of the process's state (dropProcessState: fd table, program break, scoped
// handle names), the group-dead counter, stats retirement and, for the -pid
// target of a headless run, ending the trace (endTraceOnTargetExit).
//
// Which record means "the process is gone" is the kernel's group_dead flag,
// not the leader's exit: a leader that calls pthread_exit dies first and
// leaves its threads running under the same tgid, with the same descriptors
// and working directory, and a non-leader execve keeps the tgid as well.
//
// A known group-dead record does all of it. A record whose flag is unknown
// (legacy 24-byte layout) still evicts that state, as every exit did before
// group_dead existed: keeping it would leave a dead process's descriptors
// until LRU trimming, while a wrong eviction only costs the surviving
// threads a /proc/<pid>/fd fallback (and, for a scoped handle name, the
// procfs fallback of an unknown handle). It neither counts nor retires,
// though: retiring on every thread exit would split a live multi-threaded
// process into one Processes-table lifetime row per exited thread, and the
// counter reports only exits the kernel confirmed as whole-process.
func (e *eventLoop) applyProcessDeath(ev *types.ProcessExitEvent) {
	if !ev.IsGroupDead() {
		if !ev.IsGroupDeadKnown() {
			e.dropProcessState(ev.Pid)
		}
		return
	}
	// A repeat record of a death already handled has nothing left to do.
	if e.isDuplicateGroupDead(ev) {
		return
	}
	// Counted for the end-of-run statistics: it makes the whole-process
	// exits that reached userspace observable, including those of untraced
	// threads forwarded by the -tid bypass (ior_process_exit_in_scope).
	e.numGroupDeadExits++
	e.dropProcessState(ev.Pid)
	e.retireStatsProcess(ev.Pid)
	// Last: the process's state is fully retired before the trace is told to
	// end, so the shutdown statistics see the final picture.
	e.endTraceOnTargetExit(ev)
}

// dropProcessState forgets what is keyed by the process pid and means
// nothing once that process is gone: its descriptor table, its program break
// and the handle names scoped to it (task 523). The three go together so
// that "the process is gone" is decided in one place for all of them; a new
// process's leftovers from a lost exit record are cleared the same way when
// its number comes up again (inheritFdTable, retireRecycledPid).
//
// An execve is not such an end, and drops no scoped name
// (handleProcessExecEvent): the new program runs under the same tgid in the
// same working directory, so a relative pathname still names the same file,
// and a descriptor name ("memfd:x") is what ior called the file the handle
// belongs to, which the handle still opens whether or not the descriptor it
// was taken through survived the exec.
func (e *eventLoop) dropProcessState(pid uint32) {
	e.fdState().deletePid(pid)
	e.brkState.forget(pid)
	e.handleState().dropScoped(pid)
}

// isDuplicateGroupDead reports whether ev repeats the group-dead record of a
// process death already handled, and remembers ev otherwise.
//
// Kernels whose sched_process_exit tracepoint lacks a group_dead field make
// the BPF side derive it from signal->live == 0 (ior_exit_group_dead in
// internal/c/exec.c). do_exit() decrements live before it fires the
// tracepoint, so when several threads of one exit_group exit concurrently the
// earlier ones can fire after the last one's decrement and every one of them
// reads 0: one process death, several group_dead=1 records. (Derived from the
// kernel's do_exit() ordering; not yet observed on a real old kernel.) Fd
// eviction and stats retirement are idempotent, but numGroupDeadExits is not,
// so the repeats must not be counted or replayed.
//
// A time window rather than a permanent "seen" set: pids are recycled, and a
// later process legitimately dying under the same pid must count again. The
// window bookkeeping, with O(1) amortised expiry, lives in groupDeadDedup.
func (e *eventLoop) isDuplicateGroupDead(ev *types.ProcessExitEvent) bool {
	return e.recentGroupDead.seen(ev.Pid, ev.Time)
}

// retireStatsProcess tells the stats engine that process pid has exited, when
// the aggregate sink is the engine (TUI runtimes wire the same Engine as both;
// headless modes have no engine and no sink). It rides on the sink the way
// aggregateDrainPeriodSetter does rather than on a dedicated field: the sink
// is already this loop's handle on the engine.
//
// Calling it from the event loop goroutine is what keeps it correct: the print
// callback ingests every pair synchronously on this goroutine too, so the
// retirement lands after the dying process's last pair and before the first
// pair of any successor with the same PID.
func (e *eventLoop) retireStatsProcess(pid uint32) {
	if retirer, ok := e.aggregateSink.(statsengine.ProcessRetirer); ok {
		retirer.RetireProcess(pid)
	}
}
