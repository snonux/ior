package internal

import (
	"ior/internal/types"
)

// handleProcessExitEvent applies a sched:sched_process_exit control record to
// the four pieces of state that would otherwise outlive the task the kernel
// just reported dead.
//
// The fd table: the exited task belonged to tgid ev.Pid, so every (pid, fd)
// entry of that process is dropped from the fdTracker and its procfs cache.
// Without this, descriptors of dead processes lingered in the table until LRU
// eviction - stale garbage for any fd number they ever held, and unbounded
// growth on process-churning traces (see the note on
// defaultMaxFdTableEntries).
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
// numSyscalls is only reached by a pair that found its enter.
//
// It is emphatically not a mismatch. numTracepointMismatches means the tracker
// paired two records that do not belong together, and a task killed inside a
// syscall is ordinary kernel behaviour - counting it there would inflate the
// health percentage stats() prints and mask a real pairing regression behind
// routine traffic. This eviction in fact *removes* false positives from that
// counter, which is the strongest argument for keeping them apart:
// exit/exit_group/rt_sigreturn emit an enter and have no exit handler at all
// (ior_on_noreturn_syscall_enter), and no matching exit trace ID exists, so
// such an enter parks forever and any exit that does consume it is
// necessarily counted as a mismatch. Usually the recycled tid's own enter
// supersedes it first and nothing is counted; the mismatch needs that enter to
// be missing, which is the ring-buffer loss and -comm enter-gate case below.
// Routing eviction drops into the same counter would have cancelled that
// improvement rather than measured anything. Note this concerns runs tracing
// the Process family: exit_group is not in the default FS-only allowlist.
//
// A statistic of its own is a judgement call rather than an impossibility. An
// enter can die unpaired four ways - here, superseded in set() when an exit
// record is lost, trimmed from the pending-enter LRU, and left parked at
// end of run - and all four are reachable, so a counter *could* be complete.
// It is not worth one: the number would mix a kernel fact (tasks die inside
// syscalls) with a tracer symptom (records were lost), and a reader cannot act
// on the sum.
//
// sched_process_exit fires per *task*, which lands differently on the four:
//   - For the fd table, keyed by tgid, a thread exit inside a still-living
//     multithreaded process evicts that process's entries early. That is
//     degraded, not wrong: the next syscall on one of those descriptors
//     resolves through the procfs fallback (/proc/<pid>/fd), which still
//     answers correctly while the process lives and re-populates the table.
//   - For the comm cache, the pair tracker and the pending-handle tracker, all
//     keyed by tid, per-task is exactly the right granularity: only the name,
//     parked enter, gap baseline and unconsumed name_to_handle_at pathname of
//     the thread that actually died are dropped, and its siblings keep theirs.
//
// A record lost to ring-buffer backpressure simply never evicts (counted in
// ringbuf_drop_map like every other record); the stale entries linger until
// the LRU cap trims them, which is the same trade the procfs cache already
// makes per (pid, fd).
func (e *eventLoop) handleProcessExitEvent(ev *types.ProcessExitEvent) {
	defer ev.Recycle()
	e.fdState().deletePid(ev.Pid)
	e.evictCachedComm(ev.Tid)
	// Neither of these guards tid == 0 the way commResolver.evictTid does:
	// there the guard exists because a zero tid is the resolver's "unknown"
	// sentinel, while here it is simply a key no live task uses, so deleting
	// it is a no-op rather than a hazard.
	e.pairs.evictTid(ev.Tid)
	// name_to_handle_at parks a pathname under the tid for the matching
	// open_by_handle_at to consume, and a task that resolves a handle and dies
	// - or simply hands it to another process, which is what the API is for -
	// leaves it parked. Left behind, the recycled tid's next open_by_handle_at
	// takes the dead task's path, and handleOpenByHandleAtExit then registers
	// that path in the fd table for the *new* process, so every later read,
	// write and close on the descriptor reports it too: a wrong row rather
	// than a missing one, and a persistent one.
	e.pendingHandleState().delete(ev.Tid)
}
