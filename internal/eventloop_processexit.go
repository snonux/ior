package internal

import (
	"ior/internal/types"
)

// handleProcessExitEvent applies a sched:sched_process_exit control record to
// the three pieces of state that outlive the task the kernel just reported
// dead.
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
// The drop is deliberately not counted anywhere. It costs no accounting:
// numTracepoints counted the enter record when it was seen, and numSyscalls
// only ever counted completed pairs, so nothing that was already tallied
// disappears. It is not a mismatch either - numTracepointMismatches means the
// tracker paired two records that do not belong together, and a task killed
// inside a syscall is ordinary kernel behaviour, so counting it there would
// both inflate the health percentage stats() prints and mask a real pairing
// regression behind a routine one. A statistic of its own would be worse than
// none: it would cover one of the three ways an enter dies unpaired (this one,
// the LRU trim, and end-of-run leftovers), so a reader would take its zero for
// "no enters were dropped".
//
// sched_process_exit fires per *task*, which lands differently on the three:
//   - For the fd table, keyed by tgid, a thread exit inside a still-living
//     multithreaded process evicts that process's entries early. That is
//     degraded, not wrong: the next syscall on one of those descriptors
//     resolves through the procfs fallback (/proc/<pid>/fd), which still
//     answers correctly while the process lives and re-populates the table.
//   - For the comm cache and the pair tracker, both keyed by tid, per-task is
//     exactly the right granularity: only the name, parked enter and gap
//     baseline of the thread that actually died are dropped, and its siblings
//     keep theirs.
//
// A record lost to ring-buffer backpressure simply never evicts (counted in
// ringbuf_drop_map like every other record); the stale entries linger until
// the LRU cap trims them, which is the same trade the procfs cache already
// makes per (pid, fd).
func (e *eventLoop) handleProcessExitEvent(ev *types.ProcessExitEvent) {
	defer ev.Recycle()
	e.fdState().deletePid(ev.Pid)
	e.evictCachedComm(ev.Tid)
	e.pairs.evictTid(ev.Tid)
}
