package internal

import (
	"ior/internal/types"
)

// handleProcessExitEvent applies a sched:sched_process_exit control record to
// the two caches that outlive the task the kernel just reported dead.
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
// sched_process_exit fires per *task*, which lands differently on the two:
//   - For the fd table, keyed by tgid, a thread exit inside a still-living
//     multithreaded process evicts that process's entries early. That is
//     degraded, not wrong: the next syscall on one of those descriptors
//     resolves through the procfs fallback (/proc/<pid>/fd), which still
//     answers correctly while the process lives and re-populates the table.
//   - For the comm cache, keyed by tid, per-task is exactly the right
//     granularity: only the name of the thread that actually died is dropped,
//     and its siblings keep theirs.
//
// A record lost to ring-buffer backpressure simply never evicts (counted in
// ringbuf_drop_map like every other record); the stale entries linger until
// the LRU cap trims them, which is the same trade the procfs cache already
// makes per (pid, fd).
func (e *eventLoop) handleProcessExitEvent(ev *types.ProcessExitEvent) {
	defer ev.Recycle()
	e.fdState().deletePid(ev.Pid)
	e.evictCachedComm(ev.Tid)
}
