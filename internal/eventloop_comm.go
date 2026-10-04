package internal

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/types"
)

// resolveCommTimeout bounds how long each procfs lookup may make its caller
// wait. A /proc/<tid>/comm read of a task stuck in D state (or a frozen
// cgroup) blocks inside the kernel arbitrarily long and cannot be
// interrupted, so the default resolver runs the blocking read in a helper
// goroutine and abandons it on expiry (resolveCommWithinCtx). That is what
// keeps the lookup workers moving and shutdown bounded: both the worker
// loop's next queue item and shutdown()'s workersWG.Wait() depend on a read
// not sticking.
const resolveCommTimeout = time.Second

// commEntry is one cached command name plus the bookkeeping that keeps it
// honest across execve.
//
// epoch counts the authoritative kernel-sourced names userspace has installed
// for the tid - a sched_process_exec or task_rename control record
// (setCachedFromKernel) and an open or exec enter's payload comm
// (setCachedFromEnterPayload, which shares the epoch-bumping write but may
// leave the entry stale). A provisional write (setCachedProvisional) does not
// count: it is a guess a procfs result is meant to replace. A lookup
// worker samples it *before* reading /proc and discards its result when the epoch
// moved on in the meantime: without that guard a worker descheduled between the
// procfs read and the cache write can overwrite an exact, kernel-reported name
// with the older one it is still holding. That is a purely logical race (both
// writes are correctly mutex-protected), so the race detector cannot see it.
//
// stale marks an entry whose value may predate an exec record the kernel never
// managed to emit, because bpf_ringbuf_reserve() failed under backpressure
// (internal/c/exec.c counts that in ringbuf_drop_map). Such an entry keeps
// serving its current value - dropping it outright would blank the comm column
// and, with an active -comm filter, drop the tid's rows at the exit-side comm
// check (finishPair) - but it triggers one asynchronous procfs re-read on next use.
// That read happens after the exec, so it returns the new name and heals the
// label. The same flag marks a provisional entry - the name a new task
// inherited from its creator (setCachedProvisional), when a rename of it could
// go unreported - whose one re-read picks up a rename the task performed on
// itself - and an entry seeded from an enter
// payload that is either about to be superseded (an exec enter) or contradicted
// the cache (setCachedFromEnterPayload).
type commEntry struct {
	comm  string
	epoch uint64
	stale bool
}

// lookupState is the set of generation counters a resolver worker samples
// before its procfs read, so that storeLookupResult can tell what happened to
// the cache while the read was in flight. See storeLookupResult.
type lookupState struct {
	epoch    uint64
	staleGen uint64
	evictGen uint64
}

type commResolver struct {
	comms map[uint32]commEntry

	mu       sync.RWMutex
	pending  map[uint32]struct{}
	closed   bool
	commAges map[uint32]uint64 // insertion/access order per TID, for comms LRU eviction
	commAge  uint64            // monotonic counter for comms LRU ordering
	maxComms int               // max cached comms before pruning; 0 = default

	// staleGen counts the markAllStale sweeps applied to the cache. It is a
	// resolver-wide counter rather than a per-entry flag because the entry a
	// sweep needs to reach may not exist yet: a lookup started before the sweep
	// can create it afterwards, carrying a value read before the lost exec.
	// Workers sample the counter before their procfs read and storeLookupResult
	// re-flags any result that predates the current sweep.
	staleGen uint64

	// evictedLookups counts, per tid, the evictTid calls that landed while a
	// lookup for that tid was in flight, so storeLookupResult can throw away a
	// name read from a process that has since exited.
	//
	// The entry's own epoch cannot carry this, because eviction *deletes* the
	// entry: a result landing afterwards would find no entry, read epoch 0 back
	// and match the 0 it sampled for a tid that had none either - reinstating
	// exactly the dead process's name the eviction removed. Leaving a zeroed
	// entry behind as a tombstone would carry the epoch, but it would sit in
	// comms and therefore in the LRU, where pruning could drop it while the very
	// lookup it guards is still in flight. A counter beside the pending set has
	// neither problem, and no lifetime problem either: it is only created for a
	// tid whose lookup is actually in flight, and storeLookupResult drops it
	// together with that lookup's pending flag.
	evictedLookups map[uint32]uint64

	lookupQueue      chan uint32
	lookupWorkers    int
	resolveFn        func(context.Context, uint32) (string, error)
	warningFn        func(string)
	startWorkersOnce sync.Once
	workersWG        sync.WaitGroup
	shutdownOnce     sync.Once
}

func newCommResolver(comms map[uint32]string) *commResolver {
	if comms == nil {
		comms = make(map[uint32]string)
	}
	r := &commResolver{
		comms:   make(map[uint32]commEntry, len(comms)),
		pending: make(map[uint32]struct{}),
	}
	for tid, comm := range comms {
		r.comms[tid] = commEntry{comm: comm}
	}
	r.ensureCommsAllocated()
	r.ensureLookupConfig()
	return r
}

// ensureInitialized makes any resolver usable by completing every lazily
// created structure behind the resolver's own methods: the comms cache and
// its LRU metadata, the pending-lookup set, and the worker/queue/resolveFn
// defaults. The constructor and the loop's injection seam
// (configuredCommResolver) both go through it, so the resolver's invariants
// are spelled out in exactly one file.
func (r *commResolver) ensureInitialized() {
	r.ensureCommsAllocated()
	if r.pending == nil {
		r.pending = make(map[uint32]struct{})
	}
	r.ensureLookupConfig()
}

// setDefaultWarningFn installs fn as the lookup-failure reporting sink only
// when none is wired yet, so an injected resolver keeps its own sink and the
// event loop's default wiring cannot override it.
func (r *commResolver) setDefaultWarningFn(fn func(string)) {
	if r.warningFn == nil {
		r.warningFn = fn
	}
}

// ensureCommsAllocated initializes the comms cache and its LRU age metadata
// when absent. Safe both in constructors/lazy-init paths (before concurrent
// use) and under r.mu from the mutation helpers. When age metadata is created
// fresh for an injected pre-populated comms map, its entries are aged
// oldest-first (0) so they evict before freshly touched entries.
func (r *commResolver) ensureCommsAllocated() {
	if r.comms == nil {
		r.comms = make(map[uint32]commEntry)
	}
	if r.commAges == nil {
		r.commAges = make(map[uint32]uint64, len(r.comms))
		for tid := range r.comms {
			r.commAges[tid] = 0
		}
	}
}

func (r *commResolver) ensureLookupConfig() {
	if r.lookupWorkers <= 0 {
		r.lookupWorkers = defaultCommLookupWorkers
	}
	if r.lookupQueue == nil {
		r.lookupQueue = make(chan uint32, defaultCommLookupQueueSize)
	}
	if r.resolveFn == nil {
		// The default resolver honours ctx for real: the blocking procfs read
		// runs in a helper goroutine that is abandoned when ctx expires
		// (resolveCommWithinCtx), because os.ReadFile/Readlink cannot be
		// interrupted once inside the kernel.
		r.resolveFn = resolveCommWithinCtx
	}
}

func (r *commResolver) startLookupWorkers() {
	r.ensureLookupConfig()
	r.mu.RLock()
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return
	}
	r.startWorkersOnce.Do(func() {
		for i := 0; i < r.lookupWorkers; i++ {
			r.workersWG.Add(1)
			go r.lookupWorker()
		}
	})
}

func (r *commResolver) lookupWorker() {
	defer r.workersWG.Done()
	for tid := range r.lookupQueue {
		// Shutdown drains the queue without paying for procfs reads: the
		// results would land in a cache the event loop no longer reads, and
		// every skipped read saves up to resolveCommTimeout off the
		// workersWG.Wait() that shutdown() is blocked on. storeLookupResult
		// with an empty comm just clears the pending flag.
		if r.isClosed() {
			r.storeLookupResult(tid, "", lookupState{})
			continue
		}
		// Sample the generation counters before the read: everything this
		// worker observes in /proc from here on may already be one execve, or
		// one drop-triggered staleness sweep, out of date. storeLookupResult
		// uses the sample to detect exactly that.
		state := r.sampleLookupState(tid)
		// Each procfs read gets an independent timeout so that a frozen cgroup
		// or a slow /proc entry cannot block a worker goroutine indefinitely
		// and stall shutdown (which waits on workersWG).
		ctx, cancel := context.WithTimeout(context.Background(), resolveCommTimeout)
		comm, err := r.resolveFn(ctx, tid)
		cancel()
		r.storeLookupResult(tid, comm, state)
		r.notifyResolveFailure(tid, err)
	}
}

// isClosed reports whether shutdown has begun, so the worker loop can drain
// the remaining queue items without paying for their procfs reads.
func (r *commResolver) isClosed() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.closed
}

// sampleLookupState snapshots the generation counters that decide whether a
// lookup result is still usable when it lands: the tid's kernel-rename
// generation, the resolver-wide staleness-sweep generation, and the tid's
// exit-eviction generation.
func (r *commResolver) sampleLookupState(tid uint32) lookupState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return lookupState{
		epoch:    r.comms[tid].epoch,
		staleGen: r.staleGen,
		evictGen: r.evictedLookups[tid],
	}
}

// storeLookupResult clears the pending flag for tid and caches comm, subject to
// the two generation counters sampled before the procfs read.
//
// epoch: an authoritative kernel-sourced name (a sched_process_exec control
// record, a task_rename record, an open or exec enter's payload comm) landed
// for this tid
// while the lookup was in flight. That name is exact and this result - read
// before the rename, or concurrently with it - would put the older name back,
// so it is discarded outright.
//
// evictGen: the tid exited while the lookup was in flight (evictTid). The name
// this worker is holding was read from a process that is gone, and the tid may
// already have been recycled by a new one, so it is discarded outright -
// without this the eviction would be silently undone by the very lookup it was
// meant to outrank.
//
// staleGen: a markAllStale sweep ran while the lookup was in flight, so this
// value may predate the exec record whose loss triggered the sweep. The sweep
// itself could not flag this entry, which may not even have existed yet, and
// setCommLocked clears the stale flag - without the re-flag here such a tid
// would keep a pre-exec label for the rest of its life if the drop burst was a
// one-off. The value is still stored (it is the best label available and
// blanking it would drop the tid's rows at the exit-side comm check); it is
// simply marked for one more re-read on next use.
func (r *commResolver) storeLookupResult(tid uint32, comm string, state lookupState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, tid)
	// At most one lookup per tid is ever in flight (enqueueLookupLocked refuses
	// a second while pending is set), so the tid's eviction counter has done its
	// job the moment that lookup lands and dies with its pending flag.
	evicted := r.evictedLookups[tid]
	delete(r.evictedLookups, tid)
	if comm == "" {
		return
	}
	if evicted != state.evictGen {
		return
	}
	if r.comms[tid].epoch != state.epoch {
		return
	}
	r.setCommLocked(tid, comm)
	if r.staleGen != state.staleGen {
		entry := r.comms[tid]
		entry.stale = true
		r.comms[tid] = entry
	}
}

func (r *commResolver) seedTrackedPidComm(pidFilter int) {
	candidates := []uint32{uint32(os.Getpid()), uint32(os.Getppid())}
	if pidFilter > 0 {
		candidates = append(candidates, uint32(pidFilter))
	}

	seen := make(map[uint32]struct{}, len(candidates))
	for _, tid := range candidates {
		if tid == 0 {
			continue
		}
		if _, ok := seen[tid]; ok {
			continue
		}
		seen[tid] = struct{}{}
		// Bounded by resolveCommTimeout: seeding runs synchronously on the
		// event-loop goroutine at startup, and a /proc read stuck in the
		// kernel (D-state task, frozen cgroup) would otherwise delay the
		// entire initialisation - the default resolver abandons the read
		// when the deadline hits (resolveCommWithinCtx).
		ctx, cancel := context.WithTimeout(context.Background(), resolveCommTimeout)
		comm, err := r.resolveFn(ctx, tid)
		cancel()
		if comm != "" {
			r.setCached(tid, comm)
			continue
		}
		r.notifyResolveFailure(tid, err)
		r.queueLookup(tid)
	}
}

func (r *commResolver) comm(tid uint32) string {
	if comm, ok := r.cached(tid); ok {
		return comm
	}
	r.queueLookup(tid)
	return ""
}

func (r *commResolver) cached(tid uint32) (string, bool) {
	comm, ok, stale := r.lookupCached(tid)
	if stale {
		// Serve the value we have and heal it in the background.
		r.refreshStaleComm(tid)
	}
	return comm, ok
}

// lookupCached reads the cache entry for tid, refreshing its LRU age, and
// additionally reports whether the entry was flagged for re-resolution.
func (r *commResolver) lookupCached(tid uint32) (comm string, ok, stale bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.comms[tid]
	if !ok {
		return "", false, false
	}
	// Refresh the LRU age on use so active TIDs stay cached.
	r.touchCommLocked(tid)
	return entry.comm, true, entry.stale
}

// markAllStale flags every cached comm for one asynchronous re-read and
// reports how many entries it newly flagged.
//
// The count covers only entries present at sweep time; a lookup in flight
// across the sweep is caught by the staleGen check in storeLookupResult
// instead, so a non-zero return is not the full extent of the healing.
//
// Called after the ring-buffer drop counter grew: a dropped record may have
// been a sched_process_exec control record, and that is the one loss the event
// stream cannot repair by itself. The open and exec payload comms heal a tid
// that opens or execs (seedCommFromEnterPayload runs before the raw -comm gate,
// so even a dropped open refreshes the cache), but a tid that only reads and
// writes has no such record. Without this sweep it would keep a stale-cached
// forking-shell label - and keep contradicting the filter - for the rest of its
// life.
func (r *commResolver) markAllStale() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Bump the sweep generation first, so a lookup already in flight - whose
	// entry this loop cannot reach, because the lookup may not have created it
	// yet - is re-flagged by storeLookupResult when it lands.
	r.staleGen++
	marked := 0
	for tid, entry := range r.comms {
		if entry.stale {
			continue
		}
		entry.stale = true
		r.comms[tid] = entry
		marked++
	}
	return marked
}

// refreshStaleComm queues one procfs re-read for a stale entry. The cached
// value stays in place until the read lands, so rows keep their (possibly
// outdated) label instead of losing it. The stale flag is cleared only once
// the lookup is actually queued, so a saturated queue means "retry on next
// use" rather than "give up".
func (r *commResolver) refreshStaleComm(tid uint32) {
	if tid == 0 {
		return
	}
	r.startLookupWorkers()

	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.comms[tid]
	if !ok || !entry.stale {
		return
	}
	if !r.enqueueLookupLocked(tid) {
		return
	}
	entry.stale = false
	r.comms[tid] = entry
}

// evictTid drops the cached command name of a task the kernel reported as
// exited (a sched:sched_process_exit control record, handleProcessExitEvent).
//
// Tids are recycled, and nothing else in the cache's write paths reaches an
// entry whose owner is gone: an entry is only ever overwritten by an
// authoritative kernel-sourced name (setCachedFromKernel, or an enter payload
// through setCachedFromEnterPayload), by a creator's inherited name for a new
// task (setCachedProvisional, on a task_newtask record), by a completed
// procfs lookup, or - once, at startup - by the procfs seed of ior itself, its
// parent and the -pid target (setCached, from seedTrackedPidComm). None of
// them is triggered by the owner's death, and the task_newtask record that
// would overwrite the entry for the tid's next owner can be lost or its probe
// missing. So without this the next process to be
// handed the same tid number was labelled with the dead process's comm until
// one of those writes happened to reach it (an open, an execve(), a rename) or
// the entry aged out of the 8192-entry LRU - and on a box churning short-lived
// processes that reuse is neither rare nor slow.
//
// The record fires per *task*, and the comm cache is keyed per task, so
// evicting exactly ev.Tid is precise rather than degraded: a thread exiting
// inside a still-living multithreaded process drops that thread's name only,
// which is the very name that has just become meaningless. This runs on every
// exit record; the sibling fdTracker eviction does not, because its key is the
// tgid: it runs only on the record flagged group_dead (the last thread of the
// process exited) - see handleProcessExitEvent.
//
// A lookup already in flight for the tid is retired via evictedLookups rather
// than by touching the entry, because the entry is about to stop existing; see
// storeLookupResult. Evicting - as opposed to the markAllStale treatment given
// to a lost exec record - is right here because there is nothing left to serve:
// the value does not merely risk being outdated, its owner is gone. The next
// use of the tid queues a fresh lookup (comm) and, under an active -comm
// filter, the recycled tid's rows until that lookup lands are dropped at the
// exit-side comm check exactly as a never-before-seen tid's would be (its
// fd-table changes still apply: see tracepointEntered).
func (r *commResolver) evictTid(tid uint32) {
	if tid == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, cached := r.comms[tid]
	_, inFlight := r.pending[tid]
	if !cached && !inFlight {
		return
	}
	delete(r.comms, tid)
	delete(r.commAges, tid)
	if inFlight {
		if r.evictedLookups == nil {
			r.evictedLookups = make(map[uint32]uint64)
		}
		r.evictedLookups[tid]++
	}
}

func (r *commResolver) setCached(tid uint32, comm string) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	r.setCommLocked(tid, comm)
	r.mu.Unlock()
}

// setCommLocked stores comm for tid, refreshes its LRU age, and prunes the
// cache when over the limit. Callers must hold r.mu.
func (r *commResolver) setCommLocked(tid uint32, comm string) {
	r.ensureCommsAllocated()
	r.commAge++
	entry := r.comms[tid]
	entry.comm = comm
	entry.stale = false
	r.comms[tid] = entry
	r.commAges[tid] = r.commAge
	r.pruneCommsLocked()
}

// setCachedFromKernel stores a command name the kernel itself reported for tid
// and bumps its rename generation, which invalidates every procfs lookup that
// was already in flight for that tid (see storeLookupResult).
//
// Every authoritative kernel-sourced write takes this path, not just the
// sched_process_exec record: a task_rename record (a task renaming itself with
// prctl(PR_SET_NAME) or pthread_setname_np, handleTaskRenameEvent) and the
// payload comm of an open or exec enter (seedCommFromEnterPayload, through
// setCachedFromEnterPayload, which shares this write) are exact for the moment
// the kernel produced them, whereas a resolver worker's /proc read is
// unordered with respect to them. Bumping only on exec left those writes
// clobberable by a descheduled worker holding an older name - reachable
// whenever the exec record was dropped, and also with no execve at all through
// a rename.
func (r *commResolver) setCachedFromKernel(tid uint32, comm string) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setKernelCommLocked(tid, comm)
}

// setKernelCommLocked is the body of setCachedFromKernel: it bumps the tid's
// rename generation and stores comm (clearing the stale flag). Callers must
// hold r.mu and pass a non-empty comm.
func (r *commResolver) setKernelCommLocked(tid uint32, comm string) {
	entry := r.comms[tid]
	entry.epoch++
	r.comms[tid] = entry
	r.setCommLocked(tid, comm)
}

// markStaleLocked flags an existing entry for one procfs re-read on next use
// (refreshStaleComm). Callers must hold r.mu.
func (r *commResolver) markStaleLocked(tid uint32) {
	entry, ok := r.comms[tid]
	if !ok {
		return
	}
	entry.stale = true
	r.comms[tid] = entry
}

// setCachedFromEnterPayload installs the payload comm of an open or exec enter
// record (seedCommFromEnterPayload). The write is authoritative like any
// kernel-sourced one - it bumps the rename generation, so a procfs read already
// in flight cannot land on top of it - but in two cases it additionally leaves
// the entry stale, so that its next use queues exactly one /proc re-read:
//
//   - recheck (an exec enter): the payload is the *calling* program's name, which
//     a successful execve is about to replace. The task_rename and
//     sched_process_exec records that report the replacement follow in ring
//     order and clear the flag again (setCachedFromKernel). When neither probe
//     is attached (an old IOR_BPF_OBJECT, or both attaches failed) or both
//     records were lost, the re-read is the only thing that ever learns the new
//     program's name. It runs on the tid's first comm use after the enter - the
//     execve exit labels its row from its own payload, so that is a syscall of
//     the new program - and therefore reads the post-exec name. Clearing the
//     flag here instead cost exactly that read for a fork child whose first
//     syscall is execve: the task_newtask record had left the parent's name
//     provisional and stale, and the exec enter re-wrote that same name as
//     final. A failed execve pays one redundant read on the next use.
//   - the payload contradicts the cached name: almost always the cache was the
//     wrong one (a lost record), but it is also the trace of a narrow race.
//     __set_task_comm() fires the task_rename tracepoint *before* it copies the
//     new name into task->comm, so when thread A renames sibling T
//     (/proc/<T>/comm, pthread_setname_np) while T enters openat on another
//     CPU, T's payload can carry the old name although its record sits behind
//     the rename record in the ring. Applying the payload then undoes the
//     rename; the re-read, which happens after the rename record and a later
//     record of T have reached userspace, finds the new name. Without it the
//     old name stuck until T's next open or rename. The row labelled between
//     the two still carries the old name, and a /proc read of a thread that has
//     already exited finds nothing and leaves the payload name. A matching
//     payload (the common case) costs nothing.
func (r *commResolver) setCachedFromEnterPayload(tid uint32, comm string, recheck bool) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	prev, had := r.comms[tid]
	r.setKernelCommLocked(tid, comm)
	if recheck || (had && prev.comm != comm) {
		r.markStaleLocked(tid)
	}
}

// setCachedProvisional stores a best-guess name for tid without invalidating
// procfs lookups and, when recheck is set, marks the entry stale, so it is
// re-read from /proc once.
//
// It is the write for a name that is known to be *inherited* rather than
// current: the comm a task_newtask record reports is the creator's, and a new
// thread commonly renames itself (prctl(PR_SET_NAME), pthread_setname_np) as
// its very first act - tokio, Java, Chrome and Bun worker pools all do. The
// task_rename record reports that rename, but it can be lost (ring-buffer
// backpressure) or its probe can fail to attach, and the one /proc read below
// is the fallback for those cases. Two properties follow from that, and each is
// the opposite of setCachedFromKernel:
//   - The epoch is not bumped, so a procfs result may overwrite the guess
//     (storeLookupResult only discards results that predate an authoritative
//     write). Bumping it would pin the parent's name for the thread's life.
//   - With recheck, the entry is flagged stale, which makes the first use of
//     the tid queue exactly one /proc/<tid>/comm read (refreshStaleComm). The
//     read happens after the thread's first traced syscall reached userspace,
//     i.e. after any rename that precedes it, and its result replaces the
//     guess. A read of a task that has already exited yields nothing and leaves
//     the guess in place, which is still better than an empty comm.
//
// recheck is the caller's verdict on whether a rename could go unreported
// (eventLoop.provisionalSeedNeedsRecheck, task xr2). When the task_rename probe
// is attached and ring-buffer drops are monitored, a rename normally arrives
// as a record or shows up as a drop whose markAllStale sweep flags the entry
// (a rename whose new name the BPF handler cannot read is counted as a drop
// too, task mz2; the copy_process windows listed at provisionalSeedNeedsRecheck
// are not covered), so the read
// is overhead - and under thread churn it was most of the
// resolver's work: one read per new thread, nearly all of them ENOENT because
// the thread had exited before a worker got to it. Without recheck the entry
// is stored non-stale and costs nothing until a sweep or a record touches it.
//
// A later authoritative write (exec record, task_rename record, open or exec
// enter payload) bumps the epoch and so still outranks a read that was in
// flight at that moment. Of those, only an enter payload can keep the entry
// stale (setCachedFromEnterPayload), and in two cases: an exec enter always,
// because it names the program that is about to be replaced and so must not
// count as the answer the re-read was waiting for, and an open enter whose
// payload contradicts the cached name (here: the inherited guess), because the
// payload may predate a sibling's rename. A matching open payload clears the
// flag, which is fine: it confirms the guess with a name the kernel reported
// after the task started running.
func (r *commResolver) setCachedProvisional(tid uint32, comm string, recheck bool) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.setCommLocked(tid, comm)
	if recheck {
		r.markStaleLocked(tid)
	}
}

// touchCommLocked refreshes the LRU age of an existing comms entry. Callers
// must hold r.mu and the entry must exist.
func (r *commResolver) touchCommLocked(tid uint32) {
	if r.commAges == nil {
		r.commAges = make(map[uint32]uint64)
	}
	r.commAge++
	r.commAges[tid] = r.commAge
}

// pruneCommsLocked evicts the oldest comms entries when over the limit, so
// the per-TID comm cache stays bounded on thread-churning traces. Callers
// must hold r.mu.
func (r *commResolver) pruneCommsLocked() {
	limit := r.commsLimit()
	if len(r.comms) <= limit {
		return
	}
	trimLRU(r.comms, r.commAges, trimTarget(limit))
}

// commsLimit reports the maximum number of cached comms before pruning.
func (r *commResolver) commsLimit() int {
	if r.maxComms > 0 {
		return r.maxComms
	}
	return defaultMaxHandleEntries
}

func (r *commResolver) queueLookup(tid uint32) {
	if tid == 0 {
		return
	}
	r.startLookupWorkers()

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if _, ok := r.comms[tid]; ok {
		// Already resolved; refresh the LRU age so the active TID stays cached.
		r.touchCommLocked(tid)
		return
	}
	r.enqueueLookupLocked(tid)
}

// enqueueLookupLocked marks tid pending and hands it to a lookup worker,
// reporting whether it was actually queued. It refuses after shutdown and when
// a lookup for tid is already in flight, and stays non-blocking so event
// processing never stalls on saturated resolver workers. Callers must hold
// r.mu.
func (r *commResolver) enqueueLookupLocked(tid uint32) bool {
	if r.closed {
		return false
	}
	if r.pending == nil {
		r.pending = make(map[uint32]struct{})
	}
	if _, ok := r.pending[tid]; ok {
		return false
	}
	r.pending[tid] = struct{}{}

	select {
	case r.lookupQueue <- tid:
		return true
	default:
		delete(r.pending, tid)
		return false
	}
}

func (r *commResolver) shutdown() {
	r.shutdownOnce.Do(func() {
		r.ensureLookupConfig()
		r.mu.Lock()
		r.closed = true
		for tid := range r.pending {
			delete(r.pending, tid)
			delete(r.evictedLookups, tid)
		}
		queue := r.lookupQueue
		r.mu.Unlock()
		close(queue)
		r.workersWG.Wait()
	})
}

func (r *commResolver) notifyResolveFailure(tid uint32, err error) {
	if err == nil {
		return
	}
	r.notifyWarning(fmt.Sprintf("failed to resolve comm for tid %d: %v", tid, err))
}

func (r *commResolver) notifyWarning(message string) {
	if r.warningFn == nil || message == "" {
		return
	}
	r.warningFn(message)
}

func (e *eventLoop) shutdownCommResolver() {
	if e.commResolver == nil {
		return
	}
	e.commResolver.shutdown()
}

func (e *eventLoop) comm(tid uint32) string {
	return e.commState().comm(tid)
}

func (e *eventLoop) setCachedComm(tid uint32, comm string) {
	e.commState().setCached(tid, comm)
}

// setCachedCommFromKernel applies a kernel-reported command name (see
// commResolver.setCachedFromKernel) that came with a record stamped
// recordTime (boot clock). A record no newer than the last ring-buffer drop
// the monitor saw may have been reserved before that drop and consumed only
// now, after the staleness sweep (markAllStale) already ran: the sweep flagged
// only the entries that existed then, so this write is non-stale although the
// record that followed it - the one the drop lost - never arrives. The entry is
// flagged stale here so its next use re-reads /proc once (task lz2; the same
// record-time check provisionalSeedNeedsRecheck applies to newtask seeds).
func (e *eventLoop) setCachedCommFromKernel(tid uint32, comm string, recordTime uint64) {
	e.commState().setCachedFromKernel(tid, comm)
	if e.recordMayPredateDrop(recordTime) {
		e.commState().markStale(tid)
	}
}

// recordMayPredateDrop reports whether a record stamped recordTime may have
// been reserved before the newest ring-buffer drop the monitor reported
// (lastDropSeenBootNs, see requestCommSweepAfterDrop), so that a sweep
// triggered by that drop cannot have covered a write it causes.
func (e *eventLoop) recordMayPredateDrop(recordTime uint64) bool {
	return recordTime <= e.lastDropSeenBootNs.Load()
}

// markStale flags tid's cached comm for one /proc re-read on next use, like a
// sweep does for every entry. An unknown tid is left alone.
func (r *commResolver) markStale(tid uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.markStaleLocked(tid)
}

// setCachedCommProvisional applies an inherited, possibly outdated command name
// (see commResolver.setCachedProvisional); recheck asks for the one corrective
// /proc read.
func (e *eventLoop) setCachedCommProvisional(tid uint32, comm string, recheck bool) {
	e.commState().setCachedProvisional(tid, comm, recheck)
}

// evictCachedComm drops the cached command name of an exited task (see
// commResolver.evictTid).
func (e *eventLoop) evictCachedComm(tid uint32) {
	e.commState().evictTid(tid)
}

// seedCommFromEnterPayload installs the comm an open or exec enter record
// carries (BPF copies task->comm into it when the syscall starts) as the tid's
// authoritative name.
//
// It runs when the enter record is consumed, not at the syscall's exit, because
// ring-buffer order is what makes the write correct: a task_rename record that
// lands between the enter and the exit (a sibling's pthread_setname_np on a
// thread blocked in open(2) on a FIFO) is applied after this write, so the
// rename wins. Writing the enter-time name at exit instead restored the
// pre-rename name, with an epoch bump that also discarded the lookup which could
// have repaired it, and every later row of the thread kept the old label.
//
// For an exec enter the name is the *calling* program's. That is right for the
// tid until the syscall's own records say otherwise: a successful execve is
// followed by task_rename (begin_new_exec) and PROCESS_EXEC_EVENT records that
// replace it, and a failed one (no exec record is ever emitted) leaves the task
// under exactly this name. Because those records may be missing (probes not
// attached, ring-buffer drops), the exec seed leaves the entry stale so the
// first use after the exec re-reads /proc once (setCachedFromEnterPayload).
//
// Like every kernel-sourced write it bumps the rename generation, so a procfs
// lookup already in flight cannot land on top of it. It also settles the cache
// for enters the raw filter is about to drop (-comm), which could not heal it
// when the write sat in the exit handler.
//
// Known limit: ring order is not quite task->comm order for a rename of a
// *sibling* thread. __set_task_comm() fires the task_rename tracepoint before it
// stores the new name, so an open enter of the renamed thread racing with it on
// another CPU (a nanosecond window) can carry the old name behind the rename
// record. A self-rename (prctl) cannot race this way, since the thread is busy
// renaming itself. setCachedFromEnterPayload marks such a contradicting seed
// stale, so the thread's next comm use re-reads /proc and heals it; see there.
func (e *eventLoop) seedCommFromEnterPayload(ev event.Event) {
	switch p := ev.(type) {
	case *types.OpenEvent:
		e.commState().setCachedFromEnterPayload(p.Tid, types.StringValue(p.Comm[:]), e.recordMayPredateDrop(p.Time))
	case *types.ExecEvent:
		e.commState().setCachedFromEnterPayload(p.Tid, types.StringValue(p.Comm[:]), true)
	}
}

// applyPendingCommRefresh consumes a refresh request raised by the ring-buffer
// drop monitor and flags the whole comm cache for re-resolution. The
// registered-ring tables, the other state a lost control record leaves wrong
// without a trace, are forgotten on the same notice.
//
// It runs on the event-loop goroutine, not on the monitor's: commState() lazily
// initialises the resolver and its callbacks without holding a lock, so calling
// it from the monitor goroutine would be a data race. The monitor therefore
// only sets an atomic flag and this hot-path check (one relaxed load per raw
// event) picks it up.
func (e *eventLoop) applyPendingCommRefresh() {
	if !e.commRefreshPending.Load() {
		return
	}
	if !e.commRefreshPending.CompareAndSwap(true, false) {
		return
	}
	e.commState().markAllStale()
	// The lost records may include a registered-ring control record, after
	// which a table names an index after the ring it held before; nothing
	// says whose, so every table goes and the rows fall back to their index
	// until the next registration (eventloop_ringfds.go).
	e.ringState().dropAll()
}

func (e *eventLoop) queueCommLookup(tid uint32) {
	e.commState().queueLookup(tid)
}

// handleProcessExecEvent applies the exact post-exec comm reported by the
// kernel's sched:sched_process_exec tracepoint.
//
// This is the authoritative source for a task's name after an execve, and the
// only one that is race-free. The procfs resolver below runs asynchronously on
// worker goroutines, so a lookup scheduled for a tid that has just forked can
// complete before that tid execs and cache the pre-exec program name; nothing
// then invalidated it, and the first syscalls of the new program (typically the
// dynamic loader's access("/etc/ld.so.preload")) were labelled with the old
// name. Because the kernel already installed the new name in task->comm before
// this tracepoint fires, and the ring buffer delivers this record before any
// syscall record of the new program, overwriting the cache here makes the label
// correct from the very first post-exec event. The write also bumps the tid's
// rename generation, which retires any procfs lookup still in flight for it -
// otherwise a worker holding the pre-exec name could land afterwards and undo
// this correction. The one case this cannot cover is the record never being
// emitted at all (ring-buffer backpressure); markAllStale is the recovery path
// for that.
//
// The same record is also the only notice userspace gets that the process's
// FD_CLOEXEC descriptors were closed, so it evicts those from the fd table
// (fdTracker.dropOnExec) before the new program's first syscall can resolve a
// reused descriptor number against the old program's file. That happens
// before the comm check below: an empty comm makes the record useless as a
// label, but the exec it reports still happened. ev.Pid is the tgid, the key
// of the fd table; after de_thread the exec'ing thread holds that id too.
//
// Unlike the comm, the fd table has no recovery path for a lost record: if
// bpf_ringbuf_reserve() fails for the exec record (ring-buffer backpressure,
// counted in ringbuf_drop_map), the process's FD_CLOEXEC entries stay in the
// table, and markAllStale only re-resolves comms. They then stay stale until
// the process closes, re-opens or re-dups those numbers through a traced
// syscall, exits, or they age out of the LRU.
//
// A non-leader exec changes the task's tid as well; rekeyExecCaller moves the
// execve still in flight (and the rest of the caller's tid-keyed state) to
// the leader tid it now runs under, so the execve's exit pairs. Like the fd
// eviction it runs before the comm check. Under -tid <that non-leader> the
// exit never arrives (the leader tid is filtered in BPF, which flags the record
// ExitUntraced), so completeUntracedExec turns the re-keyed enter into its row
// here and sends it on ch.
//
// Before any of that, an interrupted row the caller still holds under its
// pre-exec tid is released (releaseExecCallerRestart): this record is the last
// one that can, and an execve enter the fold had taken has to be parked again
// while the fd table is still the old program's and before the re-keying
// looks for it. The rows the process's other threads still hold - threads
// de_thread killed, whose exit records were lost - are released by the loop
// behind this record (noteExecRecord, releaseRestartsBehindExec, task v13).
func (e *eventLoop) handleProcessExecEvent(ev *types.ProcessExecEvent, ch chan<- *event.Pair) {
	defer ev.Recycle()
	e.releaseExecCallerRestart(ev, ch)
	e.noteExecRecord(ev)
	e.fdState().dropOnExec(ev.Pid)
	// The new program has a fresh address space and so a fresh program break.
	e.brkState.forget(ev.Pid)
	// An exec cancels the caller's io_uring context and with it its
	// registered-ring table (eventloop_ringfds.go).
	e.ringState().dropThread(ev.Tid)
	e.rekeyExecCaller(ev)
	if ev.ExitUntraced != 0 {
		e.completeUntracedExec(ev, ch)
	}
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		// A control record with an empty comm carries no information; keeping
		// whatever is cached beats replacing a good label with nothing.
		return
	}
	e.setCachedCommFromKernel(ev.Tid, comm, ev.Time)
}

// procTidPathPrefix is tid's /proc/<tid> directory on the real procfs.
func procTidPathPrefix(tid uint32) string {
	return procTidPathIn(procRoot, tid)
}

// procTidPathIn is the /proc/<tid> directory of tid under the procfs mount
// root (procRoot in production; tests pass a temporary directory).
func procTidPathIn(root string, tid uint32) string {
	return root + "/" + strconv.FormatUint(uint64(tid), 10)
}

func resolveCommFromProc(tid uint32) string {
	comm, _ := resolveCommFromProcWithError(tid)
	return comm
}

// resolveCommWithinCtx reads tid's comm from procfs with a real bound on how
// long the caller can be made to wait. os.ReadFile/Readlink cannot be
// interrupted once inside the kernel - a /proc/<tid>/comm read of a task in
// D state, or of a process under a frozen cgroup, blocks arbitrarily long -
// so the blocking read runs in a helper goroutine and this function returns
// as soon as ctx is done, abandoning the helper.
//
// The abandoned goroutine is not a leak in the usual sense: its channel is
// buffered, so it always completes its send and exits once the stuck read
// eventually returns (or lingers with the process if it never does - the one
// price of abandoning a syscall Go cannot cancel). It writes nothing to the
// comm cache; the timeout result is stored as an empty comm, which
// storeLookupResult drops, so a value that arrives late cannot land anywhere.
// Test-resolvable resolveFns bypass this wrapper entirely by injecting their
// own.
func resolveCommWithinCtx(ctx context.Context, tid uint32) (string, error) {
	return readWithDeadline(ctx, func() (string, error) {
		return resolveCommFromProcWithError(tid)
	})
}

// readWithDeadline runs one blocking read in a helper goroutine and returns
// its result, or ctx.Err() as soon as ctx expires - whichever comes first.
// Split out of resolveCommWithinCtx so the abandonment itself is testable
// without needing a genuinely hung /proc entry.
func readWithDeadline(ctx context.Context, read func() (string, error)) (string, error) {
	type procResult struct {
		comm string
		err  error
	}
	// Buffered so the abandoned helper can always complete its send and exit,
	// instead of blocking on a caller that has moved on.
	done := make(chan procResult, 1)
	go func() {
		comm, err := read()
		done <- procResult{comm: comm, err: err}
	}()
	select {
	case res := <-done:
		return res.comm, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// resolveCommFromProcWithError reads tid's comm from /proc/<tid>/comm and falls
// back to the basename of /proc/<tid>/exe when that read fails for a reason
// other than the task being gone, or yields an empty name.
//
// A transient failure (ENOENT, ESRCH: the task has exited) returns at once
// without the exe fallback: /proc/<tid> is gone as a whole, so the readlink
// would fail the same way. Under thread churn that is the common outcome of a
// lookup (task xr2 measured 99% ENOENT at 300 new threads/s), and the
// fallback doubled the syscalls of every one of them.
func resolveCommFromProcWithError(tid uint32) (string, error) {
	return resolveCommFromProcRoot(procRoot, tid)
}

// resolveCommFromProcRoot is resolveCommFromProcWithError under the procfs
// mount root, the seam that lets tests lay out a fake /proc/<tid> (a missing
// comm next to a present exe link) the way checkTraceTarget and targetWatch
// take theirs.
func resolveCommFromProcRoot(root string, tid uint32) (string, error) {
	procPath := procTidPathIn(root, tid)
	commPath := procPath + "/comm"
	data, commErr := os.ReadFile(commPath)
	if commErr == nil {
		comm := string(data)
		if len(comm) > 0 && comm[len(comm)-1] == '\n' {
			comm = comm[:len(comm)-1]
		}
		if comm != "" {
			return comm, nil
		}
	} else if isTransientProcError(commErr) {
		return "", nil
	} else {
		commErr = fmt.Errorf("read %s: %w", commPath, commErr)
	}

	exePath := procPath + "/exe"
	linkName, linkErr := os.Readlink(exePath)
	if linkErr == nil {
		if base := filepath.Base(linkName); base != "" {
			return base, nil
		}
	} else if isTransientProcError(linkErr) {
		linkErr = nil
	} else {
		linkErr = fmt.Errorf("readlink %s: %w", exePath, linkErr)
	}

	return "", errors.Join(commErr, linkErr)
}

func isTransientProcError(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH)
}
