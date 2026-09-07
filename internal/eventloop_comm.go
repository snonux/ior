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
// for the tid - a sched_process_exec control record, an open event's payload
// comm, a failed execve's payload comm (setCachedFromKernel). A lookup worker
// samples it *before* reading /proc and discards its result when the epoch
// moved on in the meantime: without that guard a worker descheduled between the
// procfs read and the cache write can overwrite an exact, kernel-reported name
// with the older one it is still holding. That is a purely logical race (both
// writes are correctly mutex-protected), so the race detector cannot see it.
//
// stale marks an entry whose value may predate an exec record the kernel never
// managed to emit, because bpf_ringbuf_reserve() failed under backpressure
// (internal/c/exec.c counts that in ringbuf_drop_map). Such an entry keeps
// serving its current value - dropping it outright would blank the comm column
// and, with an active -comm filter, discard the tid's events at the enter-side
// comm gate - but it triggers one asynchronous procfs re-read on next use.
// That read happens after the exec, so it returns the new name and heals the
// label.
type commEntry struct {
	comm  string
	epoch uint64
	stale bool
}

// lookupState is the pair of generation counters a resolver worker samples
// before its procfs read, so that storeLookupResult can tell what happened to
// the cache while the read was in flight. See storeLookupResult.
type lookupState struct {
	epoch    uint64
	staleGen uint64
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
// generation and the resolver-wide staleness-sweep generation.
func (r *commResolver) sampleLookupState(tid uint32) lookupState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return lookupState{epoch: r.comms[tid].epoch, staleGen: r.staleGen}
}

// storeLookupResult clears the pending flag for tid and caches comm, subject to
// the two generation counters sampled before the procfs read.
//
// epoch: an authoritative kernel-sourced name (a sched_process_exec control
// record, an open event's payload comm, a failed execve) landed for this tid
// while the lookup was in flight. That name is exact and this result - read
// before the rename, or concurrently with it - would put the older name back,
// so it is discarded outright.
//
// staleGen: a markAllStale sweep ran while the lookup was in flight, so this
// value may predate the exec record whose loss triggered the sweep. The sweep
// itself could not flag this entry, which may not even have existed yet, and
// setCommLocked clears the stale flag - without the re-flag here such a tid
// would keep a pre-exec label for the rest of its life if the drop burst was a
// one-off. The value is still stored (it is the best label available and
// blanking it would drop the tid's rows at the enter-side comm gate); it is
// simply marked for one more re-read on next use.
func (r *commResolver) storeLookupResult(tid uint32, comm string, state lookupState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, tid)
	if comm == "" {
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
// stream cannot repair by itself. With an active -comm filter the usual
// self-healing path is closed too, because matchRawOpenEvent drops
// non-matching opens at enter, so handleOpenExit never gets to refresh the
// cache from the kernel comm. Without this sweep a tid stale-cached as the
// forking shell would keep that label - and keep contradicting the filter -
// for the rest of its life.
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
// sched_process_exec record: an open event's payload comm and a failed
// execve's payload comm are read by BPF from task->comm at event time, so they
// are exact for that moment, whereas a resolver worker's /proc read is
// unordered with respect to them. Bumping only on exec left those two writes
// clobberable by a descheduled worker holding an older name - reachable
// whenever the exec record was dropped, and also with no execve at all via
// prctl(PR_SET_NAME).
func (r *commResolver) setCachedFromKernel(tid uint32, comm string) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := r.comms[tid]
	entry.epoch++
	r.comms[tid] = entry
	r.setCommLocked(tid, comm)
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
	trimLRU(r.comms, r.commAges, trimTarget(limit), nil)
}

// commsLimit reports the maximum number of cached comms before pruning.
func (r *commResolver) commsLimit() int {
	if r.maxComms > 0 {
		return r.maxComms
	}
	return defaultMaxPendingHandleEntries
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

func (e *eventLoop) cachedComm(tid uint32) (string, bool) {
	return e.commState().cached(tid)
}

func (e *eventLoop) setCachedComm(tid uint32, comm string) {
	e.commState().setCached(tid, comm)
}

// setCachedCommFromKernel applies a kernel-reported command name (see
// commResolver.setCachedFromKernel).
func (e *eventLoop) setCachedCommFromKernel(tid uint32, comm string) {
	e.commState().setCachedFromKernel(tid, comm)
}

// applyPendingCommRefresh consumes a refresh request raised by the ring-buffer
// drop monitor and flags the whole comm cache for re-resolution.
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
func (e *eventLoop) handleProcessExecEvent(ev *types.ProcessExecEvent) {
	defer ev.Recycle()
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		// A control record with an empty comm carries no information; keeping
		// whatever is cached beats replacing a good label with nothing.
		return
	}
	e.setCachedCommFromKernel(ev.Tid, comm)
}

func procTidPathPrefix(tid uint32) string {
	return "/proc/" + strconv.FormatUint(uint64(tid), 10)
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

func resolveCommFromProcWithError(tid uint32) (string, error) {
	procPath := procTidPathPrefix(tid)
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
		commErr = nil
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
