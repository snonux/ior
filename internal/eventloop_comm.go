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

// resolveCommTimeout caps each procfs read so a frozen cgroup cannot stall
// a lookup worker indefinitely and block clean shutdown.
const resolveCommTimeout = time.Second

type commResolver struct {
	comms map[uint32]string

	mu       sync.RWMutex
	pending  map[uint32]struct{}
	closed   bool
	commAges map[uint32]uint64 // insertion/access order per TID, for comms LRU eviction
	commAge  uint64            // monotonic counter for comms LRU ordering
	maxComms int               // max cached comms before pruning; 0 = default

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
		comms:   comms,
		pending: make(map[uint32]struct{}),
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
		r.comms = make(map[uint32]string)
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
		// Default resolver wraps resolveCommFromProcWithError, which does not
		// accept a context itself, so we honour cancellation by returning early
		// when the context deadline is already exceeded before the call returns.
		r.resolveFn = func(ctx context.Context, tid uint32) (string, error) {
			comm, err := resolveCommFromProcWithError(tid)
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return comm, err
		}
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
		// Each procfs read gets an independent timeout so that a frozen cgroup
		// or a slow /proc entry cannot block a worker goroutine indefinitely
		// and stall shutdown (which waits on workersWG).
		ctx, cancel := context.WithTimeout(context.Background(), resolveCommTimeout)
		comm, err := r.resolveFn(ctx, tid)
		cancel()
		r.mu.Lock()
		delete(r.pending, tid)
		if comm != "" {
			r.setCommLocked(tid, comm)
		}
		r.mu.Unlock()
		r.notifyResolveFailure(tid, err)
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
		// Use a short timeout here too; seeding happens at startup and a stall
		// would delay the entire event loop initialisation.
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
	r.mu.Lock()
	defer r.mu.Unlock()
	comm, ok := r.comms[tid]
	if ok {
		// Refresh the LRU age on use so active TIDs stay cached.
		r.touchCommLocked(tid)
	}
	return comm, ok
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
	r.comms[tid] = comm
	r.commAges[tid] = r.commAge
	r.pruneCommsLocked()
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
	if r.pending == nil {
		r.pending = make(map[uint32]struct{})
	}
	if _, ok := r.pending[tid]; ok {
		return
	}
	r.pending[tid] = struct{}{}

	// Keep event processing non-blocking if resolver workers are saturated.
	select {
	case r.lookupQueue <- tid:
	default:
		delete(r.pending, tid)
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
// correct from the very first post-exec event.
func (e *eventLoop) handleProcessExecEvent(ev *types.ProcessExecEvent) {
	defer ev.Recycle()
	comm := types.StringValue(ev.Comm[:])
	if comm == "" {
		return
	}
	e.setCachedComm(ev.Tid, comm)
}

func procTidPathPrefix(tid uint32) string {
	return "/proc/" + strconv.FormatUint(uint64(tid), 10)
}

func resolveCommFromProc(tid uint32) string {
	comm, _ := resolveCommFromProcWithError(tid)
	return comm
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
