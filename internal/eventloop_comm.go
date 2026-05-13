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
)

// resolveCommTimeout caps each procfs read so a frozen cgroup cannot stall
// a lookup worker indefinitely and block clean shutdown.
const resolveCommTimeout = time.Second

type commResolver struct {
	comms map[uint32]string

	mu      sync.RWMutex
	pending map[uint32]struct{}
	closed  bool

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
	r.ensureLookupConfig()
	return r
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
			r.comms[tid] = comm
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
	r.mu.RLock()
	defer r.mu.RUnlock()
	comm, ok := r.comms[tid]
	return comm, ok
}

func (r *commResolver) setCached(tid uint32, comm string) {
	if comm == "" {
		return
	}
	r.mu.Lock()
	r.comms[tid] = comm
	r.mu.Unlock()
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
