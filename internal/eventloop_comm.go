package internal

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type commResolver struct {
	comms map[uint32]string

	mu      sync.RWMutex
	pending map[uint32]struct{}
	closed  bool

	lookupQueue      chan uint32
	lookupWorkers    int
	resolveFn        func(uint32) string
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
		r.resolveFn = resolveCommFromProc
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
		comm := r.resolveFn(tid)
		r.mu.Lock()
		delete(r.pending, tid)
		if comm != "" {
			r.comms[tid] = comm
		}
		r.mu.Unlock()
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
		if comm := resolveCommFromProc(tid); comm != "" {
			r.setCached(tid, comm)
			continue
		}
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
	procPath := procTidPathPrefix(tid)
	if data, err := os.ReadFile(procPath + "/comm"); err == nil {
		comm := string(data)
		if len(comm) > 0 && comm[len(comm)-1] == '\n' {
			comm = comm[:len(comm)-1]
		}
		if comm != "" {
			return comm
		}
	}
	if linkName, err := os.Readlink(procPath + "/exe"); err == nil {
		linkName = filepath.Base(linkName)
		return linkName
	}
	return ""
}
