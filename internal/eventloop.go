package internal

import "C"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

const sysEnterNameToHandleAtName = "name_to_handle_at"

const (
	defaultCommLookupWorkers   = 4
	defaultCommLookupQueueSize = 512
)

type eventLoopConfig struct {
	pidFilter       int
	commFilter      string
	pathFilter      string
	collapsedFields []string
	countField      string
	pprofEnable     bool
	plainMode       bool
	// synchronousRawProcessing keeps raw decode and callback emission in a
	// single goroutine for deterministic test execution.
	synchronousRawProcessing bool
	fdTracker                *fdTracker
	commResolver             *commResolver
}

type fdTracker struct {
	files map[int32]file.File
}

func newFDTracker(files map[int32]file.File) *fdTracker {
	if files == nil {
		files = make(map[int32]file.File)
	}
	return &fdTracker{files: files}
}

func (t *fdTracker) get(fd int32) (file.File, bool) {
	f, ok := t.files[fd]
	return f, ok
}

func (t *fdTracker) set(fd int32, f file.File) {
	t.files[fd] = f
}

func (t *fdTracker) delete(fd int32) {
	delete(t.files, fd)
}

func (t *fdTracker) closeRangeFrom(first int32) {
	for fd := range t.files {
		if fd >= first {
			delete(t.files, fd)
		}
	}
}

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

type rawEventHandler func(raw []byte, ch chan<- *event.Pair)
type tracepointExitHandler func(ep *event.Pair) bool

type eventLoop struct {
	filter         *eventFilter
	enterEvs       map[uint32]*event.Pair // Temp. store of sys_enter tracepoints per Tid.
	pendingHandles map[uint32]string      // map of TID to pathname from name_to_handle_at
	fdTracker      *fdTracker
	procFdCache    map[uint64]*file.FdFile // Cache procfs-resolved metadata for unknown fds.
	commResolver   *commResolver
	prevPairTimes  map[uint32]uint64 // Previous event's time (to calculate time differences between two events)
	rawHandlers    map[types.EventType]rawEventHandler
	exitHandlers   map[reflect.Type]tracepointExitHandler
	printCb        func(ep *event.Pair) // Callback to print the event
	warningCb      func(message string) // Optional callback for non-fatal event processing warnings
	cfg            eventLoopConfig

	// Statistics
	numTracepoints          uint
	numTracepointMismatches uint
	numSyscalls             uint
	numSyscallsAfterFilter  uint
	startTime               time.Time
	done                    chan struct{}
}

func newEventLoop(cfg eventLoopConfig) (*eventLoop, error) {
	fdState := configuredFDTracker(cfg.fdTracker)
	commState := configuredCommResolver(cfg.commResolver)
	filter, err := newEventFilter(cfg.commFilter, cfg.pathFilter)
	if err != nil {
		return nil, fmt.Errorf("create event filter: %w", err)
	}

	el := &eventLoop{
		filter:         filter,
		enterEvs:       make(map[uint32]*event.Pair),
		pendingHandles: make(map[uint32]string),
		fdTracker:      fdState,
		procFdCache:    make(map[uint64]*file.FdFile),
		commResolver:   commState,
		prevPairTimes:  make(map[uint32]uint64),
		rawHandlers:    make(map[types.EventType]rawEventHandler),
		exitHandlers:   make(map[reflect.Type]tracepointExitHandler),
		printCb:        func(ep *event.Pair) { fmt.Println(ep); ep.Recycle() },
		cfg:            cfg,
		done:           make(chan struct{}),
	}
	el.initRawHandlers()
	el.initExitHandlers()
	el.configureOutputCallback()
	el.seedTrackedPidComm()
	return el, nil
}

func configuredFDTracker(injected *fdTracker) *fdTracker {
	if injected == nil {
		return newFDTracker(nil)
	}
	if injected.files == nil {
		injected.files = make(map[int32]file.File)
	}
	return injected
}

func configuredCommResolver(injected *commResolver) *commResolver {
	if injected == nil {
		return newCommResolver(nil)
	}
	if injected.comms == nil {
		injected.comms = make(map[uint32]string)
	}
	if injected.pending == nil {
		injected.pending = make(map[uint32]struct{})
	}
	injected.ensureLookupConfig()
	return injected
}

func (e *eventLoop) seedTrackedPidComm() {
	e.commState().seedTrackedPidComm(e.cfg.pidFilter)
}

func (e *eventLoop) fdState() *fdTracker {
	if e.fdTracker == nil {
		e.fdTracker = newFDTracker(nil)
	}
	if e.fdTracker.files == nil {
		e.fdTracker.files = make(map[int32]file.File)
	}
	return e.fdTracker
}

func (e *eventLoop) commState() *commResolver {
	if e.commResolver == nil {
		e.commResolver = newCommResolver(nil)
	}
	if e.commResolver.comms == nil {
		e.commResolver.comms = make(map[uint32]string)
	}
	if e.commResolver.pending == nil {
		e.commResolver.pending = make(map[uint32]struct{})
	}
	e.commResolver.ensureLookupConfig()
	return e.commResolver
}

func (e *eventLoop) configureOutputCallback() {
	switch {
	case e.cfg.pprofEnable:
		e.printCb = func(ep *event.Pair) {
			ep.Recycle()
		}
	}
}

func (e *eventLoop) stats() string {
	fmt.Println("Waiting for stats to be ready")
	<-e.done
	duration := time.Since(e.startTime)

	stats := fmt.Sprintf(
		"Statistics:\n"+
			"\tduration: %v\n"+
			"\ttracepoints: %v (%.2f/s) with %d mismatches (%.2f%%)\n"+
			"\tsyscalls: %d (%.2f/s)\n"+
			"\tsyscalls after filter: %d (%.2f/s)\n",
		duration,
		e.numTracepoints, float64(e.numTracepoints)/duration.Seconds(), e.numTracepointMismatches, (float64(e.numTracepointMismatches)/float64(e.numTracepoints))*100,
		e.numSyscalls, float64(e.numSyscalls)/duration.Seconds(),
		e.numSyscallsAfterFilter, float64(e.numSyscallsAfterFilter)/duration.Seconds(),
	)

	return stats
}

func (e *eventLoop) run(ctx context.Context, rawCh <-chan []byte) {
	defer close(e.done)
	defer e.shutdownCommResolver()

	if e.cfg.pprofEnable {
		fmt.Println("Profiling, press Ctrl+C to stop")
	}
	if e.cfg.plainMode && !e.cfg.pprofEnable {
		fmt.Println(event.EventStreamHeader)
	}

	e.startTime = time.Now()
	if e.printCb == nil {
		e.printCb = func(ep *event.Pair) { ep.Recycle() }
	}
	if e.cfg.synchronousRawProcessing {
		e.runSynchronously(ctx, rawCh)
		return
	}
	for ep := range e.events(ctx, rawCh) {
		e.printCb(ep)
		e.numSyscallsAfterFilter++
	}
}

func (e *eventLoop) runSynchronously(ctx context.Context, rawCh <-chan []byte) {
	pairs := make(chan *event.Pair, 1)

	for {
		select {
		case raw, ok := <-rawCh:
			if !ok {
				return
			}
			if len(raw) == 0 {
				continue
			}
			e.processRawEvent(raw, pairs)
			for {
				select {
				case ep := <-pairs:
					e.printCb(ep)
					e.numSyscallsAfterFilter++
				default:
					goto nextRaw
				}
			}
		case <-ctx.Done():
			fmt.Println("Stopping event loop")
			return
		}
	nextRaw:
	}
}

func (e *eventLoop) events(ctx context.Context, rawCh <-chan []byte) <-chan *event.Pair {
	ch := make(chan *event.Pair)

	go func() {
		defer close(ch)

		for {
			select {
			case raw, ok := <-rawCh:
				if !ok {
					return
				}
				if len(raw) == 0 {
					continue
				}
				e.processRawEvent(raw, ch)
			case <-ctx.Done():
				fmt.Println("Stopping event loop")
				return
			}
		}
	}()

	return ch
}

func (e *eventLoop) processRawEvent(raw []byte, ch chan<- *event.Pair) {
	e.numTracepoints++
	e.initRawHandlers()
	evType := types.EventType(raw[0])
	handler, ok := e.rawHandlers[evType]
	if !ok {
		e.notifyWarning(fmt.Sprintf("Dropped unhandled raw event type %d", evType))
		return
	}
	handler(raw, ch)
}

func (e *eventLoop) initRawHandlers() {
	if e.rawHandlers == nil {
		e.rawHandlers = make(map[types.EventType]rawEventHandler)
	}
	if len(e.rawHandlers) != 0 {
		return
	}

	e.rawHandlers[types.ENTER_OPEN_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		openEv := types.NewOpenEventFast(raw)
		if openEv == nil {
			e.dropMalformedRawEvent(types.ENTER_OPEN_EVENT, raw)
			return
		}
		if ev, ok := e.filter.openEvent(openEv); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[types.EXIT_OPEN_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		retEv := types.NewRetEventFast(raw)
		if retEv == nil {
			e.dropMalformedRawEvent(types.EXIT_OPEN_EVENT, raw)
			return
		}
		e.tracepointExited(retEv, ch)
	}
	e.rawHandlers[types.ENTER_FD_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		fdEv := types.NewFdEventFast(raw)
		if fdEv == nil {
			e.dropMalformedRawEvent(types.ENTER_FD_EVENT, raw)
			return
		}
		e.tracepointEntered(fdEv)
	}
	e.rawHandlers[types.EXIT_FD_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		fdEv := types.NewFdEventFast(raw)
		if fdEv == nil {
			e.dropMalformedRawEvent(types.EXIT_FD_EVENT, raw)
			return
		}
		e.tracepointExited(fdEv, ch)
	}
	e.rawHandlers[types.ENTER_NULL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		nullEv := types.NewNullEventFast(raw)
		if nullEv == nil {
			e.dropMalformedRawEvent(types.ENTER_NULL_EVENT, raw)
			return
		}
		e.tracepointEntered(nullEv)
	}
	e.rawHandlers[types.EXIT_NULL_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		nullEv := types.NewNullEventFast(raw)
		if nullEv == nil {
			e.dropMalformedRawEvent(types.EXIT_NULL_EVENT, raw)
			return
		}
		e.tracepointExited(nullEv, ch)
	}
	e.rawHandlers[types.EXIT_RET_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		retEv := types.NewRetEventFast(raw)
		if retEv == nil {
			e.dropMalformedRawEvent(types.EXIT_RET_EVENT, raw)
			return
		}
		e.tracepointExited(retEv, ch)
	}
	e.rawHandlers[types.ENTER_NAME_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		nameEv := types.NewNameEventFast(raw)
		if nameEv == nil {
			e.dropMalformedRawEvent(types.ENTER_NAME_EVENT, raw)
			return
		}
		if ev, ok := e.filter.nameEvent(nameEv); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[types.ENTER_PATH_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		pathEv := types.NewPathEventFast(raw)
		if pathEv == nil {
			e.dropMalformedRawEvent(types.ENTER_PATH_EVENT, raw)
			return
		}
		if ev, ok := e.filter.pathEvent(pathEv); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[types.ENTER_FCNTL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		fcntlEv := types.NewFcntlEventFast(raw)
		if fcntlEv == nil {
			e.dropMalformedRawEvent(types.ENTER_FCNTL_EVENT, raw)
			return
		}
		e.tracepointEntered(fcntlEv)
	}
	e.rawHandlers[types.ENTER_OPEN_BY_HANDLE_AT_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		openByHandleEv := types.NewOpenByHandleAtEventFast(raw)
		if openByHandleEv == nil {
			e.dropMalformedRawEvent(types.ENTER_OPEN_BY_HANDLE_AT_EVENT, raw)
			return
		}
		e.tracepointEntered(openByHandleEv)
	}
	e.rawHandlers[types.ENTER_DUP3_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		dup3Ev := types.NewDup3EventFast(raw)
		if dup3Ev == nil {
			e.dropMalformedRawEvent(types.ENTER_DUP3_EVENT, raw)
			return
		}
		e.tracepointEntered(dup3Ev)
	}
}

func (e *eventLoop) tracepointEntered(enterEv event.Event) {
	tid := enterEv.GetTid()
	// Schedule comm lookup as early as possible to reduce races for short-lived processes.
	e.queueCommLookup(tid)
	if !e.filter.commFilterEnable {
		e.enterEvs[tid] = event.NewPair(enterEv)
		return
	}

	switch enterEv.(type) {
	case *types.OpenEvent:
		e.enterEvs[tid] = event.NewPair(enterEv)
	default:
		// Only, when we have a comm name
		if _, ok := e.cachedComm(tid); ok {
			e.enterEvs[tid] = event.NewPair(enterEv)
		} else {
			e.notifyWarning(fmt.Sprintf("No comm name for %v process probably already vanished?", enterEv))
		}
	}
}

func (e *eventLoop) tracepointExited(exitEv event.Event, ch chan<- *event.Pair) {
	ep, ok := e.enterEvs[exitEv.GetTid()]
	if !ok {
		exitEv.Recycle()
		return
	}
	delete(e.enterEvs, exitEv.GetTid())
	ep.ExitEv = exitEv
	e.numSyscalls++

	// Expect ID one lower, otherwise, enter and exit tracepoints
	// don't match up. E.g.:
	// enterEv:SYS_ENTER_OPEN => exitEv:SYS_EXIT_OPEN
	if ep.EnterEv.GetTraceId()-1 != ep.ExitEv.GetTraceId() {
		e.numTracepointMismatches++
		e.notifyWarning("Dropped tracepoint pair with mismatched enter/exit IDs")
		ep.Recycle()
		return
	}
	if !e.handleTracepointExit(ep) {
		return
	}
	prevPairTime, _ := e.prevPairTimes[ep.EnterEv.GetTid()]
	ep.CalculateDurations(prevPairTime)
	e.prevPairTimes[ep.EnterEv.GetTid()] = ep.ExitEv.GetTime()
	e.freezePairForEmission(ep)
	ch <- ep
}

func (e *eventLoop) freezePairForEmission(ep *event.Pair) {
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		return
	}
	ep.File = fdFile.Dup(fdFile.FD())
}

func (e *eventLoop) initExitHandlers() {
	e.exitHandlers = map[reflect.Type]tracepointExitHandler{
		reflect.TypeOf(&types.OpenEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.OpenEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed open enter event")
				return false
			}
			return e.handleOpenExit(ep, enterEv)
		},
		reflect.TypeOf(&types.NameEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.NameEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed name enter event")
				return false
			}
			return e.handleNameExit(ep, enterEv)
		},
		reflect.TypeOf(&types.PathEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.PathEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed path enter event")
				return false
			}
			return e.handlePathExit(ep, enterEv)
		},
		reflect.TypeOf(&types.FdEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.FdEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed fd enter event")
				return false
			}
			return e.handleFdExit(ep, enterEv)
		},
		reflect.TypeOf(&types.Dup3Event{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.Dup3Event)
			if !ok {
				e.recyclePair(ep, "Dropped malformed dup3 enter event")
				return false
			}
			return e.handleDup3Exit(ep, enterEv)
		},
		reflect.TypeOf(&types.OpenByHandleAtEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.OpenByHandleAtEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed open_by_handle_at enter event")
				return false
			}
			return e.handleOpenByHandleAtExit(ep, enterEv)
		},
		reflect.TypeOf(&types.NullEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.NullEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed null enter event")
				return false
			}
			return e.handleNullExit(ep, enterEv)
		},
		reflect.TypeOf(&types.FcntlEvent{}): func(ep *event.Pair) bool {
			enterEv, ok := ep.EnterEv.(*types.FcntlEvent)
			if !ok {
				e.recyclePair(ep, "Dropped malformed fcntl enter event")
				return false
			}
			return e.handleFcntlExit(ep, enterEv)
		},
	}
}

func (e *eventLoop) exitHandlerRegistry() map[reflect.Type]tracepointExitHandler {
	if e.exitHandlers == nil {
		e.initExitHandlers()
	}
	return e.exitHandlers
}

func (e *eventLoop) handleTracepointExit(ep *event.Pair) bool {
	handler, ok := e.exitHandlerRegistry()[reflect.TypeOf(ep.EnterEv)]
	if !ok {
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
	return handler(ep)
}

func (e *eventLoop) handleOpenExit(ep *event.Pair, openEv *types.OpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open exit event")
		return false
	}

	comm := types.StringValue(openEv.Comm[:])
	ep.Comm = comm
	if fd := int32(retEvent.Ret); fd >= 0 {
		fdFile := file.NewFd(fd, types.StringValue(openEv.Filename[:]), openEv.Flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	} else {
		// Keep path information for failed opens so error scenarios remain observable.
		ep.File = file.NewPathname(openEv.Filename[:])
	}
	e.setCachedComm(openEv.Tid, comm)
	return true
}

func (e *eventLoop) handleNameExit(ep *event.Pair, nameEv *types.NameEvent) bool {
	ep.File = file.NewOldnameNewname(nameEv.Oldname[:], nameEv.Newname[:])
	ep.Comm = e.comm(nameEv.GetTid())
	return true
}

func (e *eventLoop) handlePathExit(ep *event.Pair, pathEv *types.PathEvent) bool {
	if pathEv.GetTraceId().Name() == sysEnterNameToHandleAtName {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok || retEv.Ret < 0 {
			ep.Recycle()
			return false
		}
		e.pendingHandles[pathEv.GetTid()] = types.StringValue(pathEv.Pathname[:])
		ep.Recycle()
		return false
	}

	if ep.Is(types.SYS_ENTER_CREAT) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed creat exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			fdFile := file.NewFd(fd, types.StringValue(pathEv.Pathname[:]),
				syscall.O_CREAT|syscall.O_WRONLY|syscall.O_TRUNC)
			e.fdState().set(fd, fdFile)
			ep.File = fdFile
		}
	} else {
		ep.File = file.NewPathname(pathEv.Pathname[:])
	}
	ep.Comm = e.comm(pathEv.GetTid())
	return true
}

func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *types.FdEvent) bool {
	fd := fdEv.Fd
	ep.File = e.resolveFdFile(fd, fdEv.Pid)
	if ep.Is(types.SYS_ENTER_CLOSE) {
		e.fdState().delete(fd)
		e.deleteProcFdCache(fd, fdEv.Pid)
	}
	if ep.Is(types.SYS_ENTER_CLOSE_RANGE) {
		// close_range provides (first, last), but fd_event only carries the first
		// argument, so we approximate by closing all tracked fds >= first.
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if ok && retEv.Ret == 0 {
			e.fdState().closeRangeFrom(fd)
			e.deleteProcFdCacheFrom(fd, fdEv.Pid)
		}
	}
	ep.Comm = e.comm(fdEv.GetTid())
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}

	if ep.Is(types.SYS_ENTER_DUP) || ep.Is(types.SYS_ENTER_DUP2) {
		fdFile, ok := ep.File.(*file.FdFile)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup source event")
			return false
		}
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup exit event")
			return false
		}
		// Duplicating fd
		e.registerDup(fdFile, int32(retEvent.Ret), 0)
	}
	if ep.Is(types.SYS_ENTER_PIDFD_GETFD) {
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed pidfd_getfd exit event")
			return false
		}
		if newFd := int32(retEv.Ret); newFd >= 0 {
			transferredFile := file.NewFdWithPid(newFd, fdEv.Pid)
			e.fdState().set(newFd, transferredFile)
			ep.File = transferredFile
		}
	}
	if retEv, ok := ep.ExitEv.(*types.RetEvent); ok {
		ep.Bytes = bytesFromRet(retEv)
	}
	return true
}

func (e *eventLoop) handleDup3Exit(ep *event.Pair, dup3Ev *types.Dup3Event) bool {
	fd := int32(dup3Ev.Fd)
	ep.File = e.resolveFdFile(fd, dup3Ev.Pid)
	ep.Comm = e.comm(dup3Ev.GetTid())
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 source event")
		return false
	}
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 exit event")
		return false
	}
	e.registerDup(fdFile, int32(retEvent.Ret), dup3Ev.Flags&syscall.O_CLOEXEC)
	return true
}

func (e *eventLoop) handleOpenByHandleAtExit(ep *event.Pair, openByHandleEv *types.OpenByHandleAtEvent) bool {
	tid := openByHandleEv.GetTid()
	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed open_by_handle_at exit event")
		return false
	}

	fd := int32(retEvent.Ret)
	if fd < 0 {
		ep.Recycle()
		return false
	}

	if pathname, ok := e.pendingHandles[tid]; ok {
		delete(e.pendingHandles, tid)
		fdFile := file.NewFd(fd, pathname, openByHandleEv.Flags)
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	} else {
		fdFile := file.NewFdWithPid(fd, openByHandleEv.Pid)
		if fdFile.Flags() == file.Flags(-1) {
			fdFile.SetFlags(openByHandleEv.Flags)
		}
		e.fdState().set(fd, fdFile)
		ep.File = fdFile
	}
	ep.Comm = e.comm(tid)
	return true
}

func (e *eventLoop) handleNullExit(ep *event.Pair, nullEv *types.NullEvent) bool {
	if ep.Is(types.SYS_ENTER_IO_URING_SETUP) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed io_uring_setup exit event")
			return false
		}
		if fd := int32(retEvent.Ret); fd >= 0 {
			fdFile := file.NewFdWithPid(fd, nullEv.Pid)
			e.fdState().set(fd, fdFile)
			ep.File = fdFile
		}
	}
	if ep.Is(types.SYS_ENTER_GETCWD) {
		retEvent, ok := ep.ExitEv.(*types.RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed getcwd exit event")
			return false
		}
		if retEvent.Ret > 0 {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", nullEv.GetTid())); err == nil {
				ep.File = file.NewPathname([]byte(cwd))
			}
		}
	}
	ep.Comm = e.comm(nullEv.GetTid())
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}
	return true
}

func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *types.FcntlEvent) bool {
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	ep.File = e.resolveFdFile(fd, fcntlEv.Pid)
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}

	retEvent, ok := ep.ExitEv.(*types.RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl exit event")
		return false
	}
	// Syscall returned -1, nothing was changed with the fd
	if retEvent.Ret == -1 {
		return true
	}

	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed fcntl file event")
		return false
	}

	// See fcntl(2) for implementation details
	switch fcntlEv.Cmd {
	case syscall.F_SETFL:
		const canChange = syscall.O_APPEND | syscall.O_ASYNC | syscall.O_DIRECT | syscall.O_NOATIME | syscall.O_NONBLOCK
		fdFile.SetFlags(int32(fcntlEv.Arg) & int32(canChange))
		ep.File = fdFile
		e.fdState().set(fd, fdFile)
	case syscall.F_DUPFD:
		e.registerDup(fdFile, int32(retEvent.Ret), 0)
	case syscall.F_DUPFD_CLOEXEC:
		e.registerDup(fdFile, int32(retEvent.Ret), syscall.O_CLOEXEC)
	}
	return true
}

func (e *eventLoop) registerDup(fdFile *file.FdFile, newFd int32, extraFlags int32) {
	if newFd < 0 {
		return
	}
	duppedFdFile := fdFile.Dup(newFd)
	if extraFlags != 0 {
		duppedFdFile.AddFlags(extraFlags)
	}
	e.fdState().set(newFd, duppedFdFile)
}

func (e *eventLoop) recyclePair(ep *event.Pair, warning string) {
	e.notifyWarning(warning)
	ep.Recycle()
}

func (e *eventLoop) notifyWarning(message string) {
	if e.warningCb == nil || message == "" {
		return
	}
	e.warningCb(message)
}

func (e *eventLoop) dropMalformedRawEvent(evType types.EventType, raw []byte) {
	e.notifyWarning(fmt.Sprintf("Dropped malformed raw event type %d (len=%d)", evType, len(raw)))
}

func (e *eventLoop) resolveFdFile(fd int32, pid uint32) file.File {
	if fdFile, ok := e.fdState().get(fd); ok {
		return fdFile
	}
	if fd < 0 {
		return file.NewFd(fd, "", -1)
	}

	if cached, ok := e.cachedProcFdFile(fd, pid); ok {
		return cached
	}

	// Cache first procfs resolution to avoid repeated /proc lookups for hot unknown FDs.
	discovered := file.NewFdWithPid(fd, pid)
	e.setProcFdCache(fd, pid, discovered)
	return discovered
}

func (e *eventLoop) cachedProcFdFile(fd int32, pid uint32) (*file.FdFile, bool) {
	cache, ok := e.procFdCacheState()[procFdCacheKey(pid, fd)]
	return cache, ok
}

func (e *eventLoop) setProcFdCache(fd int32, pid uint32, resolved *file.FdFile) {
	e.procFdCacheState()[procFdCacheKey(pid, fd)] = resolved
}

func (e *eventLoop) deleteProcFdCache(fd int32, pid uint32) {
	delete(e.procFdCacheState(), procFdCacheKey(pid, fd))
}

func (e *eventLoop) deleteProcFdCacheFrom(first int32, pid uint32) {
	cache := e.procFdCacheState()
	for key := range cache {
		cachePid := uint32(key >> 32)
		cacheFd := int32(uint32(key))
		if cachePid == pid && cacheFd >= first {
			delete(cache, key)
		}
	}
}

func (e *eventLoop) procFdCacheState() map[uint64]*file.FdFile {
	if e.procFdCache == nil {
		e.procFdCache = make(map[uint64]*file.FdFile)
	}
	return e.procFdCache
}

func procFdCacheKey(pid uint32, fd int32) uint64 {
	return uint64(pid)<<32 | uint64(uint32(fd))
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

func resolveCommFromProc(tid uint32) string {
	commPath := fmt.Sprintf("/proc/%d/comm", tid)
	if data, err := os.ReadFile(commPath); err == nil {
		comm := string(data)
		if len(comm) > 0 && comm[len(comm)-1] == '\n' {
			comm = comm[:len(comm)-1]
		}
		if comm != "" {
			return comm
		}
	}
	if linkName, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", tid)); err == nil {
		linkName = filepath.Base(linkName)
		return linkName
	}
	return ""
}

// bytesFromRet extracts the number of bytes transferred from a RetEvent.
// Returns 0 for nil events, errors (Ret <= 0), or unclassified syscalls.
func bytesFromRet(retEv *types.RetEvent) uint64 {
	if retEv == nil || retEv.Ret <= 0 {
		return 0
	}
	switch retEv.RetType {
	case types.READ_CLASSIFIED, types.WRITE_CLASSIFIED, types.TRANSFER_CLASSIFIED:
		return uint64(retEv.Ret)
	default:
		return 0
	}
}
