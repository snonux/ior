package internal

import "C"

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/flamegraph"
	"ior/internal/types"
	. "ior/internal/types"
)

const sysEnterNameToHandleAtName = "name_to_handle_at"

type eventLoopConfig struct {
	pidFilter        int
	commFilter       string
	pathFilter       string
	liveFlamegraph   bool
	liveInterval     time.Duration
	collapsedFields  []string
	countField       string
	flamegraphName   string
	flamegraphEnable bool
	pprofEnable      bool
	plainMode        bool
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
}

func newCommResolver(comms map[uint32]string) *commResolver {
	if comms == nil {
		comms = make(map[uint32]string)
	}
	return &commResolver{
		comms:   comms,
		pending: make(map[uint32]struct{}),
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
	r.mu.Lock()
	if _, ok := r.comms[tid]; ok {
		r.mu.Unlock()
		return
	}
	if r.pending == nil {
		r.pending = make(map[uint32]struct{})
	}
	if _, ok := r.pending[tid]; ok {
		r.mu.Unlock()
		return
	}
	r.pending[tid] = struct{}{}
	r.mu.Unlock()

	go func() {
		comm := resolveCommFromProc(tid)
		r.mu.Lock()
		delete(r.pending, tid)
		if comm != "" {
			r.comms[tid] = comm
		}
		r.mu.Unlock()
	}()
}

type rawEventHandler func(raw []byte, ch chan<- *event.Pair)

type eventLoop struct {
	filter         *eventFilter
	enterEvs       map[uint32]*event.Pair // Temp. store of sys_enter tracepoints per Tid.
	pendingHandles map[uint32]string      // map of TID to pathname from name_to_handle_at
	files          map[int32]file.File    // Track all open files by file descriptor.
	fdTracker      *fdTracker
	comms          map[uint32]string // Program or thread name of the current Tid.
	commResolver   *commResolver
	prevPairTimes  map[uint32]uint64 // Previous event's time (to calculate time differences between two events)
	rawHandlers    map[EventType]rawEventHandler
	flamegraph     flamegraph.IorDataCollector // Storing all paths in a map structure for analysis
	liveTrie       *flamegraph.LiveTrie
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

func newEventLoop(cfg eventLoopConfig) *eventLoop {
	filesByFD := make(map[int32]file.File)
	commsByTID := make(map[uint32]string)

	el := &eventLoop{
		filter:         newEventFilter(cfg.commFilter, cfg.pathFilter),
		enterEvs:       make(map[uint32]*event.Pair),
		pendingHandles: make(map[uint32]string),
		files:          filesByFD,
		fdTracker:      newFDTracker(filesByFD),
		comms:          commsByTID,
		commResolver:   newCommResolver(commsByTID),
		prevPairTimes:  make(map[uint32]uint64),
		rawHandlers:    make(map[EventType]rawEventHandler),
		printCb:        func(ep *event.Pair) { fmt.Println(ep); ep.Recycle() },
		flamegraph:     flamegraph.New(cfg.flamegraphName),
		cfg:            cfg,
		done:           make(chan struct{}),
	}
	el.initRawHandlers()
	if cfg.liveFlamegraph {
		el.liveTrie = flamegraph.NewLiveTrie(cfg.collapsedFields, cfg.countField)
	}
	el.seedTrackedPidComm()
	return el
}

func (e *eventLoop) seedTrackedPidComm() {
	e.commState().seedTrackedPidComm(e.cfg.pidFilter)
}

func (e *eventLoop) fdState() *fdTracker {
	if e.files == nil {
		e.files = make(map[int32]file.File)
	}
	if e.fdTracker == nil {
		e.fdTracker = newFDTracker(e.files)
	}
	return e.fdTracker
}

func (e *eventLoop) commState() *commResolver {
	if e.comms == nil {
		e.comms = make(map[uint32]string)
	}
	if e.commResolver == nil {
		e.commResolver = newCommResolver(e.comms)
	}
	return e.commResolver
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

	if e.liveTrie != nil {
		fmt.Println("Starting live flamegraph server")
		go func() {
			if err := flamegraph.ServeLive(ctx, e.liveTrie, e.cfg.liveInterval); err != nil && ctx.Err() == nil {
				fmt.Println("Live flamegraph server error:", err)
			}
		}()
	}

	if e.cfg.flamegraphEnable {
		fmt.Println("Collecting flame graph stats, press Ctrl+C to stop")
		e.flamegraph.Start(ctx)
	}
	if e.cfg.pprofEnable {
		fmt.Println("Profiling, press Ctrl+C to stop")
	}
	if e.cfg.plainMode && !e.cfg.flamegraphEnable && !e.cfg.pprofEnable {
		fmt.Println(event.EventStreamHeader)
	}

	e.startTime = time.Now()
	for ep := range e.events(ctx, rawCh) {
		switch {
		case e.cfg.flamegraphEnable:
			e.flamegraph.Ch <- ep
		case e.liveTrie != nil:
			e.liveTrie.Ingest(ep)
		case e.cfg.pprofEnable:
			ep.Recycle()
		default:
			e.printCb(ep)
		}
		e.numSyscallsAfterFilter++
	}

	if e.cfg.flamegraphEnable {
		fmt.Println("Waiting for flamegraph")
		if err := <-e.flamegraph.Done; err != nil {
			e.notifyWarning(fmt.Sprintf("Flamegraph generation failed: %v", err))
			if e.warningCb == nil {
				fmt.Println("Flamegraph generation failed:", err)
			}
		}
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
			default:
				time.Sleep(time.Millisecond * 10)
			}
		}
	}()

	return ch
}

func (e *eventLoop) processRawEvent(raw []byte, ch chan<- *event.Pair) {
	e.numTracepoints++
	e.initRawHandlers()
	evType := EventType(raw[0])
	handler, ok := e.rawHandlers[evType]
	if !ok {
		e.notifyWarning(fmt.Sprintf("Dropped unhandled raw event type %d", evType))
		return
	}
	handler(raw, ch)
}

func (e *eventLoop) initRawHandlers() {
	if e.rawHandlers == nil {
		e.rawHandlers = make(map[EventType]rawEventHandler)
	}
	if len(e.rawHandlers) != 0 {
		return
	}

	e.rawHandlers[ENTER_OPEN_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		if ev, ok := e.filter.openEvent(NewOpenEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[EXIT_OPEN_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		e.tracepointExited(NewRetEvent(raw), ch)
	}
	e.rawHandlers[ENTER_FD_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		e.tracepointEntered(NewFdEvent(raw))
	}
	e.rawHandlers[EXIT_FD_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		e.tracepointExited(NewFdEvent(raw), ch)
	}
	e.rawHandlers[ENTER_NULL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		e.tracepointEntered(NewNullEvent(raw))
	}
	e.rawHandlers[EXIT_NULL_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		e.tracepointExited(NewNullEvent(raw), ch)
	}
	e.rawHandlers[EXIT_RET_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		e.tracepointExited(NewRetEvent(raw), ch)
	}
	e.rawHandlers[ENTER_NAME_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		if ev, ok := e.filter.nameEvent(NewNameEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[ENTER_PATH_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		if ev, ok := e.filter.pathEvent(NewPathEvent(raw)); ok {
			e.tracepointEntered(ev)
		}
	}
	e.rawHandlers[ENTER_FCNTL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		e.tracepointEntered(NewFcntlEvent(raw))
	}
	e.rawHandlers[ENTER_OPEN_BY_HANDLE_AT_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		e.tracepointEntered(NewOpenByHandleAtEvent(raw))
	}
	e.rawHandlers[ENTER_DUP3_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		e.tracepointEntered(NewDup3Event(raw))
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
	case *OpenEvent:
		e.enterEvs[tid] = event.NewPair(enterEv)
	default:
		// Only, when we have a comm name
		if _, ok := e.cachedComm(tid); ok {
			e.enterEvs[tid] = event.NewPair(enterEv)
		} else {
			// Probably not an issue.
			fmt.Println("WARN: No comm name for", enterEv, "process probably already vanished?")
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
	ch <- ep
}

func (e *eventLoop) handleTracepointExit(ep *event.Pair) bool {
	switch enterEv := ep.EnterEv.(type) {
	case *OpenEvent:
		return e.handleOpenExit(ep, enterEv)
	case *NameEvent:
		return e.handleNameExit(ep, enterEv)
	case *PathEvent:
		return e.handlePathExit(ep, enterEv)
	case *FdEvent:
		return e.handleFdExit(ep, enterEv)
	case *Dup3Event:
		return e.handleDup3Exit(ep, enterEv)
	case *OpenByHandleAtEvent:
		return e.handleOpenByHandleAtExit(ep, enterEv)
	case *NullEvent:
		return e.handleNullExit(ep, enterEv)
	case *FcntlEvent:
		return e.handleFcntlExit(ep, enterEv)
	default:
		e.recyclePair(ep, "Dropped malformed enter event")
		return false
	}
}

func (e *eventLoop) handleOpenExit(ep *event.Pair, openEv *OpenEvent) bool {
	retEvent, ok := ep.ExitEv.(*RetEvent)
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

func (e *eventLoop) handleNameExit(ep *event.Pair, nameEv *NameEvent) bool {
	ep.File = file.NewOldnameNewname(nameEv.Oldname[:], nameEv.Newname[:])
	ep.Comm = e.comm(nameEv.GetTid())
	return true
}

func (e *eventLoop) handlePathExit(ep *event.Pair, pathEv *PathEvent) bool {
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

	if ep.Is(SYS_ENTER_CREAT) {
		retEvent, ok := ep.ExitEv.(*RetEvent)
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

func (e *eventLoop) handleFdExit(ep *event.Pair, fdEv *FdEvent) bool {
	fd := fdEv.Fd
	if fdFile, ok := e.fdState().get(fd); ok {
		ep.File = fdFile
		if ep.Is(SYS_ENTER_CLOSE) {
			e.fdState().delete(fd)
		}
	} else {
		ep.File = file.NewFdWithPid(fd, fdEv.Pid)
	}
	if ep.Is(SYS_ENTER_CLOSE_RANGE) {
		// close_range provides (first, last), but fd_event only carries the first
		// argument, so we approximate by closing all tracked fds >= first.
		retEv, ok := ep.ExitEv.(*types.RetEvent)
		if ok && retEv.Ret == 0 {
			e.fdState().closeRangeFrom(fd)
		}
	}
	ep.Comm = e.comm(fdEv.GetTid())
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}

	if ep.Is(SYS_ENTER_DUP) || ep.Is(SYS_ENTER_DUP2) {
		fdFile, ok := ep.File.(file.FdFile)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup source event")
			return false
		}
		retEvent, ok := ep.ExitEv.(*RetEvent)
		if !ok {
			e.recyclePair(ep, "Dropped malformed dup exit event")
			return false
		}
		// Duplicating fd
		if newFd := int32(retEvent.Ret); newFd != -1 {
			e.fdState().set(newFd, fdFile.Dup(newFd))
		}
	}
	if ep.Is(SYS_ENTER_PIDFD_GETFD) {
		retEv, ok := ep.ExitEv.(*RetEvent)
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
	if retEv, ok := ep.ExitEv.(*RetEvent); ok {
		ep.Bytes = bytesFromRet(retEv)
	}
	return true
}

func (e *eventLoop) handleDup3Exit(ep *event.Pair, dup3Ev *Dup3Event) bool {
	fd := int32(dup3Ev.Fd)
	if fdFile, ok := e.fdState().get(fd); ok {
		ep.File = fdFile
	} else {
		ep.File = file.NewFdWithPid(fd, dup3Ev.Pid)
	}
	ep.Comm = e.comm(dup3Ev.GetTid())
	if !e.filter.eventPair(ep) {
		ep.Recycle()
		return false
	}

	fdFile, ok := ep.File.(file.FdFile)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 source event")
		return false
	}
	retEvent, ok := ep.ExitEv.(*RetEvent)
	if !ok {
		e.recyclePair(ep, "Dropped malformed dup3 exit event")
		return false
	}
	if newFd := int32(retEvent.Ret); newFd != -1 {
		duppedFdFile := fdFile.Dup(newFd)
		duppedFdFile.AddFlags(dup3Ev.Flags & syscall.O_CLOEXEC)
		e.fdState().set(newFd, duppedFdFile)
	}
	return true
}

func (e *eventLoop) handleOpenByHandleAtExit(ep *event.Pair, openByHandleEv *OpenByHandleAtEvent) bool {
	tid := openByHandleEv.GetTid()
	retEvent, ok := ep.ExitEv.(*RetEvent)
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

func (e *eventLoop) handleNullExit(ep *event.Pair, nullEv *NullEvent) bool {
	if ep.Is(SYS_ENTER_IO_URING_SETUP) {
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
	if ep.Is(SYS_ENTER_GETCWD) {
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

func (e *eventLoop) handleFcntlExit(ep *event.Pair, fcntlEv *FcntlEvent) bool {
	ep.Comm = e.comm(fcntlEv.GetTid())
	fd := int32(fcntlEv.Fd)
	if fdFile, ok := e.fdState().get(fd); ok {
		ep.File = fdFile
	} else {
		ep.File = file.NewFdWithPid(fd, fcntlEv.Pid)
	}
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

	fdFile, ok := ep.File.(file.FdFile)
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
		newFd := int32(retEvent.Ret)
		e.fdState().set(newFd, fdFile.Dup(newFd))
	case syscall.F_DUPFD_CLOEXEC:
		newFd := int32(retEvent.Ret)
		duppedFdFile := fdFile.Dup(newFd)
		duppedFdFile.AddFlags(syscall.O_CLOEXEC)
		e.fdState().set(newFd, duppedFdFile)
	}
	return true
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
