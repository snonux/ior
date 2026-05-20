package internal

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

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
	// emit() already handles a nil printCb safely, but guard here so that
	// hot-path event emission never pays for a nil check inside the loop.
	if e.printCb == nil {
		e.printCb = func(ep *event.Pair) { ep.Recycle() }
	}
	e.initRawHandlers()
	if e.cfg.synchronousRawProcessing {
		e.runSynchronously(ctx, rawCh)
		return
	}
	for ep := range e.events(ctx, rawCh) {
		e.emit(ep)
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
			e.drainPairs(pairs)
		case <-ctx.Done():
			fmt.Println("Stopping event loop")
			return
		}
	}
}

// drainPairs consumes all immediately available pairs from the buffered channel,
// routing each completed pair through the outputFormatter.
func (e *eventLoop) drainPairs(pairs <-chan *event.Pair) {
	for {
		select {
		case ep := <-pairs:
			e.emit(ep)
			e.numSyscallsAfterFilter++
		default:
			return
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
				// Recover from any panic inside a callback so a single
				// bad event cannot crash the entire process.
				e.processRawEventSafe(raw, ch)
			case <-ctx.Done():
				fmt.Println("Stopping event loop")
				return
			}
		}
	}()

	return ch
}

// processRawEventSafe calls processRawEvent and recovers from any panic,
// converting it into a warning notification so that one misbehaving event
// does not crash the whole process.
func (e *eventLoop) processRawEventSafe(raw []byte, ch chan<- *event.Pair) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			e.notifyWarning(fmt.Sprintf("Recovered panic in processRawEvent: %v\n%s", r, stack))
		}
	}()
	e.processRawEvent(raw, ch)
}

func (e *eventLoop) processRawEvent(raw []byte, ch chan<- *event.Pair) {
	if len(raw) == 0 {
		return
	}
	e.numTracepoints++
	evType := types.EventType(raw[0])
	handler, ok := e.rawHandlers[evType]
	if !ok {
		e.notifyWarning(fmt.Sprintf("Dropped unhandled raw event type %d", evType))
		return
	}
	handler(raw, ch)
}

// initRawHandlers registers all BPF event-type dispatch callbacks. It is
// idempotent: a second call after the map is populated is a no-op. Handlers
// are grouped by event class (open, fd, null, ret, name/path, misc) so that
// each helper stays under 30 lines.
func (e *eventLoop) initRawHandlers() {
	if e.rawHandlers == nil {
		e.rawHandlers = make(map[types.EventType]rawEventHandler)
	}
	if len(e.rawHandlers) != 0 {
		return
	}
	e.registerOpenHandlers()
	e.registerFdHandlers()
	e.registerNullHandlers()
	e.registerRetHandlers()
	e.registerNamePathHandlers()
	e.registerMiscHandlers()
	e.registerSocketHandlers()
	e.registerIPCHandlers()
	e.registerPollingHandlers()
	e.registerMemoryHandlers()
}

// registerOpenHandlers wires enter/exit handlers for open-family events.
func (e *eventLoop) registerOpenHandlers() {
	e.rawHandlers[types.ENTER_OPEN_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		openEv, ok := decodeRawEvent(e, types.ENTER_OPEN_EVENT, raw, types.NewOpenEventFast)
		if !ok {
			return
		}
		if e.Filter().MatchOpenEvent(openEv) {
			e.tracepointEntered(openEv)
		}
	}
	e.rawHandlers[types.EXIT_OPEN_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		retEv, ok := decodeRawEvent(e, types.EXIT_OPEN_EVENT, raw, types.NewRetEventFast)
		if !ok {
			return
		}
		e.tracepointExited(retEv, ch)
	}
}

// registerFdHandlers wires enter/exit handlers for fd-family events (read/write/close…).
func (e *eventLoop) registerFdHandlers() {
	e.rawHandlers[types.ENTER_FD_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		fdEv, ok := decodeRawEvent(e, types.ENTER_FD_EVENT, raw, types.NewFdEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(fdEv)
	}
	e.rawHandlers[types.EXIT_FD_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		fdEv, ok := decodeRawEvent(e, types.EXIT_FD_EVENT, raw, types.NewFdEventFast)
		if !ok {
			return
		}
		e.tracepointExited(fdEv, ch)
	}
}

// registerNullHandlers wires enter/exit handlers for syscalls with no interesting arguments.
func (e *eventLoop) registerNullHandlers() {
	e.rawHandlers[types.ENTER_NULL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		nullEv, ok := decodeRawEvent(e, types.ENTER_NULL_EVENT, raw, types.NewNullEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(nullEv)
	}
	e.rawHandlers[types.EXIT_NULL_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		nullEv, ok := decodeRawEvent(e, types.EXIT_NULL_EVENT, raw, types.NewNullEventFast)
		if !ok {
			return
		}
		e.tracepointExited(nullEv, ch)
	}
}

// registerRetHandlers wires the exit handler for generic return-value events.
func (e *eventLoop) registerRetHandlers() {
	e.rawHandlers[types.EXIT_RET_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		retEv, ok := decodeRawEvent(e, types.EXIT_RET_EVENT, raw, types.NewRetEventFast)
		if !ok {
			return
		}
		e.tracepointExited(retEv, ch)
	}
}

// registerNamePathHandlers wires enter handlers for name- and path-carrying events.
func (e *eventLoop) registerNamePathHandlers() {
	e.rawHandlers[types.ENTER_NAME_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		nameEv, ok := decodeRawEvent(e, types.ENTER_NAME_EVENT, raw, types.NewNameEventFast)
		if !ok {
			return
		}
		if e.Filter().MatchNameEvent(nameEv) {
			e.tracepointEntered(nameEv)
		}
	}
	e.rawHandlers[types.ENTER_PATH_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		pathEv, ok := decodeRawEvent(e, types.ENTER_PATH_EVENT, raw, types.NewPathEventFast)
		if !ok {
			return
		}
		if e.Filter().MatchPathEvent(pathEv) {
			e.tracepointEntered(pathEv)
		}
	}
}

// registerMiscHandlers wires enter handlers for fcntl, open_by_handle_at, and dup3.
func (e *eventLoop) registerMiscHandlers() {
	e.rawHandlers[types.ENTER_FCNTL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		fcntlEv, ok := decodeRawEvent(e, types.ENTER_FCNTL_EVENT, raw, types.NewFcntlEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(fcntlEv)
	}
	e.rawHandlers[types.ENTER_OPEN_BY_HANDLE_AT_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		openByHandleEv, ok := decodeRawEvent(e, types.ENTER_OPEN_BY_HANDLE_AT_EVENT, raw, types.NewOpenByHandleAtEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(openByHandleEv)
	}
	e.rawHandlers[types.ENTER_DUP3_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		dup3Ev, ok := decodeRawEvent(e, types.ENTER_DUP3_EVENT, raw, types.NewDup3EventFast)
		if !ok {
			return
		}
		e.tracepointEntered(dup3Ev)
	}
}

func (e *eventLoop) registerSocketHandlers() {
	e.rawHandlers[types.ENTER_SOCKET_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		socketEv, ok := decodeRawEvent(e, types.ENTER_SOCKET_EVENT, raw, types.NewSocketEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(socketEv)
	}
	e.rawHandlers[types.ENTER_SOCKETPAIR_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		socketpairEv, ok := decodeRawEvent(e, types.ENTER_SOCKETPAIR_EVENT, raw, types.NewSocketpairEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(socketpairEv)
	}
	e.rawHandlers[types.EXIT_SOCKETPAIR_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		socketpairEv, ok := decodeRawEvent(e, types.EXIT_SOCKETPAIR_EVENT, raw, types.NewSocketpairEventFast)
		if !ok {
			return
		}
		e.tracepointExited(socketpairEv, ch)
	}
	e.rawHandlers[types.ENTER_ACCEPT_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		acceptEv, ok := decodeRawEvent(e, types.ENTER_ACCEPT_EVENT, raw, types.NewAcceptEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(acceptEv)
	}
	e.rawHandlers[types.EXIT_ACCEPT_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		acceptEv, ok := decodeRawEvent(e, types.EXIT_ACCEPT_EVENT, raw, types.NewAcceptEventFast)
		if !ok {
			return
		}
		e.tracepointExited(acceptEv, ch)
	}
}

func (e *eventLoop) registerIPCHandlers() {
	e.rawHandlers[types.ENTER_PIPE_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		pipeEv, ok := decodeRawEvent(e, types.ENTER_PIPE_EVENT, raw, types.NewPipeEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(pipeEv)
	}
	e.rawHandlers[types.EXIT_PIPE_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		pipeEv, ok := decodeRawEvent(e, types.EXIT_PIPE_EVENT, raw, types.NewPipeEventFast)
		if !ok {
			return
		}
		e.tracepointExited(pipeEv, ch)
	}
	e.rawHandlers[types.ENTER_EVENTFD_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		eventfdEv, ok := decodeRawEvent(e, types.ENTER_EVENTFD_EVENT, raw, types.NewEventfdEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(eventfdEv)
	}
	e.rawHandlers[types.EXIT_EVENTFD_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		eventfdEv, ok := decodeRawEvent(e, types.EXIT_EVENTFD_EVENT, raw, types.NewEventfdEventFast)
		if !ok {
			return
		}
		e.tracepointExited(eventfdEv, ch)
	}
}

func (e *eventLoop) registerPollingHandlers() {
	e.rawHandlers[types.ENTER_EPOLL_CTL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		epollCtlEv, ok := decodeRawEvent(e, types.ENTER_EPOLL_CTL_EVENT, raw, types.NewEpollCtlEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(epollCtlEv)
	}
	e.rawHandlers[types.ENTER_POLL_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		pollEv, ok := decodeRawEvent(e, types.ENTER_POLL_EVENT, raw, types.NewPollEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(pollEv)
	}
}

func (e *eventLoop) registerMemoryHandlers() {
	e.rawHandlers[types.ENTER_MEM_EVENT] = func(raw []byte, _ chan<- *event.Pair) {
		memEv, ok := decodeRawEvent(e, types.ENTER_MEM_EVENT, raw, types.NewMemEventFast)
		if !ok {
			return
		}
		e.tracepointEntered(memEv)
	}
}

func decodeRawEvent[T any](e *eventLoop, eventType types.EventType, raw []byte, decode func([]byte) *T) (*T, bool) {
	decoded := decode(raw)
	if decoded == nil {
		e.dropMalformedRawEvent(eventType, raw)
		return nil, false
	}
	return decoded, true
}

func (e *eventLoop) tracepointEntered(enterEv event.Event) {
	tid := enterEv.GetTid()
	// Schedule comm lookup as early as possible to reduce races for short-lived processes.
	e.queueCommLookup(tid)
	if !e.Filter().UsesCommFilter() {
		e.pairs.set(enterEv)
		return
	}

	switch enterEv.(type) {
	case *types.OpenEvent:
		e.pairs.set(enterEv)
	default:
		// Only, when we have a comm name
		if _, ok := e.cachedComm(tid); ok {
			e.pairs.set(enterEv)
		} else {
			e.notifyWarning(fmt.Sprintf("No comm name for %v process probably already vanished?", enterEv))
		}
	}
}

func (e *eventLoop) tracepointExited(exitEv event.Event, ch chan<- *event.Pair) {
	ep, ok := e.pairs.consume(exitEv.GetTid())
	if !ok {
		exitEv.Recycle()
		return
	}
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
	applyRetBytes(ep)
	applyAddressSpaceBytes(ep)
	tid := ep.EnterEv.GetTid()
	ep.CalculateDurations(e.pairs.prevTime(tid))
	e.pairs.setPrevTime(tid, ep.ExitEv.GetTime())
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
