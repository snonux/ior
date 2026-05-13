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
	if e.printCb == nil {
		e.printCb = func(ep *event.Pair) { ep.Recycle() }
	}
	e.initRawHandlers()
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
			e.drainPairs(pairs)
		case <-ctx.Done():
			fmt.Println("Stopping event loop")
			return
		}
	}
}

// drainPairs consumes all immediately available pairs from the buffered channel.
func (e *eventLoop) drainPairs(pairs <-chan *event.Pair) {
	for {
		select {
		case ep := <-pairs:
			e.printCb(ep)
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

func (e *eventLoop) initRawHandlers() {
	if e.rawHandlers == nil {
		e.rawHandlers = make(map[types.EventType]rawEventHandler)
	}
	if len(e.rawHandlers) != 0 {
		return
	}

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
	e.rawHandlers[types.EXIT_RET_EVENT] = func(raw []byte, ch chan<- *event.Pair) {
		retEv, ok := decodeRawEvent(e, types.EXIT_RET_EVENT, raw, types.NewRetEventFast)
		if !ok {
			return
		}
		e.tracepointExited(retEv, ch)
	}
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
