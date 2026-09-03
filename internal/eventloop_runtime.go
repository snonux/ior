package internal

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/types"
)

// logStatus prints a human-facing status line to stderr. All event-loop
// lifecycle messages live on stderr so stdout carries only machine-readable
// output (the CSV header and rows in -plain mode).
func logStatus(args ...any) {
	_, _ = fmt.Fprintln(os.Stderr, args...)
}

func (e *eventLoop) run(ctx context.Context, rawCh <-chan []byte) {
	defer close(e.done)
	defer e.shutdownCommResolver()
	stopAggregateLoop := e.startAggregateDrainLoop(ctx)
	defer stopAggregateLoop()
	stopDropMonitor := e.startRingbufDropMonitor(ctx)
	defer stopDropMonitor()

	if e.cfg.pprofEnable {
		logStatus("Profiling, press Ctrl+C to stop")
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

func (e *eventLoop) startAggregateDrainLoop(ctx context.Context) func() {
	if e.aggregateSrc == nil || e.aggregateSink == nil {
		return func() {}
	}

	drainer := newAggregateDrainer(e.aggregateSrc, e.cfg.aggregateIngestTraceIDs, e.Filter)
	return drainer.Start(ctx, e.cfg.aggregateDrainEvery, e.handleAggregateDrainResult)
}

// startRingbufDropMonitor polls the kernel-side ring-buffer drop counter for
// the lifetime of the run. Both stop paths (ctx cancellation and the deferred
// stop) take a final reading before stats() is unblocked by close(e.done), so
// the reported total covers the whole run.
func (e *eventLoop) startRingbufDropMonitor(ctx context.Context) func() {
	if e.dropSrc == nil {
		return func() {}
	}
	monitor := newRingbufDropMonitor(e.dropSrc)
	return monitor.Start(ctx, e.cfg.aggregateDrainEvery, e.handleRingbufDropResult)
}

// handleRingbufDropResult records the running drop total and raises a warning
// for every interval that lost events, so backpressure shows up live in the
// TUI stream (and in -plain runs via the end-of-run statistics).
func (e *eventLoop) handleRingbufDropResult(result ringbufDropResult) {
	if result.warning != "" {
		e.notifyWarning(result.warning)
		return
	}
	e.numRingbufDrops.Store(result.total)
	if result.delta == 0 {
		return
	}
	message := formatRingbufDropWarning(result)
	if e.warningCb != nil {
		e.notifyWarning(message)
		return
	}
	// Modes without a warning sink (-plain, -flamegraph, headless -parquet)
	// would otherwise only learn about the loss from the end-of-run
	// statistics, which can be hours away. Losing events silently is exactly
	// the finding this counter closes, so fall back to stderr - stdout stays
	// machine-readable.
	logStatus("Warning:", message)
}

func (e *eventLoop) handleAggregateDrainResult(result aggregateDrainResult) {
	if result.warning != "" {
		e.notifyWarning(result.warning)
		return
	}
	if len(result.rows) == 0 {
		return
	}
	e.aggregateSink.IngestSyscallAggregates(result.rows)
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
			logStatus("Stopping event loop")
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
				logStatus("Stopping event loop")
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

// initRawHandlers registers all BPF event-type dispatch callbacks from the
// runtime event-kind table. It is idempotent: a second call after the map is
// populated is a no-op.
func (e *eventLoop) initRawHandlers() {
	if e.rawHandlers == nil {
		e.rawHandlers = make(map[types.EventType]rawEventHandler)
	}
	if len(e.rawHandlers) != 0 {
		return
	}
	for _, rawEvent := range rawRuntimeEvents() {
		e.rawHandlers[rawEvent.eventType] = e.rawRuntimeEventHandler(rawEvent)
	}
}

func (e *eventLoop) rawRuntimeEventHandler(rawEvent rawRuntimeEvent) rawEventHandler {
	return func(raw []byte, ch chan<- *event.Pair) {
		ev, ok := e.decodeRuntimeEvent(rawEvent, raw)
		if !ok {
			return
		}
		if rawEvent.direction == rawControlEvent {
			// Control records never become rows; they only update event-loop
			// state. Because the BPF ring buffer preserves reservation order
			// and this goroutine is the single consumer, a control record is
			// applied before any later event of the same task is turned into
			// a pair.
			if rawEvent.control == nil {
				ev.Recycle()
				return
			}
			rawEvent.control(e, ev)
			return
		}
		if rawEvent.direction == rawExitEvent {
			e.tracepointExited(ev, ch)
			return
		}
		if rawEvent.filter != nil && !rawEvent.filter(e.Filter(), ev) {
			ev.Recycle()
			return
		}
		e.tracepointEntered(ev)
	}
}

func (e *eventLoop) decodeRuntimeEvent(rawEvent rawRuntimeEvent, raw []byte) (event.Event, bool) {
	decoded := rawEvent.decode(raw)
	if decoded == nil {
		e.dropMalformedRawEvent(rawEvent.eventType, raw)
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
	case *types.ExecEvent:
		e.pairs.set(enterEv)
	default:
		// Only, when we have a comm name
		if _, ok := e.cachedComm(tid); ok {
			e.pairs.set(enterEv)
		} else {
			e.notifyWarning(fmt.Sprintf("No comm name for %v process probably already vanished?", enterEv))
			// The event is dropped (no cached comm to match a comm filter
			// against): return it to its pool per the EventLifecycle contract.
			enterEv.Recycle()
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
	e.finalizeTracepointPair(ep)
	ch <- ep
}

func (e *eventLoop) finalizeTracepointPair(ep *event.Pair) {
	applyRetBytes(ep)
	applyAddressSpaceBytes(ep)
	applyRequestedSleepNs(ep)
	tid := ep.EnterEv.GetTid()
	ep.CalculateDurations(e.pairs.prevTime(tid))
	e.pairs.setPrevTime(tid, ep.ExitEv.GetTime())
	e.freezePairForEmission(ep)
}

func (e *eventLoop) freezePairForEmission(ep *event.Pair) {
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		return
	}
	ep.File = fdFile.Dup(fdFile.FD())
}
