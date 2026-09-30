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

// logStatus prints a human-facing status line to stderr, so stdout carries
// only machine-readable output (the CSV header and rows in -plain mode). It is
// the fallback sink for notifyStatus and notifyWarningOrLog; lifecycle lines
// go through notifyStatus so TUI mode can silence them.
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
	// Registered last so it runs first (defers are LIFO): buffered -plain rows
	// reach stdout before the drop monitor, the aggregate drainer and the comm
	// resolver are stopped (their final drain can take a moment) and before
	// close(e.done) unblocks stats(). Only this goroutine feeds the sink
	// (drainPairs), so none of those stoppers can race with the flush. It must
	// stay a defer: a panic that unwinds through run then still writes the rows
	// buffered before it (TestPlainSinkPanicFlushesEarlierRows). An exit that
	// skips defers altogether - a crash in another goroutine, SIGQUIT,
	// SIGKILL - loses the still-buffered rows; see the plainSink doc. SIGHUP
	// is not one of them: headless modes cancel the context on it (unless it
	// was inherited as ignored), so this defer runs.
	defer e.flushOutput()

	if e.cfg.pprofEnable {
		e.notifyStatus("Profiling, press Ctrl+C to stop")
	}
	if e.cfg.plainMode && !e.cfg.pprofEnable {
		// Written straight to stdout, not through the buffered sink: it is
		// safe only because no row can be buffered yet (the event loop has not
		// started), so it always precedes the first row. Do not move it after
		// processRawEvents starts (TestPlainRunHeaderPrecedesRows).
		//
		// A failed header write is a failed stdout like any other: recorded
		// here, it stops the trace before the first row is even decoded.
		if _, err := fmt.Fprintln(os.Stdout, event.EventStreamHeader); err != nil {
			e.outputFailed(err, 0)
		}
	}
	e.flushPendingWarnings()
	e.announceSampling()

	e.startTime = time.Now()
	// emit() already handles a nil printCb safely, but guard here so that
	// hot-path event emission never pays for a nil check inside the loop.
	if e.printCb == nil {
		e.SetPrintCallback(func(ep *event.Pair) { ep.Recycle() })
	}
	e.initRawHandlers()
	e.processRawEvents(ctx, rawCh)
}

func (e *eventLoop) startAggregateDrainLoop(ctx context.Context) func() {
	if e.aggregateSrc == nil || e.aggregateSink == nil {
		return func() {}
	}

	// The PID/TID scope the BPF program was loaded with (PID_FILTER /
	// TID_FILTER) lets the drainer honour a matching runtime PID/TID filter
	// for aggregate rows instead of gating them off.
	scope := kernelProcessScope{pid: e.cfg.pidFilter, tid: e.cfg.tidFilter}
	drainer := newAggregateDrainer(e.aggregateSrc, e.cfg.aggregateIngestTraceIDs, scope, e.Filter)
	// Tell the sink the real period (it may differ from the default) before
	// the first batch arrives.
	if setter, ok := e.aggregateSink.(aggregateDrainPeriodSetter); ok {
		setter.SetAggregateDrainPeriod(e.cfg.aggregateDrainEvery)
	}
	stop := drainer.Start(ctx, e.cfg.aggregateDrainEvery, e.handleAggregateDrainResult)
	// Publish the drainer so SetFilter flushes it before a live swap. stop
	// unpublishes it only AFTER the final drain: a SetFilter landing while
	// stop runs must still go through SwapFilter, or it would install the new
	// filter while the final drain is pending and that drain would judge the
	// pre-stop counts by it. Such a swap either wins the drainer lock first
	// (flushing under the outgoing filter) or waits until the final drain
	// retired the drainer under that lock (pollCycle), when SwapFilter is a
	// plain swap that never touches the possibly closed map - which is also
	// what keeps a SetFilter holding the pointer past the Store(nil) safe.
	e.aggregateDrainer.Store(drainer)
	return func() {
		stop()
		e.aggregateDrainer.Store(nil)
	}
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
		// The counter could not be read, so the run total is not "unchanged"
		// - it is unknown. Record that so stats() stops asserting the last
		// reading (0, for a run whose first read already failed) as fact, and
		// surface the failure in every mode: a headless run that only called
		// notifyWarning here learnt nothing at all, which is precisely the
		// silence this counter exists to end.
		e.ringbufDropReadFailed.Store(true)
		e.notifyWarningOrLog(result.warning)
		return
	}
	// The kernel counter is cumulative, so one successful read supersedes any
	// earlier failure: the total is authoritative again.
	//
	// The total is published before the flag is cleared, and stats() reads
	// them in the opposite order, so a reader that sees "not failed" is
	// guaranteed to see the total that cleared it. Storing the flag first
	// would leave a window where stats() reads the stale total (0, on a run
	// whose first read failed) together with a cleared flag and prints it as a
	// confident "no loss" - the very statement this whole change exists to
	// prevent. The two goroutines do overlap: startTraceShutdownWatcher calls
	// stats() on ctx.Done() while the monitor is still winding down on the
	// same signal.
	e.numRingbufDrops.Store(result.total)
	e.ringbufDropReadFailed.Store(false)
	if result.delta == 0 {
		return
	}
	// Some of those lost records may have been sched_process_exec control
	// records, and that is the one loss the stream cannot repair on its own:
	// with an active -comm filter the open-side cache refresh never runs for a
	// non-matching program, so a tid stale-cached under its pre-exec name would
	// keep that name forever. Ask the event-loop goroutine to re-resolve the
	// comm cache; the flag is consumed in applyPendingCommRefresh because this
	// callback runs on the monitor goroutine.
	e.commRefreshPending.Store(true)
	// Modes without a warning sink (-plain, -flamegraph, headless -parquet)
	// would otherwise only learn about the loss from the end-of-run
	// statistics, which can be hours away. Losing events silently is exactly
	// the finding this counter closes, so notifyWarningOrLog falls back to
	// stderr - stdout stays machine-readable.
	e.notifyWarningOrLog(formatRingbufDropWarning(result))
}

// handleAggregateDrainResult ingests one drained batch of kernel-side syscall
// aggregates, or reports why the drain failed. The drain loop only runs with an
// aggregate sink wired: the stats engine in TUI mode
// (makeTUIEventLoopConfigurer), or the samplingTally of a raw output mode that
// samples (newEventLoop). Both report a failed drain through
// notifyWarningOrLog, so it reaches stderr where no warning sink is wired.
// A raw-mode run also records whether its latest drain failed: the tally's
// exact totals are only claimed when the final drain succeeded.
func (e *eventLoop) handleAggregateDrainResult(result aggregateDrainResult) {
	if e.samplingTally != nil {
		e.samplingTally.drainFailed.Store(result.warning != "")
	}
	if result.warning != "" {
		e.notifyWarningOrLog(result.warning)
		return
	}
	if len(result.rows) == 0 {
		return
	}
	e.aggregateSink.IngestSyscallAggregates(result.rows)
}

// processRawEvents decodes rawCh and emits every completed pair on the
// calling goroutine, until rawCh is closed or ctx is cancelled.
//
// Decoding and emission share one goroutine on purpose. Handing each pair to
// a separate emit goroutine cost a goroutine park and wake per pair, which
// dominated the pipeline profile, and a buffered handoff let decoding run
// ahead of emission: warnings raised while decoding (notifyWarning) then
// overtook the pairs decoded before them in the TUI stream, and a stopped
// trace kept emitting its buffered pairs into the next session's stream.
// Here a pair is emitted before the next raw record is read, so
//   - pairs and decode-side warnings reach the callbacks in stream order;
//   - no decoded pair is ever pending when the loop returns: every pair
//     produced (numSyscalls) is emitted and counted (numSyscallsAfterFilter),
//     whichever way the loop stops;
//   - a slow consumer stalls decoding directly, so backpressure reaches
//     rawCh and, through it, the BPF ring buffer.
//
// rawCh itself stays buffered (see appconfig.DefaultChannelBufferSize), so
// ring-buffer polling remains decoupled from decoding.
func (e *eventLoop) processRawEvents(ctx context.Context, rawCh <-chan []byte) {
	// A raw record completes at most one pair (tracepointExited, through
	// sendPair, is the only sender), so one slot always suffices. sendPair
	// never blocks: a second pair for one record panics instead of
	// deadlocking this goroutine, which is the channel's only reader.
	pairs := make(chan *event.Pair, 1)

	// Buffered output (-plain) is flushed by the timer: a row waits at most
	// plainFlushInterval, however busy or idle the loop is.
	flush := newFlushTimer(e.flusher)
	defer flush.stop()

	for {
		select {
		case <-flush.C():
			flush.fire()
		case raw, ok := <-rawCh:
			if !ok {
				return
			}
			if len(raw) == 0 {
				continue
			}
			// Recover from any panic inside a handler so a single bad
			// event cannot crash the entire process.
			e.processRawEventSafe(raw, pairs)
			e.drainPairs(pairs)
			flush.armIfPending()
		case <-ctx.Done():
			e.notifyStatus("Stopping event loop")
			return
		}
	}
}

// flushOutput writes out whatever the default -plain sink still buffers. It
// runs when the loop stops, on the loop goroutine that owns the sink.
func (e *eventLoop) flushOutput() {
	if e.flusher != nil {
		_ = e.flusher.Flush() // the sink records the error
	}
}

// drainPairs emits the pair, if any, that the last raw record completed.
func (e *eventLoop) drainPairs(pairs <-chan *event.Pair) {
	for {
		select {
		case ep := <-pairs:
			// Counted before emit, which hands the pair on and may recycle it.
			if e.samplingTally != nil {
				e.samplingTally.countTraced(ep.EnterEv.GetTraceId())
			}
			e.emit(ep)
			e.numSyscallsAfterFilter++
		default:
			return
		}
	}
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
	e.applyPendingCommRefresh()
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

// rawRuntimeEventHandler builds the raw handler for one registered event
// kind: it decodes the record, applies control records to event-loop state,
// and hands syscall enter/exit events on to pairing.
func (e *eventLoop) rawRuntimeEventHandler(rawEvent rawRuntimeEvent) rawEventHandler {
	return func(raw []byte, ch chan<- *event.Pair) {
		ev, ok := e.decodeRuntimeEvent(rawEvent, raw)
		if !ok {
			return
		}
		if rawEvent.direction == rawControlEvent {
			// Control records never become rows themselves; they update
			// event-loop state, and the exec record may complete one pending
			// execve pair whose exit is untraced (completeUntracedExec).
			// Because the BPF ring buffer preserves reservation order and
			// this goroutine is the single consumer, a control record that
			// reaches userspace is applied before any later event of the same
			// task is turned into a pair. The caveat is backpressure: a record
			// the kernel could not reserve never arrives at all, so the
			// ordering guarantee holds for delivered records only and the drop
			// counter drives the recovery path (applyPendingCommRefresh).
			if rawEvent.control == nil {
				ev.Recycle()
				return
			}
			rawEvent.control(e, ev, ch)
			return
		}
		syscallEvent, ok := ev.(event.Event)
		if !ok {
			e.notifyWarning("Dropped malformed syscall event")
			ev.Recycle()
			return
		}
		if rawEvent.direction == rawExitEvent {
			e.tracepointExited(syscallEvent, ch)
			return
		}
		if rawEvent.filter != nil && !rawEvent.filter(e.Filter(), syscallEvent) {
			syscallEvent.Recycle()
			return
		}
		e.tracepointEntered(syscallEvent)
	}
}

func (e *eventLoop) decodeRuntimeEvent(rawEvent rawRuntimeEvent, raw []byte) (runtimeDecodedEvent, bool) {
	decoded := rawEvent.decode(raw)
	if decoded == nil {
		e.dropMalformedRawEvent(rawEvent.eventType, raw)
		return nil, false
	}
	return decoded, true
}

// tracepointEntered parks a syscall enter until its exit arrives.
//
// There is deliberately no comm-based gate here. The comm filter is applied to
// the pair at the exit checkpoint (finishPair -> MatchPair), where the tid's
// cached comm is attached; a tid whose comm is unknown yields "", which matches
// no ordinary -comm pattern, so its row is dropped there just like a cached
// non-matching one. Only the patterns that match the empty string (^$, ^, $;
// all are valid -comm values) select such a row; that is intended: the TUI's
// exact-pattern helper produces ^$ for a row whose comm cell is empty, and it
// must find that row's kind (TestCommFilterEmptyPatternSelectsUncachedTid).
// An earlier version recycled the enter of every non-open,
// non-exec syscall of a tid with no cached comm (task dr2): the exit handler
// then never ran, so a close/dup2/dup3/close_range/fcntl of such a thread never
// reached the fd table. The table is per process and shared by all its
// threads, so the rows a run does want kept reporting a closed file's name.
// handleFdExit and its siblings apply their state change before the filter for
// exactly this reason; dropping the enter earlier contradicted that rule. Every
// fresh thread is uncached until the task_newtask record or a procfs read names
// it, and a lost record leaves it so, which made this routine rather than rare.
//
// Open kinds still shed non-matching enters earlier, in the raw filter
// (matchRawOpenEvent), because their payload carries the comm.
func (e *eventLoop) tracepointEntered(enterEv event.Event) {
	// Schedule comm lookup as early as possible to reduce races for short-lived processes.
	e.queueCommLookup(enterEv.GetTid())
	e.storeEnter(enterEv)
}

// storeEnter parks enterEv until its exit record arrives.
//
// An exec enter resolves its dirfd-relative target right here instead of in
// handleExecExit. A successful execve/execveat is delivered as enter record,
// then the PROCESS_EXEC_EVENT control record (sched_process_exec fires inside
// the syscall), then the exit record. That control record evicts the process's
// FD_CLOEXEC descriptors (fdTracker.dropOnExec), and fexecve's descriptor is
// typically opened O_CLOEXEC - so by the time the exit arrives, the dirfd the
// kernel resolved against is gone from the table. At enter time the table
// still holds it, because the eviction is applied in ring-buffer order.
//
// That guarantee covers only descriptors the fd table tracks (opened, duped or
// otherwise registered by a traced syscall). For an untracked dirfd the
// resolver falls back to /proc/<pid>/fd, and that read is no earlier at enter
// time than at exit: user space consumes the enter record after the kernel has
// usually finished the exec, so an untracked O_CLOEXEC dirfd is already closed
// (or its number reused by the new program) and still resolves to the fd
// number with an empty name.
func (e *eventLoop) storeEnter(enterEv event.Event) {
	execEv, ok := enterEv.(*types.ExecEvent)
	if !ok {
		e.pairs.set(enterEv)
		return
	}
	e.pairs.setWithFile(enterEv, e.snapshotExecTarget(execEv))
}

func (e *eventLoop) tracepointExited(exitEv event.Event, ch chan<- *event.Pair) {
	ep, ok := e.pairs.consume(exitEv.GetTid())
	if !ok {
		// A non-leader execve whose exec record was lost: see
		// adoptLostExecCaller.
		ep, ok = e.adoptLostExecCaller(exitEv)
	}
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
	// The derived values must be on the Pair *before* the exit handlers run,
	// because that is where the pair filter is applied: MatchPair reads
	// Bytes/Duration/DurationToPrev, and evaluating them while they are still
	// zero silently turns `-latency`/`-gap`/`-bytes` into "compare against 0"
	// for every kind (a `-latency >= 50` filter dropped a row whose real
	// latency was 100ns). Only the emission-side freeze has to wait for the
	// handler, since that is what assigns ep.File.
	e.applyDerivedPairValues(ep)
	if !e.handleTracepointExit(ep) {
		return
	}
	e.finalizeTracepointPair(ep)
	sendPair(ch, ep)
}

// secondPairPanic is the panic message of sendPair on a full channel.
const secondPairPanic = "raw record completed more than one pair; extra pair dropped"

// sendPair hands a completed pair to processRawEvents, which drains the
// channel only after the handler has returned. Its one slot is enough
// because a raw record completes at most one pair; a full channel therefore
// means a handler broke that rule. A blocking send would then wait forever
// for a reader that runs on this very goroutine - run() would never return,
// e.done never close, and stats and shutdown would hang with it. So the send
// never blocks: the extra pair is recycled and the handler panics, which
// processRawEventSafe turns into a warning before the loop carries on. The
// dropped pair stays counted in numSyscalls but not in
// numSyscallsAfterFilter, so the loss also shows in the statistics. Its
// tid's prevTime has already advanced, since finalizeTracepointPair runs first.
func sendPair(ch chan<- *event.Pair, ep *event.Pair) {
	select {
	case ch <- ep:
	default:
		ep.Recycle()
		panic(secondPairPanic)
	}
}

// applyDerivedPairValues computes every filterable value the Pair does not
// carry straight from its two events: transferred bytes, address-space extent
// (brk from the per-process break the loop remembers),
// requested sleep, syscall latency and the inter-syscall gap. It reads the
// per-tid previous-exit timestamp but deliberately does not advance it - that
// happens in finalizeTracepointPair, so the gap keeps being measured from the
// previously *emitted* pair rather than from a filtered-out one.
//
// Both key the baseline by the EXIT's tid. For almost every pair that is the
// enter's tid as well; the exception is an execve by a non-leader thread,
// which returns under the leader's tid (de_thread). rekeyExecCaller moves the
// baseline to that tid together with the parked enter, so the execve row still
// measures its gap from the caller's previous syscall and the new program's
// first syscall measures its gap from the execve's return, with nothing left
// behind under the vanished pre-exec tid.
func (e *eventLoop) applyDerivedPairValues(ep *event.Pair) {
	applyRetBytes(ep)
	applyAddressSpaceBytes(ep)
	e.applyBrkGrowth(ep)
	applyRequestedSleepNs(ep)
	ep.CalculateDurations(e.pairs.prevTime(ep.ExitEv.GetTid()))
}

func (e *eventLoop) finalizeTracepointPair(ep *event.Pair) {
	e.pairs.setPrevTime(ep.ExitEv.GetTid(), ep.ExitEv.GetTime())
	e.freezePairForEmission(ep)
}

func (e *eventLoop) freezePairForEmission(ep *event.Pair) {
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		return
	}
	ep.File = fdFile.Dup(fdFile.FD())
}
