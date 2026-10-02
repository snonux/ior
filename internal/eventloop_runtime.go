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
//
// The monitor is published (e.dropMonitor) so the TUI can read it on demand at
// the edges of a Parquet recording (flushRecordingCounters); like the
// aggregate drainer it is unpublished only after the final read, which also
// retired it, so a flush holding the pointer past that reads nothing.
func (e *eventLoop) startRingbufDropMonitor(ctx context.Context) func() {
	if e.dropSrc == nil {
		return func() {}
	}
	monitor := newRingbufDropMonitor(e.dropSrc)
	stop := monitor.Start(ctx, e.cfg.aggregateDrainEvery, e.handleRingbufDropResult)
	e.dropMonitor.Store(monitor)
	return func() {
		stop()
		e.dropMonitor.Store(nil)
	}
}

// handleRingbufDropResult records the running drop total and raises a warning
// for every interval that lost events, and for every failed counter read, so
// backpressure shows up live (and in the end-of-run statistics).
//
// Both warnings go through notifyWarningOrLog, which falls back to stderr in
// modes without a warning sink (-plain, -flamegraph, headless -parquet): those
// would otherwise learn about the loss, or about a counter that cannot be
// read, only from the end-of-run statistics, which can be hours away. Losing
// events silently is exactly the finding this counter closes; stdout stays
// machine-readable.
func (e *eventLoop) handleRingbufDropResult(result ringbufDropResult) {
	// A loss (or a counter that could not be read) during a TUI recording
	// makes its sampling totals a lower bound.
	if result.warning != "" || result.delta > 0 {
		e.markRecordingLowerBound()
	}
	if result.warning != "" {
		e.recordDropReadFailure()
		e.notifyWarningOrLog(result.warning)
		return
	}
	e.publishDropTotal(result.total)
	// The restart fold's drop watch (restartDropWatch) is told of the reading,
	// with a clock reading taken after the counter was read (the result is in
	// hand). The reading that matters is the one that CHANGED the total: it
	// stamps the new total here, within one monitor period of the drop, and a
	// call interrupted after that stamp folds again. Without it the new total
	// would first be seen by a fold's own read, which comes after that call's
	// interruption, and the fold would be refused. A reading that returns the
	// total the watch already has changes nothing there (observe keeps the
	// first stamp). One reading with delta 0 does move the watch: a stale one,
	// taken before the loop's own read saw a newer total and delivered after
	// it. The watch takes any differing total for a change and stamps it now,
	// and the next read of the real total stamps once more, so the invariant
	// holds and the price is the folds of the calls interrupted before that next
	// read (usually one). One clock read serves
	// both users of the stamp.
	if result.delta == 0 {
		e.restarts.drops.observe(result.total, e.readDropStampClock())
		return
	}
	e.restarts.drops.observe(result.total, e.requestCommSweepAfterDrop())
	e.notifyWarningOrLog(formatRingbufDropWarning(result))
}

// recordDropReadFailure notes that the counter could not be read, so the run
// total is not "unchanged" - it is unknown. stats() then stops asserting the
// last reading (0, for a run whose first read already failed) as fact, and
// provisionalSeedNeedsRecheck stops trusting rename records while the flag
// stays set: a lost rename could no longer show up as a drop.
func (e *eventLoop) recordDropReadFailure() {
	e.ringbufDropReadFailed.Store(true)
}

// publishDropTotal stores a successful reading of the cumulative kernel
// counter. Being cumulative, one successful read supersedes any earlier
// failure: the total is authoritative again.
//
// The total is published before the flag is cleared, and stats() reads them
// in the opposite order, so a reader that sees "not failed" is guaranteed to
// see the total that cleared it. Storing the flag first would leave a window
// where stats() reads the stale total (0, on a run whose first read failed)
// together with a cleared flag and prints it as a confident "no loss" - the
// very statement this whole change exists to prevent. The two goroutines do
// overlap: startTraceShutdownWatcher calls stats() on ctx.Done() while the
// monitor is still winding down on the same signal.
func (e *eventLoop) publishDropTotal(total uint64) {
	e.numRingbufDrops.Store(total)
	e.ringbufDropReadFailed.Store(false)
}

// requestCommSweepAfterDrop answers a poll that saw lost records. Some of them
// may have been sched_process_exec control records, and that is the one loss
// the stream cannot repair on its own: with an active -comm filter the
// open-side cache refresh never runs for a non-matching program, so a tid
// stale-cached under its pre-exec name would keep that name forever. (A lost
// task_rename record is the same case, task xr2.) So the event-loop goroutine
// is asked to re-resolve the comm cache; the flag is consumed in
// applyPendingCommRefresh because this runs on the monitor goroutine.
//
// The boot-clock stamp is stored before the flag is raised. It is read after
// the counter, so every record counted here was reserved before it. Were the
// flag visible first, the loop could apply the sweep and then seed a newtask
// record reserved before the drop while lastDropSeenBootNs still held the
// previous stamp: that seed would escape both the sweep and the time check
// in provisionalSeedNeedsRecheck. Pinned by
// TestDropStampIsStoredBeforeTheSweepIsRequested.
//
// It returns the stamp, for the restart fold's drop watch.
func (e *eventLoop) requestCommSweepAfterDrop() uint64 {
	seenAt := e.readDropStampClock()
	e.lastDropSeenBootNs.Store(seenAt)
	e.commRefreshPending.Store(true)
	return seenAt
}

// readDropStampClock reads the boot clock through the test seam
// dropStampClock, or bootClockNs when none is set.
func (e *eventLoop) readDropStampClock() uint64 {
	if e.dropStampClock != nil {
		return e.dropStampClock()
	}
	return bootClockNs()
}

// handleAggregateDrainResult ingests one drained batch of kernel-side syscall
// aggregates, or reports why the drain failed. The drain loop only runs with an
// aggregate sink wired: the stats engine in TUI mode
// (makeTUIEventLoopConfigurer), or the samplingTally of a raw output mode that
// samples (newEventLoop). Both report a failed drain through
// notifyWarningOrLog, so it reaches stderr where no warning sink is wired.
// A raw-mode run also records whether its latest drain failed: the tally's
// exact totals are only claimed when the final drain succeeded. In TUI mode
// the result also goes to the active Parquet recording's sampling totals
// (forwardAggregatesToRecording).
func (e *eventLoop) handleAggregateDrainResult(result aggregateDrainResult) {
	if e.samplingTally != nil {
		e.samplingTally.drainFailed.Store(result.warning != "")
	}
	e.forwardAggregatesToRecording(result)
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
// ring-buffer polling remains decoupled from decoding. Records still buffered
// when ctx is cancelled are not abandoned: drainBacklogAtStop decodes them
// first (bounded by count and time) and accounts for any it cannot.
func (e *eventLoop) processRawEvents(ctx context.Context, rawCh <-chan []byte) {
	pairs := make(chan *event.Pair, pairChannelSlots)

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
				e.releaseAllHeldRestarts(pairs)
				return
			}
			e.consumeRaw(raw, pairs, flush)
			if !e.consumeReadyRaw(ctx, rawCh, pairs, flush) {
				e.releaseAllHeldRestarts(pairs)
				return
			}
		case <-ctx.Done():
			e.notifyStatus("Stopping event loop")
			e.drainBacklogAtStop(rawCh, pairs, flush)
			e.countKernelRingLeftAtStop()
			// Rows still held for a possible continuation (restart_syscall
			// or a re-execution) are emitted unchanged now, before run's
			// deferred flushOutput writes the -plain buffer out (tasks fs2,
			// 103).
			e.releaseAllHeldRestarts(pairs)
			return
		}
	}
}

// maxReadyBatch bounds how many records the loop takes from rawCh between two
// looks at the flush timer and ctx (see consumeReadyRaw).
const maxReadyBatch = 256

// consumeReadyRaw takes up to maxReadyBatch records that are already waiting
// in rawCh, without blocking, and consumes each like the select case that
// received the first one. Under load rawCh is rarely empty, and a select per
// record (selectgo over the flush timer, rawCh and ctx) cost ~17% of ior's CPU
// in -flamegraph mode and ~8% in -plain mode, next to the channel send on the
// poll side (task 5s2); a plain non-blocking receive is far cheaper. The bound
// keeps the flush timer waiting at most one batch (256 records, microseconds of
// decoding), so a -plain row still leaves within plainFlushInterval plus that.
// ctx is checked before every record (one atomic load): a cancelled run must
// stop at once and hand over to drainBacklogAtStop, whose time budget exists
// for a slow consumer, instead of finishing a whole batch first
// (TestRunCountsBacklogItCannotDrainInTime). It reports false when rawCh was
// closed, which ends the loop exactly as the select case does.
func (e *eventLoop) consumeReadyRaw(ctx context.Context, rawCh <-chan []byte, pairs chan *event.Pair, flush *flushTimer) bool {
	for range maxReadyBatch {
		if ctx.Err() != nil {
			return true
		}
		select {
		case raw, ok := <-rawCh:
			if !ok {
				return false
			}
			e.consumeRaw(raw, pairs, flush)
		default:
			return true
		}
	}
	return true
}

// consumeRaw decodes one raw record and emits the pair it completed, if any.
// It is the single per-record step of both the running loop and the drain at
// stop, so a record counts the same wherever it is taken from.
func (e *eventLoop) consumeRaw(raw []byte, pairs chan *event.Pair, flush *flushTimer) {
	if len(raw) == 0 {
		return
	}
	// Recover from any panic inside a handler so a single bad
	// event cannot crash the entire process.
	e.processRawEventSafe(raw, pairs)
	e.drainPairs(pairs)
	flush.armIfPending()
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
// kind: it decodes the record, lets the restart fold claim or settle it
// (routeHeldRestart, tasks fs2 and 103: the kernel's continuation of a held
// interrupted row - restart_syscall, or the proven re-execution of the call -
// is folded into it, the syscalls of a signal handler the call survives pass
// by, and any other record of that tid first releases the row),
// applies control records to event-loop state, and hands syscall enter/exit
// events on to pairing (syscallEntered, tracepointExited).
func (e *eventLoop) rawRuntimeEventHandler(rawEvent rawRuntimeEvent) rawEventHandler {
	return func(raw []byte, ch chan<- *event.Pair) {
		ev, ok := e.decodeRuntimeEvent(rawEvent, raw)
		if !ok {
			return
		}
		if e.routeHeldRestart(rawEvent, ev, ch) {
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
		e.syscallEntered(rawEvent, syscallEvent, ch)
	}
}

// syscallEntered handles a decoded syscall enter record: it seeds the comm
// cache, applies the kind's raw enter filter, and then either parks the enter
// for its exit (tracepointEntered) or, for a syscall that never returns,
// completes the row right away (completeNoReturnEnter).
func (e *eventLoop) syscallEntered(rawEvent rawRuntimeEvent, enterEv event.Event, ch chan<- *event.Pair) {
	// Before the enter filter: the payload comm is true whether or not this
	// run wants the row, and a filtered-out enter must still heal the cache.
	e.seedCommFromEnterPayload(enterEv)
	if rawEvent.filter != nil && !rawEvent.filter(e.Filter(), enterEv) {
		enterEv.Recycle()
		return
	}
	if enterEv.GetTraceId().NoReturn() {
		e.completeNoReturnEnter(enterEv, ch)
		return
	}
	e.tracepointEntered(enterEv)
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
		ep, ok = e.adoptLostExecCaller(exitEv, ch)
	}
	if !ok {
		// An exit with no enter is dropped without a row and without a count
		// (it is neither a mismatch nor a syscall ior saw start). Besides a
		// lost enter record it is ordinary kernel behaviour: the first return
		// of a clone/fork child, a call already in flight when the probes
		// attached, and a call a seccomp filter denies with an errno - the
		// filter runs before sys_enter, so only sys_exit fires and there is
		// nothing to build the row's arguments from (task qr2; such calls are
		// invisible in the trace, but they no longer consume a parked enter
		// and inflate the mismatch count now that noreturn enters are not
		// parked, task pr2).
		exitEv.Recycle()
		return
	}
	ep.ExitEv = exitEv
	// Counted here, once per call: an interrupted row folded with its
	// continuation (restart_syscall or the re-executed call) does not count
	// that continuation again (tasks fs2, 103).
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
	// A call interrupted with a restart code may still be carried on by the
	// kernel (a proven restart_syscall for -516, a proven re-execution for
	// -512/-513/-514): it is held, not completed, until its tid's next
	// records decide (eventloop_restart.go). Everything that judges the row -
	// exit handler, derived values, pair filter - waits for that, so it sees
	// the whole call.
	if e.holdRestart(ep, ch) {
		return
	}
	e.completeTracepointPair(ep, ch)
}

// completeTracepointPair turns a matched pair into a row: it derives the
// filterable values, runs the kind's exit handler (state changes and the pair
// filter), advances the tid's gap baseline and sends the row on ch. It is the
// tail of tracepointExited and the path a held interrupted row takes once its
// fate is known (folded or released unchanged, eventloop_restart.go). For a
// held row the gap is thus read at release rather than at its first exit. The
// tid's baseline has not moved in between, because every record of that tid
// releases the row before it is processed itself - except the rows of a
// signal handler the call survives, for which completeHeldRestart puts the
// baseline back first.
func (e *eventLoop) completeTracepointPair(ep *event.Pair, ch chan<- *event.Pair) {
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

// pairChannelSlots is how many pairs one raw record may complete, and so the
// size of the channel its handler sends them on (processRawEvents drains it
// only after the handler has returned).
//
// A record completes at most one pair of its own - tracepointExited,
// completeNoReturnEnter for a noreturn enter, completeUntracedExec for the
// exec record - and before it at most one interrupted row for each tid it
// retires (tasks fs2, 103). Every record retires the row of its own tid:
// routeHeldRestart releases or folds it, and holdRestart releases it before a
// new one takes its place, which is the same one row. The exec side of a
// non-leader exec retires a second tid, the caller's pre-exec one: the exec
// record through releaseExecCallerRestart, or, when that record was lost, the
// execve's exit through adoptLostExecCaller. So the worst case is three: the
// row held under the leader tid (only when the dead leader's own exit record
// was lost, which would have released it), the row held under the caller's old
// tid, and the execve's pair - from the exit record, or from the exec record
// under -tid <caller>. The first and the last can hardly meet in the second
// form (the kernel-side tid filter emits nothing under the leader's tid), but
// a slot is cheaper than an argument that has to stay true: the channel is
// sized for the sum. The released rows are sent first, so they are drained
// first. A release that parks the continuation's enter again adds no pair
// (reparkContinuation), and the exit that then pairs with it is that record's
// one pair of its own.
const pairChannelSlots = 3

// extraPairPanic is the panic message of sendPair on a full channel.
const extraPairPanic = "raw record completed more pairs than the pair channel holds; extra pair dropped"

// sendPair hands a completed pair to processRawEvents, which drains the
// channel only after the handler has returned. Its pairChannelSlots slots hold
// everything one raw record can complete; a full channel therefore means a
// handler broke that rule. A blocking send would then wait forever
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
		panic(extraPairPanic)
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

// freezePairForEmission gives the pair an independent snapshot of its
// descriptor, so the row reports the flags the syscall returned with. The fd
// table's FdFile is live: a later fcntl(F_SETFL) through any duplicate of the
// same open file description rewrites the status word they share (task nr2), so
// the pair must not keep a Dup (which shares it) but a Detach (which owns its
// copy).
func (e *eventLoop) freezePairForEmission(ep *event.Pair) {
	fdFile, ok := ep.File.(*file.FdFile)
	if !ok {
		return
	}
	ep.File = fdFile.Detach()
}
