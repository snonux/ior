package internal

import (
	"fmt"
	"sync/atomic"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	"ior/internal/textsafe"
	"ior/internal/types"
)

const sysEnterNameToHandleAtName = "name_to_handle_at"

const (
	defaultCommLookupWorkers       = 4
	defaultCommLookupQueueSize     = 512
	defaultMaxPendingEnterEvs      = 16384
	defaultMaxPendingHandleEntries = 8192
	defaultMaxProcFdCacheSize      = 8192
	// defaultMaxFdTableEntries caps the fdTracker's (pid, fd) table. The flat
	// per-fd map it replaced had no cap at all, but its key space was bounded
	// by the number of distinct descriptor *numbers* (a few hundred per
	// process, shared system-wide). Keying per pid makes the space grow with
	// every traced process, and nothing in the syscall stream alone reclaims
	// the entries of a process that exited - hence both this cap and the
	// sched_process_exit eviction that usually makes it moot: between close,
	// close_range, dup-overwrites and process exits, steady state tracks the
	// genuinely-open descriptors of live traced processes, and 32768 covers
	// that with headroom (32 processes at the RLIMIT_NOFILE soft default of
	// 1024, or ~8 busy ones at 4096) before LRU trimming starts. Trimming is
	// not lossy-by-design either: resolve falls back to the procfs cache and
	// then to a live /proc/<pid>/fd readlink, so an evicted-but-open
	// descriptor still resolves correctly.
	defaultMaxFdTableEntries   = 32768
	cacheTrimDivisor           = 4
	defaultAggregateDrainEvery = time.Second
)

type syscallAggregateSource interface {
	Drain() ([]statsengine.SyscallAggregate, error)
}

type syscallAggregateSink interface {
	IngestSyscallAggregates([]statsengine.SyscallAggregate)
}

// aggregateDrainPeriodSetter is optionally implemented by an aggregate sink
// that needs to know how often batches arrive: statsengine.Engine spreads
// each batch over at most one drain period in its latency series.
type aggregateDrainPeriodSetter interface {
	SetAggregateDrainPeriod(time.Duration)
}

// ringbufDropSource reports the cumulative number of events the kernel dropped
// because the event ring buffer was full. Implemented by ringbufDropCounter
// over the BPF ringbuf_drop_map; stubbed in tests.
type ringbufDropSource interface {
	Total() (uint64, error)
}

type eventLoopConfig struct {
	pidFilter               int
	tidFilter               int
	filter                  globalfilter.Filter
	pprofEnable             bool
	plainMode               bool
	escapeMode              textsafe.EscapeMode
	fdTracker               *fdTracker
	commResolver            *commResolver
	aggregateDrainEvery     time.Duration
	aggregateIngestTraceIDs map[types.TraceId]struct{}
	// samplingRates are the syscalls a raw output mode samples and their
	// effective rates (rawModeSamplingRates); nil when nothing is sampled and
	// in the TUI, whose stats engine merges the kernel counts itself. When
	// set, newEventLoop keeps an exact tally of them (samplingTally).
	samplingRates map[types.TraceId]uint32
	// samplingFamilyRates are the family-wide rates among samplingRates, so
	// the report can name a family once instead of each of its syscalls.
	samplingFamilyRates map[types.SyscallFamily]uint32
}

type rawEventHandler func(raw []byte, ch chan<- *event.Pair)

type eventLoop struct {
	// filterPtr holds the active global filter. Stored as atomic.Pointer so
	// the TUI can swap filters in place via SetFilter without tearing down
	// and reattaching the BPF probes (the previous behavior caused a multi-
	// second 'Attaching tracepoints' overlay every time the filter changed).
	filterPtr      atomic.Pointer[globalfilter.Filter]
	pairs          pairTracker           // enter/exit pairing state and inter-syscall duration tracking
	restarts       restartTracker        // interrupted rows held for the kernel's continuation of the call, by tid (eventloop_restart.go)
	pendingHandles *pendingHandleTracker // TID → pathname from name_to_handle_at, for open_by_handle_at correlation
	fdTracker      *fdTracker            // fd table and procfs resolution cache
	commResolver   *commResolver
	// commWired is the resolver commState last completed and wired to this
	// loop's warning sink. While it still equals commResolver, commState
	// skips that one-time wiring: evaluating the method value
	// e.notifyWarning heap-allocates a closure, and commState runs several
	// times per event.
	//
	// Invariant: once a resolver is wired, nothing clears its warningFn.
	// The fast path never re-runs setDefaultWarningFn, so a sink cleared
	// after wiring would silently stay cleared; swap in a new resolver
	// instead, which commState wires on its first use.
	commWired       *commResolver
	outputFormatter // pair-emission and warning-notification callbacks (embedded collaborator)
	rawHandlers     map[types.EventType]rawEventHandler
	exitHandlers    map[types.EventType]runtimeExitHandler
	cfg             eventLoopConfig
	aggregateSink   syscallAggregateSink
	aggregateSrc    syscallAggregateSource
	// samplingTally is the exact population of the sampled syscalls of a raw
	// output mode, or nil (see eventLoopConfig.samplingRates). It is the
	// aggregate sink of such a run.
	samplingTally *samplingTally
	// recordingCounter receives, in TUI mode, the kernel counts and the loss
	// signals a Parquet recording's sampling totals need (see
	// recording_sampling.go); nil everywhere else. Set by the TUI configurer
	// before the loop and its drain/drop goroutines start, read-only after.
	recordingCounter runtime.RecordingSamplingCounter
	// aggregateDrainer is the running aggregate drainer, published by
	// startAggregateDrainLoop and cleared by its stop function, so SetFilter
	// (called from the TUI goroutine) can flush the aggregate map before a
	// live filter swap. nil while no drain loop runs. It is cleared only
	// after the final drain, so a SetFilter racing the stop still flushes
	// under the outgoing filter; one that holds the pointer past the clear
	// finds the drainer retired (under its lock, during the final drain) and
	// drains nothing.
	aggregateDrainer atomic.Pointer[aggregateDrainer]
	// dropSrc reads the kernel-side ring-buffer drop counter. nil disables
	// drop monitoring (tests and any path without a BPF module).
	dropSrc ringbufDropSource
	// dropMonitor is the running drop monitor, published and cleared by
	// startRingbufDropMonitor like aggregateDrainer, so a TUI recording edge
	// can read the drop counter now (flushRecordingCounters). nil while no
	// monitor runs.
	dropMonitor atomic.Pointer[ringbufDropMonitor]

	// Statistics
	numTracepoints          uint
	numTracepointMismatches uint
	numSyscalls             uint
	numSyscallsAfterFilter  uint
	// numGroupDeadExits counts sched_process_exit records flagged group_dead,
	// i.e. traced processes that ended and had their fd entries evicted
	// (handleProcessExitEvent). Written only by the event-loop goroutine;
	// stats() reads it after <-e.done like the counters above.
	numGroupDeadExits uint
	// numDiscardedAtStop counts the records still buffered in rawCh at the
	// stop that the stop-time drain could not decode (see
	// drainBacklogAtStop); they are in neither numTracepoints nor the kernel
	// drop counter. Written by the event-loop goroutine only; stats() reads it
	// after <-e.done.
	numDiscardedAtStop uint
	// stopDrainBudget overrides defaultStopDrainBudget when positive (tests).
	stopDrainBudget time.Duration
	// ringUnread reads what the consumer left in the kernel ring buffer at the
	// stop (task us2); nil disables the report (tests, a failed attach).
	ringUnread ringbufUnreadSource
	// numLeftInKernelRing counts the committed records still in the kernel ring
	// buffer when the stop-time drain finished: delivered to neither rawCh nor
	// the decoder, and not counted as drops. Written by the event-loop
	// goroutine only; stats() reads it after <-e.done.
	numLeftInKernelRing uint
	// stopOnTargetExit arms endTraceOnTargetExit and
	// endTraceOnTargetThreadExit, the record-based triggers: the -pid
	// target's group-dead exit record, the -tid thread's own exit record (one
	// not flagged as inherited by an exec'ing sibling), or, for a -tid leader
	// target, the group-dead record of its process cancels the trace. Set by
	// runTraceLoop for the headless modes before the loop starts; false (the
	// zero value) in the TUI and in tests. The liveness watcher
	// (watchTargetLiveness) does not need it: it is started separately.
	stopOnTargetExit bool
	// targetExitSeen makes the triggers (the event-loop goroutine's records
	// and the watcher goroutine's liveness poll) fire the stop and its
	// status line once between them, hence atomic.
	targetExitSeen atomic.Bool
	// recentGroupDead remembers the pids of recently counted group-dead
	// records, so the repeated records old kernels can produce for one
	// process death are counted once (isDuplicateGroupDead). Zero value
	// usable, expires entries incrementally so it is bounded by the deaths of
	// one dedup window, event-loop goroutine only.
	recentGroupDead groupDeadDedup
	// brkState remembers each traced process's last program break so a brk
	// call's address-space extent can be computed as the movement since the
	// previous one (applyBrkGrowth). Zero value usable; evicted per process on
	// exec and on group-dead exit; event-loop goroutine only.
	brkState brkTracker
	// numRingbufDrops is the cumulative kernel-side ring-buffer drop count.
	// Written by the drop-monitor goroutine and read by stats(), hence atomic.
	numRingbufDrops atomic.Uint64
	// ringbufDropReadFailed records whether the most recent reading of the
	// kernel drop counter failed. numRingbufDrops is then stale (or still 0,
	// if the very first read failed) and says nothing about the real loss, so
	// stats() reports the total as unknown rather than as a confident count.
	// Written by the drop-monitor goroutine and read by stats(), hence atomic.
	ringbufDropReadFailed atomic.Bool
	// commRefreshPending is raised by the drop-monitor goroutine when the
	// kernel lost events (one of which may have been a sched_process_exec
	// control record) and consumed by the event-loop goroutine in
	// applyPendingCommRefresh, which owns the comm cache's lazy init.
	commRefreshPending atomic.Bool
	// lastDropSeenBootNs is the CLOCK_BOOTTIME reading (the clock of the
	// records' bpf_ktime_get_boot_ns timestamps) taken right after the newest
	// drop-counter poll that reported lost records: every lost record was
	// reserved before it. Written by the drop-monitor goroutine, read by the
	// event-loop goroutine (provisionalSeedNeedsRecheck), hence atomic.
	lastDropSeenBootNs atomic.Uint64
	// dropStampClock reads the clock lastDropSeenBootNs is stamped from. nil
	// (every loop outside one test) means bootClockNs; the store-order test
	// injects one that observes commRefreshPending at the moment of the read
	// (TestDropStampIsStoredBeforeTheSweepIsRequested).
	dropStampClock func() uint64
	// renameRecordsTrusted is set by trace setup (trustRenameRecords) before
	// the loop starts and only read afterwards: the task_rename probe attached
	// and drops are monitored, so a provisional newtask seed normally needs no
	// corrective /proc read (provisionalSeedNeedsRecheck). False in tests and
	// whenever either is missing, which keeps the read.
	renameRecordsTrusted bool
	startTime            time.Time
	done                 chan struct{}
}

// Filter returns a snapshot of the currently active global filter. Each call
// loads a single atomic pointer and returns the underlying value, so the
// caller observes a consistent filter even if SetFilter races concurrently.
func (e *eventLoop) Filter() globalfilter.Filter {
	if p := e.filterPtr.Load(); p != nil {
		return *p
	}
	return globalfilter.Filter{}
}

// SetFilter atomically replaces the active global filter. The replacement is
// cloned so the caller can keep mutating its own filter without affecting
// what the eventloop sees. While the aggregate drain loop runs, the swap goes
// through aggregateDrainer.SwapFilter, which first ingests the kernel
// aggregate counts accumulated under the outgoing filter, so they cannot leak
// into the baseline the TUI resets right after a live swap.
func (e *eventLoop) SetFilter(filter globalfilter.Filter) {
	cloned := filter.Clone()
	store := func() { e.filterPtr.Store(&cloned) }
	if d := e.aggregateDrainer.Load(); d != nil {
		d.SwapFilter(store)
		return
	}
	store()
}

// SetAggregateSink wires the syscall-aggregate ingestion sink (the stats
// engine), so the kernel-side aggregate map's drained rows reach the same
// aggregates the per-event stream feeds. Part of the loop's explicit output
// mutation surface alongside SetPrintCallback/SetWarningCallback.
func (e *eventLoop) SetAggregateSink(sink syscallAggregateSink) {
	e.aggregateSink = sink
}

func newEventLoop(cfg eventLoopConfig) (*eventLoop, error) {
	fdState := configuredFDTracker(cfg.fdTracker)
	commState := configuredCommResolver(cfg.commResolver)
	if err := cfg.filter.ValidateTracepointFields(); err != nil {
		return nil, fmt.Errorf("create event filter: %w", err)
	}

	plainSink := newPlainStdoutSink(cfg.escapeMode)
	el := &eventLoop{
		pairs:          newPairTracker(),
		pendingHandles: newPendingHandleTracker(),
		fdTracker:      fdState,
		commResolver:   commState,
		// Default printCb prints each pair to stdout as a CSV row (escaped
		// as -escape selects) then recycles it. The rows are buffered, so
		// the sink is also the loop's flusher; callers (e.g. TUI,
		// headless-parquet) replace this through SetPrintCallback, which drops
		// the flusher along with the callback; configureEventLoopOutput only
		// wraps it (WrapPrintCallback), which keeps the flusher.
		outputFormatter: outputFormatter{
			printCb: plainSink.Print,
			flusher: plainSink,
		},
		rawHandlers:  make(map[types.EventType]rawEventHandler),
		exitHandlers: make(map[types.EventType]runtimeExitHandler),
		cfg:          cfg,
		done:         make(chan struct{}),
	}
	if el.cfg.aggregateDrainEvery <= 0 {
		el.cfg.aggregateDrainEvery = defaultAggregateDrainEvery
	}
	// Failed stdout writes of the default sink reach the loop, which stops the
	// trace and makes the run exit non-zero (outputFailed).
	plainSink.onErr = el.outputFailed
	el.initSamplingTally(cfg.samplingRates, cfg.samplingFamilyRates)
	el.SetFilter(cfg.filter)
	el.initRawHandlers()
	el.initRuntimeEventKinds()
	el.configureOutputCallback()
	el.seedTrackedPidComm()
	return el, nil
}

func configuredFDTracker(injected *fdTracker) *fdTracker {
	if injected == nil {
		return newFDTracker(nil)
	}
	// The tracker owns its own invariants (map allocation, per-pid index
	// seeding); the loop only decides WHICH tracker to use.
	injected.ensureInit()
	return injected
}

func configuredCommResolver(injected *commResolver) *commResolver {
	if injected == nil {
		return newCommResolver(nil)
	}
	// The resolver owns its own invariants; the loop only decides WHICH
	// resolver to use.
	injected.ensureInitialized()
	return injected
}

func (e *eventLoop) seedTrackedPidComm() {
	e.commState().seedTrackedPidComm(e.cfg.pidFilter)
}

func (e *eventLoop) fdState() *fdTracker {
	if e.fdTracker == nil {
		e.fdTracker = newFDTracker(nil)
	}
	return e.fdTracker
}

func (e *eventLoop) pendingHandleState() *pendingHandleTracker {
	if e.pendingHandles == nil {
		e.pendingHandles = newPendingHandleTracker()
	}
	return e.pendingHandles
}

// commState returns the loop's comm resolver, creating and wiring it on first
// use. The wiring (the resolver completing its own invariants, then taking the
// loop's warning sink unless it already has one) runs once per resolver
// instance: the hot path is a single pointer comparison, and a resolver
// swapped in later (tests do this) is still wired on its first use. The fast
// path relies on the wired resolver's warningFn never being cleared (see
// commWired).
func (e *eventLoop) commState() *commResolver {
	if r := e.commResolver; r != nil && r == e.commWired {
		return r
	}
	return e.wireCommState()
}

func (e *eventLoop) wireCommState() *commResolver {
	if e.commResolver == nil {
		e.commResolver = newCommResolver(nil)
	}
	e.commResolver.ensureInitialized()
	e.commResolver.setDefaultWarningFn(e.notifyWarning)
	e.commWired = e.commResolver
	return e.commResolver
}

func (e *eventLoop) configureOutputCallback() {
	switch {
	case e.cfg.pprofEnable:
		e.SetPrintCallback(func(ep *event.Pair) {
			ep.Recycle()
		})
	}
}

// stats blocks until the event loop has finished and then renders the
// end-of-run statistics block.
func (e *eventLoop) stats() string {
	// Human-facing progress note; routed through the status sink (stderr in
	// headless modes) so stdout stays machine-readable (the CSV header/rows
	// in -plain mode).
	e.notifyStatus("Waiting for stats to be ready")
	<-e.done
	duration := time.Since(e.startTime)
	rate := perSecondRate(duration.Seconds())

	return fmt.Sprintf(
		"Statistics:\n"+
			"\tduration: %v\n"+
			"\ttracepoints: %v (%.2f/s)\n"+
			"\tsyscalls: %d (%.2f/s) with %d mismatched enter/exit pairs (%.2f%%)\n"+
			"\tsyscalls after filter: %d (%.2f/s)\n"+
			"\tgroup-dead exits: %d\n"+
			"%s%s",
		duration,
		e.numTracepoints, rate(uint64(e.numTracepoints)),
		e.numSyscalls, rate(uint64(e.numSyscalls)), e.numTracepointMismatches, e.mismatchPercent(),
		e.numSyscallsAfterFilter, rate(uint64(e.numSyscallsAfterFilter)),
		e.numGroupDeadExits,
		e.outputLossStatLine()+e.ringbufDropStatLine(rate)+e.discardedAtStopStatLine()+e.leftInKernelRingStatLine()+e.fdCopySkipStatLine(),
		e.samplingStatLines(),
	)
}

// outputLossStatLine reports the rows the -plain sink dropped on failed stdout
// writes, so "syscalls after filter" is not read as "rows written". It is
// empty on a healthy run. The count is an upper bound: a partial write is
// counted as losing its whole batch.
func (e *eventLoop) outputLossStatLine() string {
	if e.rowsLost == 0 {
		return ""
	}
	return fmt.Sprintf("\trows lost to stdout write errors: up to %d (counted in syscalls after filter)\n", e.rowsLost)
}

// fdCopySkipStatLine reports the fd-table copies the tracker skipped
// (fdTracker.inheritSkipped): forks, and execs/CLOSE_RANGE_UNSHARE leaving a
// shared table, whose source table held more than maxInheritedEntries
// fd-table plus procfs-cache entries, or whose copy would not fit in ior's own
// tracker maps (the files and procfs-cache maps would exceed filesLimit or
// cacheLimit; see inheritFits). That second reason is about ior's bounded
// bookkeeping, not the traced process's fd table or RLIMIT_NOFILE, so the line
// says "no room in ior's fd tracker" rather than "fd table full". Those
// processes start with an empty tracked table and resolve their inherited
// descriptors through procfs, so their rows may show the procfs spelling
// (pipe:[N]) or E:name instead of the tracked name; the line explains such
// rows. Like the other
// conditional lines it is empty when nothing was skipped, the common case.
// stats() reads the counter only after e.done is closed, so the event-loop
// goroutine that writes it has finished.
func (e *eventLoop) fdCopySkipStatLine() string {
	skipped := e.fdState().inheritSkipped
	if skipped == 0 {
		return ""
	}
	return fmt.Sprintf(
		"\tfd-table copies skipped: %d (source table over %d entries or no room in ior's fd tracker; descriptors resolved through procfs)\n",
		skipped, maxInheritedEntries,
	)
}

// perSecondRate returns a counter-to-rate converter for a run of secs seconds.
// It guards against division by zero when stats are taken immediately after
// start (secs <= 0 yields a rate of 0).
func perSecondRate(secs float64) func(uint64) float64 {
	return func(n uint64) float64 {
		if secs <= 0 {
			return 0
		}
		return float64(n) / secs
	}
}

// mismatchPercent returns mismatched enter/exit pairs as a share of the pairs
// the tracker formed (numSyscalls).
//
// Numerator and denominator are deliberately the same unit. A mismatch is
// counted once per *pair* (tracepointExited: the exit found its parked enter
// but their trace IDs do not belong together), and numSyscalls is incremented
// on that very path just before the ID check, so every mismatch is also a
// member of the denominator and the result is a true 0..100% share. A
// noreturn row (completeNoReturnEnter) also counts in numSyscalls: it is a
// formed pair, just one that cannot mismatch, since no exit record is involved.
// It used
// to divide by numTracepoints, which counts ring-buffer *records* - at least
// two per pair, plus control records - so even a run where every pair
// mismatched printed at most ~50%.
//
// numTracepoints stays the denominator of the ring-buffer drop share in
// ringbufDropStatLine instead: there the numerator (kernel drop counter)
// counts records, control records included (internal/c/exec.c), so the
// records-seen total is the matching unit.
func (e *eventLoop) mismatchPercent() float64 {
	if e.numSyscalls == 0 {
		return 0
	}
	return (float64(e.numTracepointMismatches) / float64(e.numSyscalls)) * 100
}

// ringbufDropStatLine renders the end-of-run "ring buffer drops" line.
//
// Kernel-side ring-buffer drops used to be invisible (audit findings D2 F1 /
// D9 Y2): a full event_map makes bpf_ringbuf_reserve() return NULL and the
// generated handlers skip the event. The counter is always reported, so a zero
// line is an explicit "no loss" statement - which is exactly why it may only be
// printed when the counter was actually read. Two things make it unreadable:
// no drop map in the loaded BPF object (dropSrc nil, so the monitor never ran)
// and a read that failed (ringbufDropReadFailed). In either case the run total
// is unknown, and printing the last reading - 0, for a run that never got one -
// would state "no loss" as fact about a loss nobody measured.
func (e *eventLoop) ringbufDropStatLine(rate func(uint64) float64) string {
	// Flag first, then the total: handleRingbufDropResult publishes them in
	// the opposite order, so seeing a cleared flag here guarantees the total
	// below is the one that cleared it rather than a stale reading.
	// No counter at all is the purest form of the same problem: nothing was
	// ever measured, so there is nothing to report as fact. attachRingbufDropCounter
	// already warns at startup (a TUI warning row, stderr headless), but a
	// long run's summary is read hours later and on its own.
	if e.dropSrc == nil {
		return "\tring buffer drops: unknown (drop counter unavailable)\n"
	}
	readFailed := e.ringbufDropReadFailed.Load()
	drops := e.numRingbufDrops.Load()
	if readFailed {
		if drops == 0 {
			return "\tring buffer drops: unknown (drop counter unreadable)\n"
		}
		return fmt.Sprintf(
			"\tring buffer drops: unknown (drop counter unreadable; %d counted before the failure)\n",
			drops,
		)
	}
	dropPct := 0.0
	if total := uint64(e.numTracepoints) + drops; total > 0 {
		dropPct = (float64(drops) / float64(total)) * 100
	}
	return fmt.Sprintf("\tring buffer drops: %d (%.2f/s, %.2f%% of events)\n", drops, rate(drops), dropPct)
}
