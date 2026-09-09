package internal

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"ior/internal/event"
	"ior/internal/globalfilter"
	"ior/internal/statsengine"
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

// ringbufDropSource reports the cumulative number of events the kernel dropped
// because the event ring buffer was full. Implemented by ringbufDropCounter
// over the BPF ringbuf_drop_map; stubbed in tests.
type ringbufDropSource interface {
	Total() (uint64, error)
}

type eventLoopConfig struct {
	pidFilter   int
	filter      globalfilter.Filter
	pprofEnable bool
	plainMode   bool
	// synchronousRawProcessing keeps raw decode and callback emission in a
	// single goroutine for deterministic test execution.
	synchronousRawProcessing bool
	fdTracker                *fdTracker
	commResolver             *commResolver
	aggregateDrainEvery      time.Duration
	aggregateIngestTraceIDs  map[types.TraceId]struct{}
}

type rawEventHandler func(raw []byte, ch chan<- *event.Pair)

type eventLoop struct {
	// filterPtr holds the active global filter. Stored as atomic.Pointer so
	// the TUI can swap filters in place via SetFilter without tearing down
	// and reattaching the BPF probes (the previous behavior caused a multi-
	// second 'Attaching tracepoints' overlay every time the filter changed).
	filterPtr       atomic.Pointer[globalfilter.Filter]
	pairs           pairTracker           // enter/exit pairing state and inter-syscall duration tracking
	pendingHandles  *pendingHandleTracker // TID → pathname from name_to_handle_at, for open_by_handle_at correlation
	fdTracker       *fdTracker            // fd table and procfs resolution cache
	commResolver    *commResolver
	outputFormatter // pair-emission and warning-notification callbacks (embedded collaborator)
	rawHandlers     map[types.EventType]rawEventHandler
	exitHandlers    map[types.EventType]runtimeExitHandler
	cfg             eventLoopConfig
	aggregateSink   syscallAggregateSink
	aggregateSrc    syscallAggregateSource
	// dropSrc reads the kernel-side ring-buffer drop counter. nil disables
	// drop monitoring (tests and any path without a BPF module).
	dropSrc ringbufDropSource

	// Statistics
	numTracepoints          uint
	numTracepointMismatches uint
	numSyscalls             uint
	numSyscallsAfterFilter  uint
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
	startTime          time.Time
	done               chan struct{}
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
// what the eventloop sees.
func (e *eventLoop) SetFilter(filter globalfilter.Filter) {
	cloned := filter.Clone()
	e.filterPtr.Store(&cloned)
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

	el := &eventLoop{
		pairs:          newPairTracker(),
		pendingHandles: newPendingHandleTracker(),
		fdTracker:      fdState,
		commResolver:   commState,
		// Default printCb prints each pair to stdout then recycles it; callers
		// (e.g. TUI, headless-parquet) replace this via configureEventLoopOutput.
		outputFormatter: outputFormatter{
			printCb: func(ep *event.Pair) { fmt.Println(ep); ep.Recycle() },
		},
		rawHandlers:  make(map[types.EventType]rawEventHandler),
		exitHandlers: make(map[types.EventType]runtimeExitHandler),
		cfg:          cfg,
		done:         make(chan struct{}),
	}
	if el.cfg.aggregateDrainEvery <= 0 {
		el.cfg.aggregateDrainEvery = defaultAggregateDrainEvery
	}
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
	// The tracker owns its own invariants (map allocation, pid-presence
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

func (e *eventLoop) commState() *commResolver {
	if e.commResolver == nil {
		e.commResolver = newCommResolver(nil)
	}
	e.commResolver.ensureInitialized()
	e.commResolver.setDefaultWarningFn(e.notifyWarning)
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

func (e *eventLoop) stats() string {
	// Human-facing progress note; stderr so stdout stays machine-readable
	// (the CSV header/rows in -plain mode).
	_, _ = fmt.Fprintln(os.Stderr, "Waiting for stats to be ready")
	<-e.done
	duration := time.Since(e.startTime)

	secs := duration.Seconds()
	// Guard against division by zero when called immediately after start.
	rate := func(n uint64) float64 {
		if secs <= 0 {
			return 0
		}
		return float64(n) / secs
	}
	// numTracepoints counts every non-empty ring-buffer record the loop pulled
	// off the ring. It is incremented before dispatch, so it counts records
	// *seen*, not records successfully turned into something: records that fail
	// to decode (dropMalformedRawEvent) and records of an unhandled event type
	// are included, and so are - since the sched_process_exec probe - control
	// records (one per successful execve and one per task exit, since the
	// sched probes) alongside the syscall enter/exit
	// records. Both denominators below are deliberately left on that total: the
	// kernel-side drop counter also counts control records it failed to reserve
	// (internal/c/exec.c), so "drops as a share of events" only stays
	// arithmetically honest if the events side counts them too. The mismatch
	// share is diluted by the same records, which is acceptable - execve is
	// rare next to syscall traffic, task exits less so on thread-churning
	// workloads, and both figures describe the ring-buffer
	// stream as a whole rather than the syscall pairs alone.
	mismatchPct := 0.0
	if e.numTracepoints > 0 {
		mismatchPct = (float64(e.numTracepointMismatches) / float64(e.numTracepoints)) * 100
	}

	stats := fmt.Sprintf(
		"Statistics:\n"+
			"\tduration: %v\n"+
			"\ttracepoints: %v (%.2f/s) with %d mismatches (%.2f%%)\n"+
			"\tsyscalls: %d (%.2f/s)\n"+
			"\tsyscalls after filter: %d (%.2f/s)\n"+
			"%s",
		duration,
		e.numTracepoints, rate(uint64(e.numTracepoints)), e.numTracepointMismatches, mismatchPct,
		e.numSyscalls, rate(uint64(e.numSyscalls)),
		e.numSyscallsAfterFilter, rate(uint64(e.numSyscallsAfterFilter)),
		e.ringbufDropStatLine(rate),
	)

	return stats
}

// ringbufDropStatLine renders the end-of-run "ring buffer drops" line.
//
// Kernel-side ring-buffer drops used to be invisible (audit findings D2 F1 /
// D9 Y2): a full event_map makes bpf_ringbuf_reserve() return NULL and the
// generated handlers skip the event. The counter is always reported, so a zero
// line is an explicit "no loss" statement - which is exactly why it may only be
// printed when the counter was actually read. If the last read failed the run
// total is unknown, and printing the last reading (0, for a run whose first
// read already failed) would state "no loss" as fact about a loss nobody
// measured.
func (e *eventLoop) ringbufDropStatLine(rate func(uint64) float64) string {
	// Flag first, then the total: handleRingbufDropResult publishes them in
	// the opposite order, so seeing a cleared flag here guarantees the total
	// below is the one that cleared it rather than a stale reading.
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
