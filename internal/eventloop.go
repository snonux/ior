package internal

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"ior/internal/event"
	"ior/internal/file"
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
	cacheTrimDivisor               = 4
	defaultAggregateDrainEvery     = time.Second
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
	startTime       time.Time
	done            chan struct{}
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
	if injected.files == nil {
		injected.files = make(map[int32]file.File)
	}
	return injected
}

func configuredCommResolver(injected *commResolver) *commResolver {
	if injected == nil {
		return newCommResolver(nil)
	}
	injected.ensureCommsAllocated()
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

func (e *eventLoop) pendingHandleState() *pendingHandleTracker {
	if e.pendingHandles == nil {
		e.pendingHandles = newPendingHandleTracker()
	}
	if e.pendingHandles.paths == nil {
		e.pendingHandles.paths = make(map[uint32]string)
	}
	if e.pendingHandles.pathAges == nil {
		e.pendingHandles.pathAges = make(map[uint32]uint64)
	}
	return e.pendingHandles
}

func (e *eventLoop) commState() *commResolver {
	if e.commResolver == nil {
		e.commResolver = newCommResolver(nil)
	}
	e.commResolver.ensureCommsAllocated()
	if e.commResolver.pending == nil {
		e.commResolver.pending = make(map[uint32]struct{})
	}
	if e.commResolver.warningFn == nil {
		e.commResolver.warningFn = e.notifyWarning
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
	mismatchPct := 0.0
	if e.numTracepoints > 0 {
		mismatchPct = (float64(e.numTracepointMismatches) / float64(e.numTracepoints)) * 100
	}

	// Kernel-side ring-buffer drops used to be invisible (audit findings
	// D2 F1 / D9 Y2): a full event_map makes bpf_ringbuf_reserve() return
	// NULL and the generated handlers skip the event. The counter is always
	// reported, so a zero line is an explicit "no loss" statement.
	drops := e.numRingbufDrops.Load()
	dropPct := 0.0
	if total := uint64(e.numTracepoints) + drops; total > 0 {
		dropPct = (float64(drops) / float64(total)) * 100
	}

	stats := fmt.Sprintf(
		"Statistics:\n"+
			"\tduration: %v\n"+
			"\ttracepoints: %v (%.2f/s) with %d mismatches (%.2f%%)\n"+
			"\tsyscalls: %d (%.2f/s)\n"+
			"\tsyscalls after filter: %d (%.2f/s)\n"+
			"\tring buffer drops: %d (%.2f/s, %.2f%% of events)\n",
		duration,
		e.numTracepoints, rate(uint64(e.numTracepoints)), e.numTracepointMismatches, mismatchPct,
		e.numSyscalls, rate(uint64(e.numSyscalls)),
		e.numSyscallsAfterFilter, rate(uint64(e.numSyscallsAfterFilter)),
		drops, rate(drops), dropPct,
	)

	return stats
}
