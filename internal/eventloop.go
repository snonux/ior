package internal

import "C"

import (
	"fmt"
	"reflect"
	"time"

	"ior/internal/event"
	"ior/internal/file"
	"ior/internal/globalfilter"
	"ior/internal/types"
)

const sysEnterNameToHandleAtName = "name_to_handle_at"

const (
	defaultCommLookupWorkers   = 4
	defaultCommLookupQueueSize = 512
	defaultMaxPendingEnterEvs  = 16384
	defaultMaxProcFdCacheSize  = 8192
	cacheTrimDivisor           = 4
)

type eventLoopConfig struct {
	pidFilter       int
	filter          globalfilter.Filter
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

type rawEventHandler func(raw []byte, ch chan<- *event.Pair)
type tracepointExitHandler func(ep *event.Pair) bool

type eventLoop struct {
	filter             globalfilter.Filter
	enterEvs           map[uint32]*event.Pair // Temp. store of sys_enter tracepoints per Tid.
	enterEvAges        map[uint32]uint64
	pendingHandles     map[uint32]string // map of TID to pathname from name_to_handle_at
	fdTracker          *fdTracker
	procFdCache        map[uint64]*file.FdFile // Cache procfs-resolved metadata for unknown fds.
	procFdCacheAges    map[uint64]uint64
	commResolver       *commResolver
	prevPairTimes      map[uint32]uint64 // Previous event's time (to calculate time differences between two events)
	rawHandlers        map[types.EventType]rawEventHandler
	exitHandlers       map[reflect.Type]tracepointExitHandler
	printCb            func(ep *event.Pair) // Callback to print the event
	warningCb          func(message string) // Optional callback for non-fatal event processing warnings
	cfg                eventLoopConfig
	cacheAge           uint64
	maxPendingEnterEvs int
	maxProcFdCacheSize int

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
	if err := cfg.filter.ValidateTracepointFields(); err != nil {
		return nil, fmt.Errorf("create event filter: %w", err)
	}

	el := &eventLoop{
		filter:          cfg.filter.Clone(),
		enterEvs:        make(map[uint32]*event.Pair),
		enterEvAges:     make(map[uint32]uint64),
		pendingHandles:  make(map[uint32]string),
		fdTracker:       fdState,
		procFdCache:     make(map[uint64]*file.FdFile),
		procFdCacheAges: make(map[uint64]uint64),
		commResolver:    commState,
		prevPairTimes:   make(map[uint32]uint64),
		rawHandlers:     make(map[types.EventType]rawEventHandler),
		exitHandlers:    make(map[reflect.Type]tracepointExitHandler),
		printCb:         func(ep *event.Pair) { fmt.Println(ep); ep.Recycle() },
		cfg:             cfg,
		done:            make(chan struct{}),
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
