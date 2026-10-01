package internal

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parkwait"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// pendingAggregateSource models the kernel aggregate map: counts accumulate
// via add until a Drain returns and clears them, like the delta-draining
// syscallAggregateConsumer.
type pendingAggregateSource struct {
	mu      sync.Mutex
	pending map[types.TraceId]uint64
}

func (s *pendingAggregateSource) add(id types.TraceId, count uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = map[types.TraceId]uint64{}
	}
	s.pending[id] += count
}

func (s *pendingAggregateSource) Drain() ([]statsengine.SyscallAggregate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows := make([]statsengine.SyscallAggregate, 0, len(s.pending))
	for id, count := range s.pending {
		rows = append(rows, statsengine.SyscallAggregate{TraceID: id, Count: count})
	}
	s.pending = nil
	return rows, nil
}

func (s *pendingAggregateSource) pendingCount(id types.TraceId) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending[id]
}

// startSwapTestLoop starts a drain loop whose ticker never fires during the
// test (only SetFilter flushes and the final drain on stop reach the engine).
func startSwapTestLoop(t *testing.T, initial globalfilter.Filter) (*eventLoop, *pendingAggregateSource, *statsengine.Engine, func()) {
	t.Helper()
	src := &pendingAggregateSource{}
	el, engine, stop := startSwapTestLoopWith(t, initial, src)
	return el, src, engine, stop
}

// startSwapTestLoopWith is startSwapTestLoop over a caller-provided source.
func startSwapTestLoopWith(t *testing.T, initial globalfilter.Filter, src syscallAggregateSource) (*eventLoop, *statsengine.Engine, func()) {
	t.Helper()
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery:     time.Hour,
			aggregateIngestTraceIDs: map[types.TraceId]struct{}{types.SYS_ENTER_FUTEX: {}},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	el.SetFilter(initial)
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	return el, engine, func() { cancel(); stop() }
}

func totalSyscalls(t *testing.T, engine *statsengine.Engine) uint64 {
	t.Helper()
	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	return snap.TotalSyscalls
}

// TestLiveFilterSwapKeepsPreSwapAggregatesOutOfFreshBaseline is the
// regression test for the TUI live swap: SetFilter followed by an engine
// reset must leave only post-swap kernel counts in the new baseline. Before
// the flush-on-swap, the counts still pending in the map at swap time were
// drained by the first post-swap tick into the fresh baseline (14, not 10).
func TestLiveFilterSwapKeepsPreSwapAggregatesOutOfFreshBaseline(t *testing.T) {
	el, src, engine, stop := startSwapTestLoop(t, globalfilter.Filter{})

	src.add(types.SYS_ENTER_FUTEX, 4) // accumulated before the swap
	el.SetFilter(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "futex"}})
	engine.Reset() // what resetAggregatesAfterLiveSwap does right after the setter
	src.add(types.SYS_ENTER_FUTEX, 10)
	stop()

	if got := totalSyscalls(t, engine); got != 10 {
		t.Fatalf("TotalSyscalls after swap+reset = %d, want 10 (post-swap counts only)", got)
	}
}

// TestLiveFilterSwapJudgesPendingAggregatesByOutgoingFilter checks that the
// flush applies the filter the counts accumulated under: futex counts from a
// period whose filter excluded futex must not appear once the new filter
// selects futex, even without a stats reset.
func TestLiveFilterSwapJudgesPendingAggregatesByOutgoingFilter(t *testing.T) {
	excludeFutex := globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "^read$"}}
	el, src, engine, stop := startSwapTestLoop(t, excludeFutex)

	src.add(types.SYS_ENTER_FUTEX, 4)
	el.SetFilter(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "futex"}})
	if got := src.pendingCount(types.SYS_ENTER_FUTEX); got != 0 {
		t.Fatalf("pending futex after swap = %d, want 0 (flushed at swap)", got)
	}
	src.add(types.SYS_ENTER_FUTEX, 10)
	stop()

	if got := totalSyscalls(t, engine); got != 10 {
		t.Fatalf("TotalSyscalls = %d, want 10 (pre-swap futex was filtered out)", got)
	}
}

// TestSetFilterAfterDrainLoopStopDoesNotDrain is the negative case: once the
// loop's stop function ran, the drainer is unpublished and SetFilter is a
// plain swap that leaves the source alone.
func TestSetFilterAfterDrainLoopStopDoesNotDrain(t *testing.T) {
	el, src, _, stop := startSwapTestLoop(t, globalfilter.Filter{})
	stop()

	src.add(types.SYS_ENTER_FUTEX, 3)
	el.SetFilter(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "futex"}})
	if got := src.pendingCount(types.SYS_ENTER_FUTEX); got != 3 {
		t.Fatalf("pending futex = %d, want 3 (no drain after stop)", got)
	}
	if got := el.Filter(); got.Syscall == nil || got.Syscall.Pattern != "futex" {
		t.Fatalf("filter after swap = %+v, want syscall futex", got)
	}
}

// TestNewEventLoopConfigCarriesKernelProcessScope pins the wiring the
// aggregate drainer's kernelProcessScope depends on: the -pid/-tid values the
// BPF program is loaded with must reach eventLoopConfig unchanged.
func TestNewEventLoopConfigCarriesKernelProcessScope(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PidFilter, cfg.TidFilter = 42, 43
	got := newEventLoopConfig(cfg)
	if got.pidFilter != 42 || got.tidFilter != 43 {
		t.Fatalf("pidFilter/tidFilter = %d/%d, want 42/43", got.pidFilter, got.tidFilter)
	}

	unscoped := newEventLoopConfig(flags.NewFlags())
	if unscoped.pidFilter != -1 || unscoped.tidFilter != -1 {
		t.Fatalf("default pidFilter/tidFilter = %d/%d, want -1/-1", unscoped.pidFilter, unscoped.tidFilter)
	}
}

// gatedAggregateSource counts Drain calls and, while armed, parks the next
// Drain until release is closed, signalling entered first. It lets a test
// hold the drainer's lock inside the final drain.
type gatedAggregateSource struct {
	pendingAggregateSource
	drains  atomic.Int32
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (s *gatedAggregateSource) Drain() ([]statsengine.SyscallAggregate, error) {
	s.drains.Add(1)
	if s.armed.CompareAndSwap(true, false) {
		close(s.entered)
		<-s.release
	}
	return s.pendingAggregateSource.Drain()
}

// swapFilterFrame and swapFilterReasons identify a goroutine parked on the
// drainer mutex inside aggregateDrainer.SwapFilter in the runtime's goroutine
// dump (see package parkwait): "sync.Mutex.Lock" in the header on current
// toolchains, "semacquire" on older ones.
const swapFilterFrame = "(*aggregateDrainer).SwapFilter"

var swapFilterReasons = []string{parkwait.MutexLock, parkwait.Semacquire}

// blockedInSwapFilter counts goroutines currently parked on a mutex inside
// aggregateDrainer.SwapFilter, among those started by the calling (test)
// goroutine, so a goroutine leaked by another test cannot count (see package
// parkwait). It is the only way to observe "this goroutine
// reached the lock and is waiting for it" without a test seam in production
// code: a goroutine that merely started, or that is still spinning before it
// parks, does not count.
func blockedInSwapFilter() int {
	return parkwait.Count(swapFilterFrame, swapFilterReasons...)
}

// awaitSwapFilterBlocked returns once a goroutine beyond the baseline count is
// parked on the drainer lock inside SwapFilter, which proves the swap is
// contending with the drain that holds it. It replaces a fixed sleep that only
// hoped the swapping goroutine had been scheduled by then: on a loaded host the
// goroutine could reach the lock after the drain finished, so the test would
// take the uncontended "already retired" path and pass vacuously. The polling
// waits on that condition, not on elapsed time; the deadline only bounds a
// failing run. If the swap instead returns early (done closed), it never
// waited for the lock - the regression these tests pin - and the test fails.
func awaitSwapFilterBlocked(t *testing.T, baseline int, done <-chan struct{}) {
	t.Helper()
	parkwait.Await{
		Frame:      swapFilterFrame,
		Reasons:    swapFilterReasons,
		Baseline:   baseline,
		Done:       done,
		DoneMsg:    "swap returned while the final drain held the drainer lock; it must wait for the lock",
		TimeoutMsg: "swap never blocked on the drainer lock inside SwapFilter",
	}.Run(t)
}

// releaseOnce returns an idempotent closer for release that is also
// registered as cleanup, so a test failing while the final drain is parked
// inside Drain does not leave that goroutine (and the drainer lock) stuck.
func releaseOnce(t *testing.T, release chan struct{}) func() {
	t.Helper()
	var once sync.Once
	closeRelease := func() { once.Do(func() { close(release) }) }
	t.Cleanup(closeRelease)
	return closeRelease
}

func newFutexDrainer(src syscallAggregateSource) *aggregateDrainer {
	return newAggregateDrainer(src,
		map[types.TraceId]struct{}{types.SYS_ENTER_FUTEX: {}},
		kernelProcessScope{},
		func() globalfilter.Filter { return globalfilter.Filter{} })
}

// TestSwapFilterAfterDrainerStopDrainsNothing covers a SetFilter that loaded
// the drainer pointer before stop unpublished it and calls SwapFilter only
// after stop returned (when the BPF map may already be closed): the final
// drain retired the drainer, so the swap must not drain or handle anything.
func TestSwapFilterAfterDrainerStopDrainsNothing(t *testing.T) {
	src := &gatedAggregateSource{}
	d := newFutexDrainer(src)
	handled := 0
	stop := d.Start(context.Background(), time.Hour, func(aggregateDrainResult) { handled++ })
	stop()
	drainsAtStop, handledAtStop := src.drains.Load(), handled

	src.add(types.SYS_ENTER_FUTEX, 3)
	applied := false
	d.SwapFilter(func() { applied = true })

	if !applied {
		t.Fatal("SwapFilter after stop did not apply the new filter")
	}
	if got := src.drains.Load(); got != drainsAtStop {
		t.Fatalf("Drain calls = %d after late SwapFilter, want %d (retired drainer)", got, drainsAtStop)
	}
	if handled != handledAtStop {
		t.Fatalf("handle calls = %d, want %d", handled, handledAtStop)
	}
	if got := src.pendingCount(types.SYS_ENTER_FUTEX); got != 3 {
		t.Fatalf("pending futex = %d, want 3 (not drained)", got)
	}
}

// TestSwapFilterBlockedDuringFinalDrainDrainsNothing is the concurrent
// variant: the SwapFilter waits on the drainer lock while the final drain
// runs, and must find the drainer retired once it gets the lock.
func TestSwapFilterBlockedDuringFinalDrainDrainsNothing(t *testing.T) {
	src := &gatedAggregateSource{entered: make(chan struct{}), release: make(chan struct{})}
	d := newFutexDrainer(src)
	stop := d.Start(context.Background(), time.Hour, func(aggregateDrainResult) {})

	closeRelease := releaseOnce(t, src.release)
	src.armed.Store(true)
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	<-src.entered // the final drain now holds the drainer lock

	baseline := blockedInSwapFilter()
	swapped := make(chan struct{})
	go func() { d.SwapFilter(func() {}); close(swapped) }()
	awaitSwapFilterBlocked(t, baseline, swapped) // SwapFilter is queued on the lock
	closeRelease()
	<-stopped
	<-swapped

	if got := src.drains.Load(); got != 1 {
		t.Fatalf("Drain calls = %d, want 1 (only the final drain)", got)
	}
	src.add(types.SYS_ENTER_FUTEX, 7)
	d.SwapFilter(func() {})
	if got := src.pendingCount(types.SYS_ENTER_FUTEX); got != 7 {
		t.Fatalf("pending futex = %d, want 7 (retired drainer never drains)", got)
	}
}

// TestSetFilterDuringStopJudgesPendingCountsByOutgoingFilter covers a live
// swap landing while the drain loop stops: the final drain is parked inside
// Drain (holding the drainer lock) when SetFilter arrives. The pre-stop futex
// counts accumulated under a filter that excludes futex, so they must not be
// ingested. When stop unpublished the drainer before its final drain, that
// SetFilter took the plain-swap path, installed the futex filter at once, and
// the final drain ingested the 4 pre-stop futex calls under it.
func TestSetFilterDuringStopJudgesPendingCountsByOutgoingFilter(t *testing.T) {
	src := &gatedAggregateSource{entered: make(chan struct{}), release: make(chan struct{})}
	excludeFutex := globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "^read$"}}
	el, engine, stop := startSwapTestLoopWith(t, excludeFutex, src)

	src.add(types.SYS_ENTER_FUTEX, 4)
	closeRelease := releaseOnce(t, src.release)
	src.armed.Store(true)
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	<-src.entered // the final drain now holds the drainer lock

	baseline := blockedInSwapFilter()
	swapped := make(chan struct{})
	go func() {
		el.SetFilter(globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "futex"}})
		close(swapped)
	}()
	// SetFilter must have gone through the still-published drainer and be
	// queued on its lock; with the drainer unpublished before the final drain
	// it would instead return at once (plain swap) and fail here.
	awaitSwapFilterBlocked(t, baseline, swapped)
	closeRelease()
	<-stopped
	<-swapped

	if got := totalSyscalls(t, engine); got != 0 {
		t.Fatalf("TotalSyscalls = %d, want 0 (pre-stop futex judged by the outgoing ^read$ filter)", got)
	}
	if got := el.Filter(); got.Syscall == nil || got.Syscall.Pattern != "futex" {
		t.Fatalf("filter after swap = %+v, want syscall futex", got)
	}
}
