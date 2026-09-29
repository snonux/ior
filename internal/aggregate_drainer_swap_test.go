package internal

import (
	"context"
	"sync"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
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
	return el, src, engine, func() { cancel(); stop() }
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
