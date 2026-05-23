package internal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

type aggregateSourceStub struct {
	mu   sync.Mutex
	rows [][]statsengine.SyscallAggregate
	err  error
}

func (s *aggregateSourceStub) Drain() ([]statsengine.SyscallAggregate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if len(s.rows) == 0 {
		return nil, nil
	}
	next := s.rows[0]
	s.rows = s.rows[1:]
	return next, nil
}

type aggregateSinkStub struct {
	mu   sync.Mutex
	rows []statsengine.SyscallAggregate
}

func (s *aggregateSinkStub) IngestSyscallAggregates(rows []statsengine.SyscallAggregate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, rows...)
}

func TestAggregateDrainerTickFiltersAggregateOnlyTraceIDs(t *testing.T) {
	drainer := newAggregateDrainer(
		&aggregateSourceStub{
			rows: [][]statsengine.SyscallAggregate{{
				{TraceID: types.SYS_ENTER_FUTEX, Count: 2},
				{TraceID: types.SYS_ENTER_CLOCK_GETTIME, Count: 5},
			}},
		},
		map[types.TraceId]struct{}{
			types.SYS_ENTER_FUTEX: {},
		},
		func() globalfilter.Filter { return globalfilter.Filter{} },
	)

	got := drainer.Tick()
	if got.warning != "" {
		t.Fatalf("warning = %q, want empty", got.warning)
	}
	if len(got.rows) != 1 {
		t.Fatalf("filtered rows len = %d, want 1", len(got.rows))
	}
	if got.rows[0].TraceID != types.SYS_ENTER_FUTEX {
		t.Fatalf("filtered trace id = %v, want %v", got.rows[0].TraceID, types.SYS_ENTER_FUTEX)
	}
}

func TestAggregateDrainerTickGatesWhenUnsupportedFilterActive(t *testing.T) {
	drainer := newAggregateDrainer(
		&aggregateSourceStub{
			rows: [][]statsengine.SyscallAggregate{{
				{TraceID: types.SYS_ENTER_FUTEX, Count: 2},
			}},
		},
		map[types.TraceId]struct{}{
			types.SYS_ENTER_FUTEX: {},
		},
		func() globalfilter.Filter {
			return globalfilter.Filter{
				Comm: &globalfilter.StringFilter{Pattern: "ioworkload"},
			}
		},
	)

	got := drainer.Tick()
	if got.warning != "" {
		t.Fatalf("warning = %q, want empty", got.warning)
	}
	if len(got.rows) != 0 {
		t.Fatalf("expected no rows when comm filter is active, got %+v", got.rows)
	}
}

func TestAggregateDrainerTickRejectsRowsWithoutAggregateOnlyTraceIDs(t *testing.T) {
	drainer := newAggregateDrainer(
		&aggregateSourceStub{
			rows: [][]statsengine.SyscallAggregate{{
				{TraceID: types.SYS_ENTER_FUTEX, Count: 2},
			}},
		},
		nil,
		func() globalfilter.Filter { return globalfilter.Filter{} },
	)

	got := drainer.Tick()
	if got.warning != "" {
		t.Fatalf("warning = %q, want empty", got.warning)
	}
	if len(got.rows) != 0 {
		t.Fatalf("expected no rows without aggregate-only trace IDs, got %+v", got.rows)
	}
}

func TestAggregateDrainerTickRejectsPIDAndTIDFilters(t *testing.T) {
	tests := []struct {
		name   string
		filter globalfilter.Filter
	}{
		{name: "pid", filter: globalfilter.Filter{PID: globalfilter.NewEqFilter(42)}},
		{name: "tid", filter: globalfilter.Filter{TID: globalfilter.NewEqFilter(43)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			drainer := newAggregateDrainer(
				&aggregateSourceStub{
					rows: [][]statsengine.SyscallAggregate{{
						{TraceID: types.SYS_ENTER_FUTEX, Count: 2},
					}},
				},
				map[types.TraceId]struct{}{
					types.SYS_ENTER_FUTEX: {},
				},
				func() globalfilter.Filter { return tt.filter },
			)

			got := drainer.Tick()
			if got.warning != "" {
				t.Fatalf("warning = %q, want empty", got.warning)
			}
			if len(got.rows) != 0 {
				t.Fatalf("expected no aggregate rows with %s filter, got %+v", tt.name, got.rows)
			}
		})
	}
}

func TestAggregateDrainerTickReturnsDrainWarning(t *testing.T) {
	drainer := newAggregateDrainer(
		&aggregateSourceStub{err: errors.New("boom")},
		map[types.TraceId]struct{}{
			types.SYS_ENTER_FUTEX: {},
		},
		func() globalfilter.Filter { return globalfilter.Filter{} },
	)

	got := drainer.Tick()
	if len(got.rows) != 0 {
		t.Fatalf("rows len = %d, want 0", len(got.rows))
	}
	if got.warning != "syscall aggregate drain failed: boom" {
		t.Fatalf("warning = %q, want drain failure", got.warning)
	}
}

func TestStartAggregateDrainLoopFinalFlushesOnStop(t *testing.T) {
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{
			{{TraceID: types.SYS_ENTER_FUTEX, Count: 2}},
		},
	}
	sink := &aggregateSinkStub{}
	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: 5 * time.Second,
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: sink,
	}
	el.SetFilter(globalfilter.Filter{})

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	time.Sleep(2 * time.Millisecond)
	cancel()
	stop()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.rows) != 1 {
		t.Fatalf("final flush rows len = %d, want 1", len(sink.rows))
	}
	if sink.rows[0].TraceID != types.SYS_ENTER_FUTEX || sink.rows[0].Count != 2 {
		t.Fatalf("final flush row = %+v, want futex count=2", sink.rows[0])
	}
}

// TestAggregateEndToEndDrainIntoStatsEngine verifies that aggregate rows flow
// from the source stub through the drainer, past filter gating, into a real
// statsengine.Engine and appear in the resulting snapshot. This covers the
// full ingestion path that individual unit tests cannot: decode -> filter ->
// IngestSyscallAggregates -> Snapshot.
func TestAggregateEndToEndDrainIntoStatsEngine(t *testing.T) {
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{{
			{
				TraceID:        types.SYS_ENTER_FUTEX,
				Count:          5,
				Errors:         1,
				TotalLatencyNs: 500,
				MinLatencyNs:   50,
				MaxLatencyNs:   200,
				LatencyHistogramNs: [8]uint64{
					0, 2, 3, 0, 0, 0, 0, 0,
				},
			},
		}},
	}

	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: 5 * time.Second,
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	el.SetFilter(globalfilter.Filter{})

	// Run the drain loop and immediately stop so the final flush fires.
	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 5 {
		t.Fatalf("TotalSyscalls = %d, want 5", snap.TotalSyscalls)
	}
	if snap.TotalErrors != 1 {
		t.Fatalf("TotalErrors = %d, want 1", snap.TotalErrors)
	}

	// Verify the per-syscall row for futex exists with correct counts.
	futexRow := findSyscallSnapshot(t, snap.Syscalls(), types.SYS_ENTER_FUTEX)
	if futexRow.Count != 5 {
		t.Fatalf("futex Count = %d, want 5", futexRow.Count)
	}
	if futexRow.Errors != 1 {
		t.Fatalf("futex Errors = %d, want 1", futexRow.Errors)
	}
	if futexRow.TotalLatencyNs != 500 {
		t.Fatalf("futex TotalLatencyNs = %d, want 500", futexRow.TotalLatencyNs)
	}
	if futexRow.LatencyMinNs != 50 {
		t.Fatalf("futex LatencyMinNs = %d, want 50", futexRow.LatencyMinNs)
	}
	if futexRow.LatencyMaxNs != 200 {
		t.Fatalf("futex LatencyMaxNs = %d, want 200", futexRow.LatencyMaxNs)
	}

	// Verify the latency histogram received the bucket counts.
	if snap.LatencyHistogram.Total != 5 {
		t.Fatalf("LatencyHistogram.Total = %d, want 5", snap.LatencyHistogram.Total)
	}
}

// TestAggregateEndToEndMultipleDrainTicksAccumulate verifies that successive
// drain ticks from separate source batches accumulate into the statsengine
// correctly, ensuring the periodic drain loop handles multiple rounds.
func TestAggregateEndToEndMultipleDrainTicksAccumulate(t *testing.T) {
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{
			{{TraceID: types.SYS_ENTER_FUTEX, Count: 3, TotalLatencyNs: 300, MinLatencyNs: 100, MaxLatencyNs: 100}},
			{{TraceID: types.SYS_ENTER_FUTEX, Count: 7, TotalLatencyNs: 700, MinLatencyNs: 50, MaxLatencyNs: 200}},
		},
	}

	// Use a short drain interval so the ticker fires for both batches.
	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: time.Millisecond,
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	el.SetFilter(globalfilter.Filter{})

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	// Allow enough time for both tick rounds to fire.
	time.Sleep(10 * time.Millisecond)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 10 {
		t.Fatalf("TotalSyscalls = %d, want 10 (3+7)", snap.TotalSyscalls)
	}

	futexRow := findSyscallSnapshot(t, snap.Syscalls(), types.SYS_ENTER_FUTEX)
	if futexRow.Count != 10 {
		t.Fatalf("futex Count = %d, want 10", futexRow.Count)
	}
	// Min should reflect the lowest across both batches (50).
	if futexRow.LatencyMinNs != 50 {
		t.Fatalf("futex LatencyMinNs = %d, want 50", futexRow.LatencyMinNs)
	}
	// Max should reflect the highest across both batches (200).
	if futexRow.LatencyMaxNs != 200 {
		t.Fatalf("futex LatencyMaxNs = %d, want 200", futexRow.LatencyMaxNs)
	}
}

// TestAggregateEndToEndNonDesignatedSyscallsFiltered verifies that only
// aggregate-only designated trace IDs reach the statsengine. A source emitting
// rows for both futex (designated) and clock_gettime (not designated) should
// only produce a futex row in the snapshot.
func TestAggregateEndToEndNonDesignatedSyscallsFiltered(t *testing.T) {
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{{
			{TraceID: types.SYS_ENTER_FUTEX, Count: 4, TotalLatencyNs: 400, MinLatencyNs: 100, MaxLatencyNs: 100},
			{TraceID: types.SYS_ENTER_CLOCK_GETTIME, Count: 8, TotalLatencyNs: 800, MinLatencyNs: 100, MaxLatencyNs: 100},
		}},
	}

	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: 5 * time.Second,
			// Only futex is aggregate-only; clock_gettime should be dropped.
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	el.SetFilter(globalfilter.Filter{})

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 4 {
		t.Fatalf("TotalSyscalls = %d, want 4 (only futex)", snap.TotalSyscalls)
	}

	// Futex should be present.
	futexRow := findSyscallSnapshot(t, snap.Syscalls(), types.SYS_ENTER_FUTEX)
	if futexRow.Count != 4 {
		t.Fatalf("futex Count = %d, want 4", futexRow.Count)
	}

	// clock_gettime should be absent.
	for _, row := range snap.Syscalls() {
		if row.TraceID == types.SYS_ENTER_CLOCK_GETTIME {
			t.Fatalf("clock_gettime should not appear in snapshot, got %+v", row)
		}
	}
}

// TestAggregateEndToEndFilterGateBlocksIngestion verifies that when an
// unsupported filter (e.g. comm filter) is active, aggregate rows never
// reach the statsengine even though the source emits data.
func TestAggregateEndToEndFilterGateBlocksIngestion(t *testing.T) {
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{{
			{TraceID: types.SYS_ENTER_FUTEX, Count: 10, TotalLatencyNs: 1000, MinLatencyNs: 100, MaxLatencyNs: 100},
		}},
	}

	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: 5 * time.Second,
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	// Set a comm filter that blocks aggregate ingestion.
	el.SetFilter(globalfilter.Filter{
		Comm: &globalfilter.StringFilter{Pattern: "myapp"},
	})

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	if snap.TotalSyscalls != 0 {
		t.Fatalf("TotalSyscalls = %d, want 0 (comm filter should block aggregates)", snap.TotalSyscalls)
	}
	if len(snap.Syscalls()) != 0 {
		t.Fatalf("expected no syscall rows with comm filter active, got %d", len(snap.Syscalls()))
	}
}

// TestAggregateEndToEndFamilyRowPopulated verifies that aggregate-only
// ingestion also populates the per-family snapshot rows, not just per-syscall.
func TestAggregateEndToEndFamilyRowPopulated(t *testing.T) {
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{{
			{
				TraceID:        types.SYS_ENTER_FUTEX,
				Count:          6,
				TotalLatencyNs: 600,
				MinLatencyNs:   50,
				MaxLatencyNs:   200,
			},
		}},
	}

	el := &eventLoop{
		cfg: eventLoopConfig{
			aggregateDrainEvery: 5 * time.Second,
			aggregateOnlyTraceIDs: map[types.TraceId]struct{}{
				types.SYS_ENTER_FUTEX: {},
			},
		},
		aggregateSrc:  src,
		aggregateSink: engine,
	}
	el.SetFilter(globalfilter.Filter{})

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}

	// Futex belongs to a syscall family; verify the family row is populated.
	futexFamily := types.SYS_ENTER_FUTEX.Family()
	var found bool
	for _, fam := range snap.Families() {
		if fam.Family == futexFamily {
			found = true
			if fam.Count != 6 {
				t.Fatalf("family %s Count = %d, want 6", futexFamily, fam.Count)
			}
			if fam.TotalLatencyNs != 600 {
				t.Fatalf("family %s TotalLatencyNs = %d, want 600", futexFamily, fam.TotalLatencyNs)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected family row for %s, got families: %+v", futexFamily, snap.Families())
	}
}

// findSyscallSnapshot locates a SyscallSnapshot by trace ID and fails the test
// if no matching row exists.
func findSyscallSnapshot(t *testing.T, rows []statsengine.SyscallSnapshot, id types.TraceId) statsengine.SyscallSnapshot {
	t.Helper()
	for _, row := range rows {
		if row.TraceID == id {
			return row
		}
	}
	t.Fatalf("no syscall snapshot row for trace ID %v", id)
	return statsengine.SyscallSnapshot{}
}
