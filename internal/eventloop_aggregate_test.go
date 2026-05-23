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
