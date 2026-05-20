package internal

import (
	"context"
	"sync"
	"testing"
	"time"

	"ior/internal/statsengine"
	"ior/internal/types"
)

type aggregateSourceStub struct {
	mu   sync.Mutex
	rows [][]statsengine.SyscallAggregate
}

func (s *aggregateSourceStub) Drain() ([]statsengine.SyscallAggregate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func TestStartAggregateDrainLoopIngestsRows(t *testing.T) {
	src := &aggregateSourceStub{
		rows: [][]statsengine.SyscallAggregate{
			{{TraceID: types.SYS_ENTER_FUTEX, Count: 2}},
		},
	}
	sink := &aggregateSinkStub{}
	el := &eventLoop{
		cfg:           eventLoopConfig{aggregateDrainEvery: 2 * time.Millisecond},
		aggregateSrc:  src,
		aggregateSink: sink,
	}

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		done := len(sink.rows) > 0
		sink.mu.Unlock()
		if done {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	stop()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.rows) == 0 {
		t.Fatal("expected drained aggregate rows")
	}
	if sink.rows[0].TraceID != types.SYS_ENTER_FUTEX || sink.rows[0].Count != 2 {
		t.Fatalf("drained row = %+v, want futex count=2", sink.rows[0])
	}
}
