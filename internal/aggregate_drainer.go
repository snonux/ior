package internal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

type aggregateDrainResult struct {
	rows    []statsengine.SyscallAggregate
	warning string
}

type aggregateDrainer struct {
	source                syscallAggregateSource
	filter                func() globalfilter.Filter
	aggregateOnlyTraceIDs map[types.TraceId]struct{}
}

func newAggregateDrainer(
	source syscallAggregateSource,
	aggregateOnlyTraceIDs map[types.TraceId]struct{},
	filter func() globalfilter.Filter,
) *aggregateDrainer {
	return &aggregateDrainer{
		source:                source,
		filter:                filter,
		aggregateOnlyTraceIDs: aggregateOnlyTraceIDs,
	}
}

func (d *aggregateDrainer) Tick() aggregateDrainResult {
	if d == nil || d.source == nil {
		return aggregateDrainResult{}
	}
	rows, err := d.source.Drain()
	if err != nil {
		return aggregateDrainResult{warning: fmt.Sprintf("syscall aggregate drain failed: %v", err)}
	}
	rows = d.filterRowsForIngest(rows)
	if len(rows) == 0 {
		return aggregateDrainResult{}
	}
	return aggregateDrainResult{rows: rows}
}

func (d *aggregateDrainer) Start(ctx context.Context, every time.Duration, handle func(aggregateDrainResult)) func() {
	if d == nil || d.source == nil {
		return func() {}
	}

	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				handle(d.Tick())
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		handle(d.Tick())
	}
}

func (d *aggregateDrainer) filterRowsForIngest(rows []statsengine.SyscallAggregate) []statsengine.SyscallAggregate {
	if len(rows) == 0 {
		return nil
	}
	if !aggregateIngestAllowedForFilter(d.currentFilter()) {
		return nil
	}
	if len(d.aggregateOnlyTraceIDs) == 0 {
		return nil
	}

	filtered := make([]statsengine.SyscallAggregate, 0, len(rows))
	for _, row := range rows {
		if _, ok := d.aggregateOnlyTraceIDs[row.TraceID]; ok {
			filtered = append(filtered, row)
		}
	}
	return filtered
}

func (d *aggregateDrainer) currentFilter() globalfilter.Filter {
	if d == nil || d.filter == nil {
		return globalfilter.Filter{}
	}
	return d.filter()
}

func aggregateIngestAllowedForFilter(filter globalfilter.Filter) bool {
	if filter.ErrorsOnly {
		return false
	}
	if hasPattern(filter.Syscall) || hasPattern(filter.Comm) || hasPattern(filter.File) {
		return false
	}
	if filter.FD != nil || filter.LatencyNs != nil || filter.GapNs != nil || filter.Bytes != nil || filter.RetVal != nil {
		return false
	}
	if filter.PID != nil {
		return false
	}
	if filter.TID != nil {
		return false
	}
	return true
}

func hasPattern(filter *globalfilter.StringFilter) bool {
	return filter != nil && strings.TrimSpace(filter.Pattern) != ""
}
