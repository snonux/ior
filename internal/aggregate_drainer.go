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
	source                  syscallAggregateSource
	filter                  func() globalfilter.Filter
	aggregateIngestTraceIDs map[types.TraceId]struct{}
}

func newAggregateDrainer(
	source syscallAggregateSource,
	aggregateIngestTraceIDs map[types.TraceId]struct{},
	filter func() globalfilter.Filter,
) *aggregateDrainer {
	return &aggregateDrainer{
		source:                  source,
		filter:                  filter,
		aggregateIngestTraceIDs: aggregateIngestTraceIDs,
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

// Start polls the aggregate map every `every` until ctx is cancelled or the
// returned stop function runs; stop performs a final drain so the last partial
// interval is still ingested (see startPollLoop).
func (d *aggregateDrainer) Start(ctx context.Context, every time.Duration, handle func(aggregateDrainResult)) func() {
	if d == nil || d.source == nil {
		return func() {}
	}
	return startPollLoop(ctx, every, func() { handle(d.Tick()) })
}

// filterRowsForIngest keeps only the aggregate rows the stats engine may
// merge. The kernel aggregates exactly the events it does not emit (see
// ior_on_syscall_exit in internal/c/filter.c), so ingesting rows for both
// aggregate-only (rate 0) and sampled (rate N>1) syscalls yields their true
// invocation counts with no double counting against the per-event path. Rows
// for fully traced (rate 1) syscalls are dropped: the kernel writes none, and
// dropping any that appear keeps a version-skewed BPF object under-reporting
// rather than double-counting.
func (d *aggregateDrainer) filterRowsForIngest(rows []statsengine.SyscallAggregate) []statsengine.SyscallAggregate {
	if len(rows) == 0 {
		return nil
	}
	if !aggregateIngestAllowedForFilter(d.currentFilter()) {
		return nil
	}
	if len(d.aggregateIngestTraceIDs) == 0 {
		return nil
	}

	filtered := make([]statsengine.SyscallAggregate, 0, len(rows))
	for _, row := range rows {
		if _, ok := d.aggregateIngestTraceIDs[row.TraceID]; ok {
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
