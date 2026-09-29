package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

type aggregateDrainResult struct {
	rows    []statsengine.SyscallAggregate
	warning string
}

// kernelProcessScope is the PID/TID scope the BPF program enforces itself
// (the PID_FILTER/TID_FILTER globals, fixed at load time). A value <= 0 means
// the kernel does not restrict that dimension. The aggregate drainer needs it
// because kernel aggregate rows are keyed by syscall only: a runtime PID/TID
// filter can be honoured for them only when the kernel already applied it.
type kernelProcessScope struct {
	pid int
	tid int
}

type aggregateDrainer struct {
	source                  syscallAggregateSource
	filter                  func() globalfilter.Filter
	aggregateIngestTraceIDs map[types.TraceId]struct{}
	kernelScope             kernelProcessScope

	// mu serialises every drain-and-handle cycle (poll ticks, the final
	// drain, and the flush of SwapFilter), so a filter swap can never land
	// between one cycle's Drain and its ingest. It also guards handle,
	// source (once Start ran) and stopping.
	mu sync.Mutex
	// handle is the sink Start wired. It is nil before Start and after the
	// drainer retired; SwapFilter is then a plain swap that drains nothing.
	handle func(aggregateDrainResult)
	// stopping is set by the stop function Start returns; the next poll
	// cycle (normally the final drain) then retires the drainer under mu by
	// clearing handle and source. From then on no call drains: the BPF map
	// behind source may already be closed (infra.Close runs once the event
	// loop's run returns), and draining it would read a freed libbpf object.
	// A SwapFilter that loaded the drainer before it was unpublished and
	// waited on mu during the final drain thus finds it retired and only
	// swaps.
	stopping bool
}

func newAggregateDrainer(
	source syscallAggregateSource,
	aggregateIngestTraceIDs map[types.TraceId]struct{},
	kernelScope kernelProcessScope,
	filter func() globalfilter.Filter,
) *aggregateDrainer {
	return &aggregateDrainer{
		source:                  source,
		filter:                  filter,
		aggregateIngestTraceIDs: aggregateIngestTraceIDs,
		kernelScope:             kernelScope,
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
// interval is still ingested (see startPollLoop) and retires the drainer in the
// same locked cycle, so no later call can drain a closed source.
func (d *aggregateDrainer) Start(ctx context.Context, every time.Duration, handle func(aggregateDrainResult)) func() {
	if d == nil || d.source == nil {
		return func() {}
	}
	d.mu.Lock()
	d.handle = handle
	d.mu.Unlock()
	stopLoop := startPollLoop(ctx, every, d.pollCycle)
	return func() {
		d.mu.Lock()
		d.stopping = true
		d.mu.Unlock()
		stopLoop()
	}
}

// pollCycle is one poll-loop cycle: drain and handle under mu and, once stop
// was requested, retire the drainer in that same critical section. Normally
// that is startPollLoop's final drain; a ticker cycle racing the stop request
// may retire it first, which only moves the last drain a few microseconds
// earlier - the source is still open until stop returns.
func (d *aggregateDrainer) pollCycle() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.flushLocked()
	if d.stopping {
		d.handle = nil
		d.source = nil
	}
}

func (d *aggregateDrainer) flushLocked() {
	if d.handle != nil {
		d.handle(d.Tick())
	}
}

// SwapFilter drains the kernel aggregate map under the outgoing filter, hands
// the rows to the sink, and only then runs apply (which installs the new
// filter), all under mu. Without the flush, the map would still hold up to one
// drain interval of pre-swap invocations when the swap lands, and the first
// post-swap tick would ingest them into the baseline the TUI resets right
// after the swap (resetAggregatesAfterLiveSwap): e.g. `-syscall futex` showed
// up to ~2x its rate for the first interval. Flushing first attributes those
// counts to the pre-swap baseline, which is where they belong and which the
// reset then discards. What remains is the few-microsecond window between
// SwapFilter returning and the caller's stats reset: counts drained there go
// to the old baseline and are dropped by the reset (an undercount of that
// window, never a pre-swap count in the new baseline). Once the drainer
// retired (see pollCycle), SwapFilter drains nothing and only runs apply.
func (d *aggregateDrainer) SwapFilter(apply func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.flushLocked()
	apply()
}

// filterRowsForIngest keeps only the aggregate rows the stats engine may
// merge. The kernel aggregates exactly the events it does not emit (see
// ior_on_syscall_exit in internal/c/filter.c), so ingesting rows for both
// aggregate-only (rate 0) and sampled (rate N>1) syscalls yields their true
// invocation counts with no double counting against the per-event path. Rows
// for fully traced (rate 1) syscalls are dropped: the kernel writes none, and
// dropping any that appear keeps a version-skewed BPF object under-reporting
// rather than double-counting.
//
// The active runtime filter is then applied per row on the dimensions a
// syscall-keyed aggregate row can answer (syscall name and family), so
// `-syscall futex` still counts an aggregate-only futex and `-family FS` keeps
// other families' aggregate rows out of the dashboard totals. A filter on any
// dimension a row cannot answer gates ingestion off entirely (see
// aggregateIngestAllowedForFilter).
func (d *aggregateDrainer) filterRowsForIngest(rows []statsengine.SyscallAggregate) []statsengine.SyscallAggregate {
	if len(rows) == 0 || len(d.aggregateIngestTraceIDs) == 0 {
		return nil
	}
	filter := d.currentFilter()
	if !aggregateIngestAllowedForFilter(&filter, d.kernelScope) {
		return nil
	}

	filtered := make([]statsengine.SyscallAggregate, 0, len(rows))
	for _, row := range rows {
		if _, ok := d.aggregateIngestTraceIDs[row.TraceID]; !ok {
			continue
		}
		if filter.MatchesSyscallRow(row.TraceID.Name(), string(row.TraceID.Family())) {
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

// aggregateIngestAllowedForFilter reports whether kernel aggregate rows can be
// ingested at all under filter. A row carries only a syscall trace ID plus
// counts/errors/latency sums, so it can be matched per row on Syscall and
// Family (done by the caller) but not on comm, file, fd, latency, gap, bytes,
// return value or errors-only: with any of those set, ingesting the row would
// count invocations the filter excludes, so ingestion is gated off (the
// all-or-nothing fallback: aggregate-only syscalls disappear and sampled ones
// show their 1-in-N emitted counts until the filter is cleared). PID and TID
// pass only when unset or equal to the PID_FILTER/TID_FILTER scope the kernel
// already enforced (scope, see kernelEnforces); any other PID/TID constraint
// gates ingestion off too.
func aggregateIngestAllowedForFilter(filter *globalfilter.Filter, scope kernelProcessScope) bool {
	if filter.ErrorsOnly {
		return false
	}
	if hasPattern(filter.Comm) || hasPattern(filter.File) {
		return false
	}
	if filter.FD != nil || filter.LatencyNs != nil || filter.GapNs != nil || filter.Bytes != nil || filter.RetVal != nil {
		return false
	}
	return kernelEnforces(filter.PID, scope.pid) && kernelEnforces(filter.TID, scope.tid)
}

// kernelEnforces reports whether a PID/TID filter dimension is already
// satisfied by every aggregate row: either the dimension is unset, or it is
// exactly the equality the BPF program enforces via PID_FILTER/TID_FILTER, so
// the kernel never aggregated an out-of-scope invocation. Any other constraint
// (a different ID, a range, a runtime-only filter) cannot be answered by a
// syscall-keyed row.
func kernelEnforces(nf *globalfilter.NumericFilter, kernelID int) bool {
	if nf == nil {
		return true
	}
	id, ok := nf.EqValue()
	return ok && kernelID > 0 && id == int64(kernelID)
}

func hasPattern(filter *globalfilter.StringFilter) bool {
	return filter != nil && strings.TrimSpace(filter.Pattern) != ""
}
