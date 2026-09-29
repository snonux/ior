package internal

import (
	"context"
	"testing"
	"time"

	"ior/internal/globalfilter"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// The tests in this file cover how the aggregate drainer applies the runtime
// filter to kernel aggregate rows: per row on the dimensions a syscall-keyed
// row can answer (syscall name, family, kernel-enforced PID/TID), and as an
// all-or-nothing gate on every other dimension.

// aggregateFilterTestRows is one drain batch spanning three families:
// futex (aggregate-only by default), clock_gettime and read.
func aggregateFilterTestRows() []statsengine.SyscallAggregate {
	return []statsengine.SyscallAggregate{
		{TraceID: types.SYS_ENTER_FUTEX, Count: 4},
		{TraceID: types.SYS_ENTER_CLOCK_GETTIME, Count: 8},
		{TraceID: types.SYS_ENTER_READ, Count: 16},
	}
}

// tickWithFilter drains aggregateFilterTestRows once under filter and scope,
// with every row's trace ID designated for aggregate ingest, and returns the
// trace IDs that survived.
func tickWithFilter(t *testing.T, filter globalfilter.Filter, scope kernelProcessScope) []types.TraceId {
	t.Helper()
	rows := aggregateFilterTestRows()
	ids := make(map[types.TraceId]struct{}, len(rows))
	for _, row := range rows {
		ids[row.TraceID] = struct{}{}
	}
	drainer := newAggregateDrainer(
		&aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{rows}},
		ids,
		scope,
		func() globalfilter.Filter { return filter },
	)
	got := drainer.Tick()
	if got.warning != "" {
		t.Fatalf("warning = %q, want empty", got.warning)
	}
	kept := make([]types.TraceId, 0, len(got.rows))
	for _, row := range got.rows {
		kept = append(kept, row.TraceID)
	}
	return kept
}

func assertTraceIDs(t *testing.T, got []types.TraceId, want ...types.TraceId) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("kept trace IDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("kept trace IDs = %v, want %v", got, want)
		}
	}
}

func TestAggregateDrainerFamilyFilterKeepsOnlyMatchingFamily(t *testing.T) {
	// The three rows must belong to three distinct families, or the test
	// would not prove anything about exclusion.
	futexFamily := types.SYS_ENTER_FUTEX.Family()
	if futexFamily == types.SYS_ENTER_READ.Family() || futexFamily == types.SYS_ENTER_CLOCK_GETTIME.Family() {
		t.Fatalf("test rows share a family: futex=%s read=%s clock_gettime=%s", futexFamily,
			types.SYS_ENTER_READ.Family(), types.SYS_ENTER_CLOCK_GETTIME.Family())
	}

	fs := globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: string(types.SYS_ENTER_READ.Family())}}
	assertTraceIDs(t, tickWithFilter(t, fs, kernelProcessScope{}), types.SYS_ENTER_READ)

	futexOnly := globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "^" + string(futexFamily) + "$"}}
	assertTraceIDs(t, tickWithFilter(t, futexOnly, kernelProcessScope{}), types.SYS_ENTER_FUTEX)

	none := globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "no-such-family"}}
	assertTraceIDs(t, tickWithFilter(t, none, kernelProcessScope{}))
}

func TestAggregateDrainerSyscallFilterKeepsMatchingRows(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []types.TraceId
	}{
		{name: "substring", pattern: "futex", want: []types.TraceId{types.SYS_ENTER_FUTEX}},
		{name: "case insensitive", pattern: "CLOCK_", want: []types.TraceId{types.SYS_ENTER_CLOCK_GETTIME}},
		{name: "anchored exact", pattern: "^read$", want: []types.TraceId{types.SYS_ENTER_READ}},
		{name: "blank pattern matches all", pattern: "   ", want: []types.TraceId{
			types.SYS_ENTER_FUTEX, types.SYS_ENTER_CLOCK_GETTIME, types.SYS_ENTER_READ,
		}},
		{name: "no match", pattern: "no_such_syscall", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: tt.pattern}}
			assertTraceIDs(t, tickWithFilter(t, filter, kernelProcessScope{}), tt.want...)
		})
	}
}

func TestAggregateDrainerSyscallAndFamilyFiltersCombine(t *testing.T) {
	// Syscall matches futex, family excludes it: both dimensions must hold.
	filter := globalfilter.Filter{
		Syscall: &globalfilter.StringFilter{Pattern: "futex"},
		Family:  &globalfilter.StringFilter{Pattern: string(types.SYS_ENTER_READ.Family())},
	}
	assertTraceIDs(t, tickWithFilter(t, filter, kernelProcessScope{}))
}

func TestAggregateDrainerUnsupportedDimensionsGateOff(t *testing.T) {
	// Each case also sets a syscall filter that matches futex, so a gate
	// failure cannot hide behind the per-row syscall match.
	futex := &globalfilter.StringFilter{Pattern: "futex"}
	tests := []struct {
		name   string
		filter globalfilter.Filter
	}{
		{name: "errors only", filter: globalfilter.Filter{Syscall: futex, ErrorsOnly: true}},
		{name: "comm", filter: globalfilter.Filter{Syscall: futex, Comm: &globalfilter.StringFilter{Pattern: "x"}}},
		{name: "file", filter: globalfilter.Filter{Syscall: futex, File: &globalfilter.StringFilter{Pattern: "/tmp"}}},
		{name: "fd", filter: globalfilter.Filter{Syscall: futex, FD: globalfilter.NewEqFilter(3)}},
		{name: "latency", filter: globalfilter.Filter{Syscall: futex, LatencyNs: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1}}},
		{name: "gap", filter: globalfilter.Filter{Syscall: futex, GapNs: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1}}},
		{name: "bytes", filter: globalfilter.Filter{Syscall: futex, Bytes: &globalfilter.NumericFilter{Op: globalfilter.OpGt, Value: 1}}},
		{name: "retval", filter: globalfilter.Filter{Syscall: futex, RetVal: &globalfilter.NumericFilter{Op: globalfilter.OpLt, Value: 0}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTraceIDs(t, tickWithFilter(t, tt.filter, kernelProcessScope{}))
		})
	}
}

func TestAggregateDrainerPIDTIDFilterHonouredOnlyWhenKernelEnforced(t *testing.T) {
	all := []types.TraceId{types.SYS_ENTER_FUTEX, types.SYS_ENTER_CLOCK_GETTIME, types.SYS_ENTER_READ}
	tests := []struct {
		name   string
		filter globalfilter.Filter
		scope  kernelProcessScope
		want   []types.TraceId
	}{
		{name: "pid equals kernel pid", filter: globalfilter.Filter{PID: globalfilter.NewEqFilter(42)},
			scope: kernelProcessScope{pid: 42, tid: -1}, want: all},
		{name: "pid and tid equal kernel scope", filter: globalfilter.Filter{
			PID: globalfilter.NewEqFilter(42), TID: globalfilter.NewEqFilter(43)},
			scope: kernelProcessScope{pid: 42, tid: 43}, want: all},
		{name: "pid plus syscall filter", filter: globalfilter.Filter{
			PID: globalfilter.NewEqFilter(42), Syscall: &globalfilter.StringFilter{Pattern: "futex"}},
			scope: kernelProcessScope{pid: 42, tid: -1}, want: []types.TraceId{types.SYS_ENTER_FUTEX}},
		{name: "pid differs from kernel pid", filter: globalfilter.Filter{PID: globalfilter.NewEqFilter(7)},
			scope: kernelProcessScope{pid: 42, tid: -1}},
		{name: "pid without kernel scope", filter: globalfilter.Filter{PID: globalfilter.NewEqFilter(42)},
			scope: kernelProcessScope{pid: -1, tid: -1}},
		{name: "pid range is not enforced", filter: globalfilter.Filter{
			PID: &globalfilter.NumericFilter{Op: globalfilter.OpGte, Value: 42}},
			scope: kernelProcessScope{pid: 42, tid: -1}},
		{name: "tid differs from kernel tid", filter: globalfilter.Filter{
			PID: globalfilter.NewEqFilter(42), TID: globalfilter.NewEqFilter(99)},
			scope: kernelProcessScope{pid: 42, tid: 43}},
		{name: "tid without kernel scope", filter: globalfilter.Filter{TID: globalfilter.NewEqFilter(43)},
			scope: kernelProcessScope{pid: 42, tid: -1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTraceIDs(t, tickWithFilter(t, tt.filter, tt.scope), tt.want...)
		})
	}
}

// TestAggregateEndToEndSyscallFilterCountsAggregateOnlySyscall is the
// regression test for `-syscall futex` showing zero calls: an aggregate-only
// futex has no per-event pairs, so its count must come from the aggregate
// rows, which a syscall filter used to gate off entirely.
func TestAggregateEndToEndSyscallFilterCountsAggregateOnlySyscall(t *testing.T) {
	snap := drainIntoEngine(t, globalfilter.Filter{Syscall: &globalfilter.StringFilter{Pattern: "futex"}})
	if snap.TotalSyscalls != 4 {
		t.Fatalf("TotalSyscalls = %d, want 4 (futex aggregate count)", snap.TotalSyscalls)
	}
	if row := findSyscallSnapshot(t, snap.Syscalls(), types.SYS_ENTER_FUTEX); row.Count != 4 {
		t.Fatalf("futex Count = %d, want 4", row.Count)
	}
}

// TestAggregateEndToEndFamilyFilterExcludesOtherFamilies is the regression
// test for `-family` being ignored: rows of other families must not reach the
// engine totals the dashboard shows next to the family-filtered table.
func TestAggregateEndToEndFamilyFilterExcludesOtherFamilies(t *testing.T) {
	family := string(types.SYS_ENTER_READ.Family())
	snap := drainIntoEngine(t, globalfilter.Filter{Family: &globalfilter.StringFilter{Pattern: "^" + family + "$"}})
	if snap.TotalSyscalls != 16 {
		t.Fatalf("TotalSyscalls = %d, want 16 (only the %s row)", snap.TotalSyscalls, family)
	}
	for _, row := range snap.Syscalls() {
		if row.TraceID != types.SYS_ENTER_READ {
			t.Fatalf("unexpected row outside family %s: %+v", family, row)
		}
	}
}

// TestAggregateEndToEndPIDFilterUsesKernelScopeFromConfig covers the
// eventLoopConfig -> drainer wiring of the kernel PID/TID scope: a PID filter
// equal to cfg.pidFilter is kernel-enforced and ingests, a different PID
// cannot be answered by aggregate rows and gates ingestion off.
func TestAggregateEndToEndPIDFilterUsesKernelScopeFromConfig(t *testing.T) {
	scoped := func(cfg *eventLoopConfig) { cfg.pidFilter, cfg.tidFilter = 42, -1 }

	snap := drainIntoEngineWith(t, globalfilter.Filter{PID: globalfilter.NewEqFilter(42)}, scoped)
	if snap.TotalSyscalls != 28 {
		t.Fatalf("TotalSyscalls = %d, want 28 (all rows, PID enforced by the kernel)", snap.TotalSyscalls)
	}

	snap = drainIntoEngineWith(t, globalfilter.Filter{PID: globalfilter.NewEqFilter(7)}, scoped)
	if snap.TotalSyscalls != 0 {
		t.Fatalf("TotalSyscalls = %d, want 0 (PID 7 is not the kernel scope)", snap.TotalSyscalls)
	}
}

// drainIntoEngine runs one final-flush drain of aggregateFilterTestRows
// through a real event loop into a real statsengine under filter.
func drainIntoEngine(t *testing.T, filter globalfilter.Filter) *statsengine.Snapshot {
	t.Helper()
	return drainIntoEngineWith(t, filter, nil)
}

// drainIntoEngineWith is drainIntoEngine with a hook that adjusts the event
// loop config (e.g. the kernel PID/TID scope) before the loop starts.
func drainIntoEngineWith(t *testing.T, filter globalfilter.Filter, configure func(*eventLoopConfig)) *statsengine.Snapshot {
	t.Helper()
	engine := statsengine.NewEngine(statsengine.DefaultTopN)
	ids := map[types.TraceId]struct{}{}
	for _, row := range aggregateFilterTestRows() {
		ids[row.TraceID] = struct{}{}
	}
	cfg := eventLoopConfig{
		aggregateDrainEvery:     5 * time.Second,
		aggregateIngestTraceIDs: ids,
	}
	if configure != nil {
		configure(&cfg)
	}
	el := &eventLoop{
		cfg:           cfg,
		aggregateSrc:  &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{aggregateFilterTestRows()}},
		aggregateSink: engine,
	}
	el.SetFilter(filter)

	ctx, cancel := context.WithCancel(context.Background())
	stop := el.startAggregateDrainLoop(ctx)
	cancel()
	stop()

	snap, err := engine.Snapshot()
	if err != nil {
		t.Fatalf("snapshot error: %v", err)
	}
	return snap
}
