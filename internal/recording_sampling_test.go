package internal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/sampling"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// The TUI's sampled-syscall list holds the built-in aggregate-only syscalls
// (futex*, clock_gettime at rate 0): whenever their probes are attached they
// have no row in a TUI recording, and the recording's rates must say so. With
// the default -trace-families (FS only) they are not attached, and
// sampling.Tally.Plan leaves them out (a default recording is unmarked).
func TestTUISampledSyscallsIncludeTheAggregateOnlyDefaults(t *testing.T) {
	entries := tuiSampledSyscalls(mustParseArgs(t))
	got := make(map[string]uint32, len(entries))
	for _, e := range entries {
		got[e.Syscall] = e.Rate
	}
	for _, name := range []string{"futex", "futex_wait", "futex_wake", "futex_requeue", "futex_waitv", "clock_gettime"} {
		if rate, ok := got[name]; !ok || rate != 0 {
			t.Fatalf("%s: rate %d, present %v; want aggregate-only (0) in %+v", name, rate, ok, entries)
		}
	}
	if len(got) != 6 {
		t.Fatalf("sampled syscalls = %+v, want only the six defaults", entries)
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].Syscall >= entries[i].Syscall {
			t.Fatalf("entries not sorted by name: %+v", entries)
		}
	}
}

// Family rates are attributed, so the footer names a family once, and an
// explicit per-syscall rate overrides both the family and the defaults.
func TestTUISampledSyscallsCarryFamilyAndExplicitRates(t *testing.T) {
	cfg := mustParseArgs(t, "-syscall-sampling-families", "FS=10", "-syscall-sampling-syscalls", "read=3,futex=1")
	byName := make(map[string]sampling.Entry)
	for _, e := range tuiSampledSyscalls(cfg) {
		byName[e.Syscall] = e
	}
	if e := byName["openat"]; e.Rate != 10 || e.Family != "FS" {
		t.Fatalf("openat = %+v, want rate 10 of family FS", e)
	}
	if e := byName["read"]; e.Rate != 3 || e.Family != "" {
		t.Fatalf("read = %+v, want its own rate 3", e)
	}
	if _, ok := byName["futex"]; ok {
		t.Fatal("futex=1 traces futex in full; it must not be listed as sampled")
	}
	if got := sampling.New(tuiSampledSyscalls(cfg), "").Rates(); got != "FS=10,clock_gettime=0,futex_requeue=0,futex_wait=0,futex_waitv=0,futex_wake=0,read=3" {
		t.Fatalf("Rates() = %q", got)
	}
}

// Without any rate other than 1 there is nothing to mark.
func TestTUISampledSyscallsOfAnUnsampledTraceIsNil(t *testing.T) {
	cfg := mustParseArgs(t, "-syscall-sampling-syscalls", "futex=1,futex_wait=1,futex_wake=1,futex_requeue=1,futex_waitv=1,clock_gettime=1")
	if got := tuiSampledSyscalls(cfg); got != nil {
		t.Fatalf("tuiSampledSyscalls() = %+v, want nil", got)
	}
}

// samplingRecordingBindings are fake TUI bindings with a real recorder that
// take the session's RecordingSampling, like the TUI's session view does.
type samplingRecordingBindings struct {
	*fakeRuntimeBindings
	recorder  *parquet.Recorder
	published runtime.RecordingSampling
}

func (b *samplingRecordingBindings) Recorder() runtime.RecordingController { return b.recorder }
func (b *samplingRecordingBindings) SetRecordingSampling(source runtime.RecordingSampling) {
	b.published = source
}

// tuiRecordingHarness is a TUI trace session as the R key sees it, end to end
// through the TUI configurer, the aggregate drainer, the drop monitor and a
// real recorder: both poll loops run with an hour's period, so only the flushes
// of the recording edges read the stub sources.
type tuiRecordingHarness struct {
	bindings *samplingRecordingBindings
	el       *eventLoop
}

func newTUIRecordingHarness(t *testing.T, cfg flags.Config, source syscallAggregateSource, drops ringbufDropSource) *tuiRecordingHarness {
	t.Helper()
	bindings := &samplingRecordingBindings{
		fakeRuntimeBindings: &fakeRuntimeBindings{sink: &fakeEventSink{}, seq: &fakeSequencer{}},
		recorder:            parquet.NewRecorder(parquet.RecorderConfig{}),
	}
	rt, err := buildTUIRuntime(cfg, bindings)
	if err != nil {
		t.Fatalf("buildTUIRuntime: %v", err)
	}
	configure, unregister := makeTUIEventLoopConfigurer(cfg, rt, bindings)
	t.Cleanup(unregister)
	el := &eventLoop{
		cfg:          eventLoopConfig{aggregateDrainEvery: time.Hour, aggregateIngestTraceIDs: buildAggregateIngestTraceIDs(cfg)},
		aggregateSrc: source,
		dropSrc:      drops,
	}
	el.SetWarningCallback(func(string) {})
	configure(el)
	t.Cleanup(el.startAggregateDrainLoop(context.Background()))
	t.Cleanup(el.startRingbufDropMonitor(context.Background()))
	if bindings.published == nil {
		t.Fatal("the configurer published no RecordingSampling")
	}
	return &tuiRecordingHarness{bindings: bindings, el: el}
}

// record does what the TUI's recorderStart and recorderStop do around during:
// flush the counters, start with a fresh tally, ..., flush again, stop. It
// returns the file and what the start flush reported.
func (h *tuiRecordingHarness) record(t *testing.T, during func()) (path string, startComplete bool) {
	t.Helper()
	published := h.bindings.published
	tally := sampling.NewTally(published.SampledSyscalls(), nil)
	startComplete = published.FlushCounters()
	path = filepath.Join(t.TempDir(), "rec.parquet")
	if err := h.bindings.recorder.Start(path, parquet.StartOptions{
		Metadata: parquet.FileMetadata{Mode: "tui", Sampling: tally.Plan()}, SamplingTally: tally,
	}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	during()
	published.FlushCounters()
	if err := h.bindings.recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return path, startComplete
}

// A recording's footer carries the rates and exactly its own window - the rows
// recorded while it ran plus the kernel counts drained while it ran - with the
// counts of before the start flushed to no recording.
func TestTUIRecordingGetsTheTotalsOfItsOwnWindow(t *testing.T) {
	source := &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_OPENAT, Count: 100}, {TraceID: types.SYS_ENTER_FUTEX, Count: 7}}, // before the recording
		{{TraceID: types.SYS_ENTER_OPENAT, Count: 40}},                                              // during it
	}}
	h := newTUIRecordingHarness(t, mustParseArgs(t, "-syscall-sampling-syscalls", "openat=5"), source, nil)
	path, _ := h.record(t, func() {
		h.el.printCb(testTracePair(1, "a"))
		h.el.printCb(testTracePair(2, "b"))
	})
	if got, _ := parquetFooter(t, path, parquet.KeySampling); got != "clock_gettime=0,futex=0,futex_requeue=0,futex_wait=0,futex_waitv=0,futex_wake=0,openat=5" {
		t.Fatalf("%s = %q", parquet.KeySampling, got)
	}
	want := `[{"syscall":"openat","rate":5,"traced":2,"counted_only":40,"total":42}]`
	if got, _ := parquetFooter(t, path, parquet.KeySamplingTotals); got != want {
		t.Fatalf("%s = %s\nwant %s", parquet.KeySamplingTotals, got, want)
	}
}

// Ring-buffer drops are read at the recording edges too (the drop monitor
// polls only once a second): drops of the last moments before the stop make
// the totals a lower bound before the footer is written, and drops of before
// the start are consumed by the start flush and do not mark the recording.
func TestTUIRecordingDropsAreReadAtItsEdges(t *testing.T) {
	cfg := mustParseArgs(t, "-syscall-sampling-syscalls", "openat=5")
	for _, tc := range []struct {
		name   string
		totals []uint64 // the drop counter at the start flush, then at the stop flush
		want   string
	}{
		{"drops before the start", []uint64{5, 5}, `[{"syscall":"openat","rate":5,"traced":1,"counted_only":0,"total":1}]`},
		{"drops before the stop", []uint64{5, 8}, `[{"syscall":"openat","rate":5,"traced":1,"counted_only":0,"total":1,"lower_bound":true}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTUIRecordingHarness(t, cfg, &aggregateSourceStub{}, &ringbufDropSourceStub{totals: tc.totals})
			path, _ := h.record(t, func() { h.el.printCb(testTracePair(1, "a")) })
			if got, _ := parquetFooter(t, path, parquet.KeySamplingTotals); got != tc.want {
				t.Fatalf("totals = %s\nwant %s", got, tc.want)
			}
		})
	}
}

// A drain that fails at the start flush reaches no recording through the trace
// core, so FlushCounters must report it (the TUI then marks the new recording
// unavailable: the deltas the drain did not reach would leak into the window).
func TestTUIRecordingStartFlushReportsAFailedDrain(t *testing.T) {
	cfg := mustParseArgs(t, "-syscall-sampling-syscalls", "openat=5")
	h := newTUIRecordingHarness(t, cfg, &aggregateSourceStub{err: errors.New("map gone")}, nil)
	if _, complete := h.record(t, func() {}); complete {
		t.Fatal("FlushCounters reported a failed drain as complete")
	}
	h = newTUIRecordingHarness(t, cfg, &aggregateSourceStub{}, nil)
	if _, complete := h.record(t, func() {}); !complete {
		t.Fatal("FlushCounters reported a successful drain as failed")
	}
}

// samplingCounterStub records what the event loop reports to a recording.
type samplingCounterStub struct {
	counts      map[string]uint64
	lowerBound  int
	unavailable []string
}

func (s *samplingCounterStub) CountKernelOnly(syscall string, n uint64) {
	if s.counts == nil {
		s.counts = make(map[string]uint64)
	}
	s.counts[syscall] += n
}
func (s *samplingCounterStub) MarkSamplingLowerBound() { s.lowerBound++ }
func (s *samplingCounterStub) MarkSamplingUnavailable(reason string) {
	s.unavailable = append(s.unavailable, reason)
}

func TestDrainResultsReachTheRecording(t *testing.T) {
	counter := &samplingCounterStub{}
	el := &eventLoop{aggregateSink: &aggregateSinkStub{}}
	el.SetRecordingSamplingCounter(counter)

	el.handleAggregateDrainResult(aggregateDrainResult{rows: []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 9}}})
	if counter.counts["futex"] != 9 || len(counter.unavailable) != 0 {
		t.Fatalf("counter = %+v, want futex=9 and nothing unavailable", counter)
	}
	el.handleAggregateDrainResult(aggregateDrainResult{withheld: withheldByFilter})
	el.handleAggregateDrainResult(aggregateDrainResult{warning: "boom"})
	if len(counter.unavailable) != 2 || counter.unavailable[0] != withheldByFilter || counter.unavailable[1] != "reading the kernel counters failed" {
		t.Fatalf("unavailable = %q, want the filter reason then the drain failure", counter.unavailable)
	}
}

func TestRingbufLossMakesTheRecordingALowerBound(t *testing.T) {
	counter := &samplingCounterStub{}
	el := &eventLoop{}
	el.SetRecordingSamplingCounter(counter)
	el.SetWarningCallback(func(string) {})

	el.handleRingbufDropResult(ringbufDropResult{total: 0, delta: 0})
	if counter.lowerBound != 0 {
		t.Fatal("a poll without loss marked the recording a lower bound")
	}
	el.handleRingbufDropResult(ringbufDropResult{total: 3, delta: 3})
	el.handleRingbufDropResult(ringbufDropResult{warning: "cannot read the drop counter"})
	if counter.lowerBound != 2 {
		t.Fatalf("lower-bound marks = %d, want 2 (a loss and an unreadable counter)", counter.lowerBound)
	}
}

// The raw modes have no recording counter: forwarding is a no-op there and the
// raw tally keeps its own bookkeeping.
func TestRawModeLoopForwardsNothing(t *testing.T) {
	el := &eventLoop{aggregateSink: &aggregateSinkStub{}}
	el.handleAggregateDrainResult(aggregateDrainResult{rows: []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 1}}})
	el.markRecordingLowerBound()
}

// A filter the kernel counters cannot honour withholds drained counts; the
// drain result must name that, but only when counts were actually withheld.
func TestAggregateDrainerReportsCountsWithheldByTheFilter(t *testing.T) {
	ids := map[types.TraceId]struct{}{types.SYS_ENTER_FUTEX: {}}
	commFilter := globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "x"}}
	for _, tc := range []struct {
		name   string
		filter globalfilter.Filter
		rows   []statsengine.SyscallAggregate
		want   string
	}{
		{"no filter", globalfilter.Filter{}, []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2}}, ""},
		{"comm filter withholds", commFilter, []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX, Count: 2}}, withheldByFilter},
		{"comm filter, nothing counted", commFilter, []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_FUTEX}}, ""},
		{"comm filter, not ingestible", commFilter, []statsengine.SyscallAggregate{{TraceID: types.SYS_ENTER_READ, Count: 2}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filter := tc.filter
			drainer := newAggregateDrainer(&aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{tc.rows}}, ids,
				kernelProcessScope{}, func() globalfilter.Filter { return filter })
			if got := drainer.Tick(); got.withheld != tc.want {
				t.Fatalf("withheld = %q, want %q", got.withheld, tc.want)
			}
		})
	}
}

// Flush drains into the sink while the drain loop runs, does nothing before it
// started, and never touches the source once the final drain retired it.
func TestAggregateDrainerFlushStopsOnceRetired(t *testing.T) {
	source := &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_FUTEX, Count: 1}},
		{{TraceID: types.SYS_ENTER_FUTEX, Count: 2}},
	}}
	sink := &aggregateSinkStub{}
	el := &eventLoop{
		cfg:           eventLoopConfig{aggregateDrainEvery: time.Hour, aggregateIngestTraceIDs: map[types.TraceId]struct{}{types.SYS_ENTER_FUTEX: {}}},
		aggregateSrc:  source,
		aggregateSink: sink,
	}
	el.SetFilter(globalfilter.Filter{})
	el.flushRecordingCounters() // no drain loop yet: nothing
	stop := el.startAggregateDrainLoop(context.Background())
	el.flushRecordingCounters()
	sink.mu.Lock()
	if len(sink.rows) != 1 || sink.rows[0].Count != 1 {
		t.Fatalf("after a flush the sink has %+v, want the first batch", sink.rows)
	}
	sink.mu.Unlock()
	stop() // the final drain takes the second batch and retires the drainer
	el.flushRecordingCounters()
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.rows) != 0 {
		t.Fatalf("source still holds %d batches, want the final drain to have taken them", len(source.rows))
	}
}

// The drop monitor is flushable like the drainer: a flush reads the counter
// while the monitor runs, and none reads it once the final read retired it
// (the drop map may be closed by then), not even through a pointer loaded
// before the stop unpublished it.
func TestRingbufDropMonitorFlushStopsOnceRetired(t *testing.T) {
	source := &ringbufDropSourceStub{totals: []uint64{2}}
	counter := &samplingCounterStub{}
	el := &eventLoop{cfg: eventLoopConfig{aggregateDrainEvery: time.Hour}, dropSrc: source}
	el.SetRecordingSamplingCounter(counter)
	el.SetWarningCallback(func(string) {})
	el.flushRecordingCounters() // no monitor yet: nothing
	stop := el.startRingbufDropMonitor(context.Background())
	el.flushRecordingCounters()
	if counter.lowerBound != 1 {
		t.Fatalf("lower-bound marks after a flush = %d, want 1 (2 drops)", counter.lowerBound)
	}
	monitor := el.dropMonitor.Load() // a flush that loaded it before the stop
	stop()                           // the final read retires the monitor
	el.flushRecordingCounters()
	monitor.Flush()
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.callCnt != 2 {
		t.Fatalf("drop counter read %d times, want 2 (the flush and the final read)", source.callCnt)
	}
}
