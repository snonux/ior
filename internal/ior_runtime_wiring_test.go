package internal

import (
	"context"
	"strings"
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/parquet"
	"ior/internal/runtime"
	"ior/internal/statsengine"
	"ior/internal/streamrow"
)

// The runtime contract is interface-typed (audit task a2) so the core's
// wiring depends on behaviour, not on the concrete streamrow/parquet types.
// These tests pin that property by wiring a tuiRuntime against fakes: before
// the interfaces, wireRuntimeBindings could only be exercised with a real
// *streamrow.RingBuffer (it type-asserted the sink) and the recorder seam
// was the concrete *parquet.Recorder, so a fake was impossible.

// fakeEventSink is a stream buffer that is not a *streamrow.RingBuffer.
type fakeEventSink struct {
	rows []streamrow.Row
}

func (f *fakeEventSink) Len() int                  { return len(f.rows) }
func (f *fakeEventSink) Snapshot() []streamrow.Row { return f.rows }
func (f *fakeEventSink) Push(row streamrow.Row)    { f.rows = append(f.rows, row) }

// fakeRowRecorder is a recorder that is not a *parquet.Recorder: a full
// RecordingController built from test doubles, proving the controller
// surface carries no concrete-type requirement either.
type fakeRowRecorder struct {
	rows   []streamrow.Row
	epoch  uint64
	active bool
}

func (f *fakeRowRecorder) Record(row streamrow.Row, filterEpoch uint64) error {
	f.rows = append(f.rows, row)
	f.epoch = filterEpoch
	return nil
}

func (f *fakeRowRecorder) TakeFailure() error { return nil }

func (f *fakeRowRecorder) Start(path string, _ parquet.StartOptions) error {
	f.active = strings.HasPrefix(path, "/")
	return nil
}

func (f *fakeRowRecorder) Stop() error {
	f.active = false
	return nil
}

func (f *fakeRowRecorder) Status() parquet.Status {
	return parquet.Status{Active: f.active}
}

// fakeSequencer is a sequencer that is not a *streamrow.Sequencer.
type fakeSequencer struct {
	next uint64
}

func (f *fakeSequencer) Next() uint64 {
	f.next++
	return f.next
}

// fakeRuntimeBindings implements the full TraceRuntimeBindings contract with
// the fakes above, so the compiler itself proves the contract carries no
// concrete-type requirement.
type fakeRuntimeBindings struct {
	sink  *fakeEventSink
	rec   *fakeRowRecorder
	seq   *fakeSequencer
	epoch uint64

	publishedStreamSource runtime.StreamSource
	publishedSnapshotSrc  runtime.ResettableSnapshotSource
	liveFilterSetters     int
}

func (b *fakeRuntimeBindings) StreamBuffer() runtime.EventSink {
	if b.sink == nil {
		return nil
	}
	return b.sink
}
func (b *fakeRuntimeBindings) Recorder() runtime.RecordingController {
	if b.rec == nil {
		return nil
	}
	return b.rec
}
func (b *fakeRuntimeBindings) StreamSequencer() runtime.Sequencer {
	if b.seq == nil {
		return nil
	}
	return b.seq
}
func (b *fakeRuntimeBindings) FilterEpoch() uint64 { return b.epoch }

func (b *fakeRuntimeBindings) SetDashboardSnapshotSource(source runtime.ResettableSnapshotSource) {
	b.publishedSnapshotSrc = source
}
func (b *fakeRuntimeBindings) SetEventStreamSource(source runtime.StreamSource) {
	b.publishedStreamSource = source
}
func (b *fakeRuntimeBindings) SetLiveTrie(runtime.LiveTrieSource)   {}
func (b *fakeRuntimeBindings) SetProbeManager(runtime.ProbeManager) {}
func (b *fakeRuntimeBindings) SetLiveFilterSetter(func(globalfilter.Filter)) func() {
	b.liveFilterSetters++
	return func() {}
}

// Compile-time proof that the fake satisfies the whole contract.
var _ runtime.TraceRuntimeBindings = (*fakeRuntimeBindings)(nil)

// TestWireRuntimeBindingsAcceptsFakes drives wireRuntimeBindings with a
// bindings implementation backed entirely by test doubles and asserts the
// core runtime ends up wired to them: the sink without a downcast, the
// sequencer and the row recorder without a concrete type in sight.
func TestWireRuntimeBindingsAcceptsFakes(t *testing.T) {
	bindings := &fakeRuntimeBindings{
		sink:  &fakeEventSink{},
		rec:   &fakeRowRecorder{},
		seq:   &fakeSequencer{},
		epoch: 7,
	}
	rt := &tuiRuntime{snapSource: fakeSnapshotSource{}}

	if err := wireRuntimeBindings(rt, bindings); err != nil {
		t.Fatalf("wireRuntimeBindings: %v", err)
	}

	// The sink, sequencer and recorder the core uses are exactly the fakes.
	if rt.streamBuf != runtime.EventSink(bindings.sink) {
		t.Fatal("the wired stream sink must be the bindings' EventSink, no downcast")
	}
	if rt.streamSeq != runtime.Sequencer(bindings.seq) {
		t.Fatal("the wired sequencer must be the bindings' Sequencer")
	}
	// The recorder the core records rows through is the fake controller,
	// narrowed to the RowRecorder seam.
	if rt.recorder != runtime.RowRecorder(bindings.rec) {
		t.Fatal("the wired recorder must be the bindings' RecordingController, narrowed to RowRecorder")
	}
	if got := rt.currentFilterEpoch(); got != 7 {
		t.Fatalf("filter epoch = %d, want 7", got)
	}

	// Pushes and sequencing flow through the fakes.
	rt.streamBuf.Push(streamrow.Row{Syscall: "read", PID: 1})
	if got := bindings.sink.Len(); got != 1 {
		t.Fatalf("fake sink len = %d, want 1", got)
	}
	if got := rt.streamSeq.Next(); got != 1 {
		t.Fatalf("fake sequencer first Next = %d, want 1", got)
	}

	// Row recording flows through the fake with the live filter epoch.
	if err := rt.recorder.Record(streamrow.Row{Syscall: "write", PID: 2}, rt.currentFilterEpoch()); err != nil {
		t.Fatalf("record through the wired fake: %v", err)
	}
	if len(bindings.rec.rows) != 1 || bindings.rec.epoch != 7 {
		t.Fatalf("fake recorder saw %d rows at epoch %d, want 1 row at epoch 7",
			len(bindings.rec.rows), bindings.rec.epoch)
	}

	// The publisher side republishes the core's sources to the bindings.
	if bindings.publishedStreamSource != runtime.StreamSource(bindings.sink) {
		t.Fatal("the published stream source must be the reused persistent sink")
	}
	if bindings.publishedSnapshotSrc == nil {
		t.Fatal("the snapshot source must be published to the bindings")
	}
}

// TestWireRuntimeBindingsNilOptionalComponents pins the absent-state path:
// a bindings set without a sink or sequencer leaves the freshly built
// components in place instead of nil-ing the wiring.
func TestWireRuntimeBindingsNilOptionalComponents(t *testing.T) {
	freshBuffer := &fakeEventSink{}
	freshSeq := &fakeSequencer{}
	rt := &tuiRuntime{
		streamBuf: freshBuffer,
		streamSrc: freshBuffer,
		streamSeq: freshSeq,
	}

	bindings := &fakeRuntimeBindings{sink: nil, seq: nil, rec: nil}
	if err := wireRuntimeBindings(rt, bindings); err != nil {
		t.Fatalf("wireRuntimeBindings: %v", err)
	}
	if rt.recorder != nil {
		t.Fatal("a nil RecordingController must wire as a nil RowRecorder, not a typed nil")
	}

	if rt.streamBuf != runtime.EventSink(freshBuffer) {
		t.Fatal("a nil persistent sink must keep the fresh stream buffer wired")
	}
	if rt.streamSeq != runtime.Sequencer(freshSeq) {
		t.Fatal("a nil persistent sequencer must keep the fresh sequencer wired")
	}
}

// fakeSnapshotSource is a minimal ResettableSnapshotSource so the wiring test
// does not depend on a live stats engine.
type fakeSnapshotSource struct{}

func (fakeSnapshotSource) Snapshot() (*statsengine.Snapshot, error) {
	return nil, nil
}

func (fakeSnapshotSource) Reset() {}

// capturedTraceRun records what the TUI trace starter handed its trace run,
// standing in for runTraceWithContext so the explicit request-to-setup path
// can be checked without BPF.
type capturedTraceRun struct {
	cfg   flags.Config
	hooks traceSetupHooks
}

func captureTraceRun(runs chan<- capturedTraceRun) traceRunFunc {
	return func(_ context.Context, cfg flags.Config, started chan<- struct{}, configure func(*eventLoop), hooks traceSetupHooks) error {
		configure(&eventLoop{})
		runs <- capturedTraceRun{cfg: cfg, hooks: hooks}
		close(started)
		return nil
	}
}

// TestTuiTraceStarterHandsRequestBindingsDownToSetup pins that the request's
// bindings and shutdown reporter reach trace setup explicitly - the probe
// manager publisher and the shutdown progress sink - and that the same
// bindings wire the session runtime and its live filter setter. These used to
// be fished out of the context at each layer, where a lost value silently
// meant "no TUI".
func TestTuiTraceStarterHandsRequestBindingsDownToSetup(t *testing.T) {
	runs := make(chan capturedTraceRun, 1)
	starter := tuiTraceStarterFromRunTrace(flags.NewFlags(), captureTraceRun(runs))
	bindings := &fakeRuntimeBindings{sink: &fakeEventSink{}, seq: &fakeSequencer{}}
	reporter := runtime.NewTraceShutdownReporter()

	req := runtime.TraceRequest{Bindings: bindings, ShutdownReporter: reporter}
	if err := starter(context.Background(), req); err != nil {
		t.Fatalf("starter() error = %v", err)
	}
	run := <-runs

	if run.hooks.probes != probeManagerPublisher(bindings) {
		t.Fatalf("setup probe publisher = %v, want the request's bindings", run.hooks.probes)
	}
	if run.hooks.shutdown != reporter {
		t.Fatal("setup shutdown reporter is not the request's reporter")
	}
	if bindings.publishedStreamSource != runtime.StreamSource(bindings.sink) {
		t.Fatal("the session runtime was not wired to the request's bindings")
	}
	if bindings.liveFilterSetters != 1 {
		t.Fatalf("live filter setters registered = %d, want 1 through the request's bindings", bindings.liveFilterSetters)
	}
}

// TestTuiTraceStarterZeroRequestRunsWithoutTUI is the negative case: a zero
// request (no bindings, no filter, no reporter) must reach setup as the
// headless zero hooks - a true nil publisher, not a typed nil that setup
// would call - and keep the starter's configured filter and PID/TID scope.
func TestTuiTraceStarterZeroRequestRunsWithoutTUI(t *testing.T) {
	base := flags.NewFlags()
	base.PidFilter = 11
	base.TidFilter = 12
	base.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "base"}}
	runs := make(chan capturedTraceRun, 1)
	starter := tuiTraceStarterFromRunTrace(base, captureTraceRun(runs))

	if err := starter(context.Background(), runtime.TraceRequest{}); err != nil {
		t.Fatalf("starter() error = %v", err)
	}
	run := <-runs

	if run.hooks.probes != nil {
		t.Fatalf("setup probe publisher = %#v, want nil without bindings", run.hooks.probes)
	}
	if run.hooks.shutdown != nil {
		t.Fatal("setup got a shutdown reporter the request never carried")
	}
	if run.cfg.PidFilter != 11 || run.cfg.TidFilter != 12 {
		t.Fatalf("scope = pid %d tid %d, want the configured 11/12 kept without a request filter",
			run.cfg.PidFilter, run.cfg.TidFilter)
	}
	if run.cfg.GlobalFilter.Comm == nil || run.cfg.GlobalFilter.Comm.Pattern != "base" {
		t.Fatalf("global filter = %+v, want the configured filter kept", run.cfg.GlobalFilter)
	}
}

// TestTraceConfigForRequestDistinguishesAbsentFromEmptyFilter pins the one
// place a nil and an empty request filter differ: an empty filter is a real
// filter change (the user cleared every dimension) and drops the PID/TID
// scope, while an absent one keeps the configured scope.
func TestTraceConfigForRequestDistinguishesAbsentFromEmptyFilter(t *testing.T) {
	base := flags.NewFlags()
	base.PidFilter = 11
	base.TidFilter = 12

	if got := traceConfigForRequest(base, nil); got.PidFilter != 11 || got.TidFilter != 12 {
		t.Fatalf("nil filter scope = pid %d tid %d, want 11/12 kept", got.PidFilter, got.TidFilter)
	}
	empty := globalfilter.Filter{}
	if got := traceConfigForRequest(base, &empty); got.PidFilter != -1 || got.TidFilter != -1 {
		t.Fatalf("empty filter scope = pid %d tid %d, want -1/-1", got.PidFilter, got.TidFilter)
	}

	filter := globalfilter.Filter{PID: &globalfilter.NumericFilter{Op: globalfilter.OpEq, Value: 42}}
	got := traceConfigForRequest(base, &filter)
	filter.PID.Value = 7
	if got.PidFilter != 42 || got.TidFilter != -1 {
		t.Fatalf("pid filter scope = pid %d tid %d, want 42/-1", got.PidFilter, got.TidFilter)
	}
	if got.GlobalFilter.PID == nil || got.GlobalFilter.PID.Value != 42 {
		t.Fatalf("global filter PID = %+v, want a clone unaffected by the caller's edit", got.GlobalFilter.PID)
	}
}
