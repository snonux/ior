package internal

import (
	"strings"
	"testing"

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
	publishedSnapshotSrc  runtime.SnapshotSource
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

func (b *fakeRuntimeBindings) SetDashboardSnapshotSource(source runtime.SnapshotSource) {
	b.publishedSnapshotSrc = source
}
func (b *fakeRuntimeBindings) SetEventStreamSource(source runtime.StreamSource) {
	b.publishedStreamSource = source
}
func (b *fakeRuntimeBindings) SetLiveTrie(runtime.LiveTrieSource)   {}
func (b *fakeRuntimeBindings) SetProbeManager(runtime.ProbeManager) {}
func (b *fakeRuntimeBindings) SetLiveFilterSetter(func(globalfilter.Filter)) func() {
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
	// narrowed to the one-method RowRecorder seam.
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

// fakeSnapshotSource is a minimal SnapshotSource so the wiring test does not
// depend on a live stats engine.
type fakeSnapshotSource struct{}

func (fakeSnapshotSource) Snapshot() (*statsengine.Snapshot, error) {
	return nil, nil
}
