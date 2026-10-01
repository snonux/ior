package internal

import (
	"testing"

	"ior/internal/flags"
	"ior/internal/globalfilter"
	"ior/internal/runtime"
	"ior/internal/streamrow"
)

// countingRowEmitter is a runtime.RowEmitter that only collects the rows it
// is handed, so a test can see what the print callback delivers where.
type countingRowEmitter struct {
	rows []streamrow.Row
}

func (c *countingRowEmitter) EmitRow(row streamrow.Row) { c.rows = append(c.rows, row) }

// emitterBindings is fakeRuntimeBindings plus the optional session emitter.
type emitterBindings struct {
	fakeRuntimeBindings
	emitter *countingRowEmitter
}

func (b *emitterBindings) RowEmitter() runtime.RowEmitter { return b.emitter }

// TestWireRuntimeBindingsAdoptsTheSessionEmitter: bindings that offer the
// single-gate emitter get it wired - but only next to their own stream
// buffer, because the emitter pushes into that buffer. Without one the fresh
// local buffer keeps receiving the rows through the plain fallback.
func TestWireRuntimeBindingsAdoptsTheSessionEmitter(t *testing.T) {
	emitter := &countingRowEmitter{}
	withSink := &emitterBindings{
		fakeRuntimeBindings: fakeRuntimeBindings{sink: &fakeEventSink{}, seq: &fakeSequencer{}},
		emitter:             emitter,
	}
	rt := &tuiRuntime{snapSource: fakeSnapshotSource{}}
	if err := wireRuntimeBindings(rt, withSink); err != nil {
		t.Fatalf("wireRuntimeBindings: %v", err)
	}
	if rt.emitter != runtime.RowEmitter(emitter) {
		t.Fatal("bindings offering a RowEmitter must have it wired")
	}

	noSink := &emitterBindings{emitter: emitter}
	rt = &tuiRuntime{snapSource: fakeSnapshotSource{}}
	if err := wireRuntimeBindings(rt, noSink); err != nil {
		t.Fatalf("wireRuntimeBindings: %v", err)
	}
	if rt.emitter != nil {
		t.Fatal("an emitter must not be wired when the bindings have no stream buffer to push into")
	}

	plain := &fakeRuntimeBindings{sink: &fakeEventSink{}}
	rt = &tuiRuntime{snapSource: fakeSnapshotSource{}}
	if err := wireRuntimeBindings(rt, plain); err != nil {
		t.Fatalf("wireRuntimeBindings: %v", err)
	}
	if rt.emitter != nil {
		t.Fatal("bindings without the optional capability must leave the plain fallback in place")
	}
}

// TestPrintCallbackDeliversRowsThroughTheEmitter pins the hot path: with an
// emitter wired, every ingested pair reaches it exactly once (in sequence
// order) and the callback itself touches neither the stream buffer nor the
// recorder any more - the emitter owns both behind one gate. A pair the
// filter rejects is not emitted at all.
func TestPrintCallbackDeliversRowsThroughTheEmitter(t *testing.T) {
	emitter := &countingRowEmitter{}
	sink, recorder := &fakeEventSink{}, &fakeRowRecorder{}
	cfg := flags.NewFlags()
	cfg.GlobalFilter = globalfilter.Filter{Comm: &globalfilter.StringFilter{Pattern: "keep"}}
	rt, err := buildTUIRuntime(cfg, nil)
	if err != nil {
		t.Fatalf("buildTUIRuntime() error = %v", err)
	}
	rt.streamBuf, rt.recorder, rt.emitter = sink, recorder, emitter
	configure, unregister := makeTUIEventLoopConfigurer(cfg, rt, nil)
	t.Cleanup(unregister)
	el := &eventLoop{}
	configure(el)

	el.printCb(testTracePair(1, "keep"))
	el.printCb(testTracePair(2, "drop"))
	el.printCb(testTracePair(3, "keep"))

	if len(emitter.rows) != 2 || emitter.rows[0].Seq+1 != emitter.rows[1].Seq {
		t.Fatalf("emitter rows = %+v, want the two kept pairs with consecutive sequence numbers", emitter.rows)
	}
	if len(sink.rows) != 0 || len(recorder.rows) != 0 {
		t.Fatalf("callback bypassed the emitter: sink %d rows, recorder %d rows", len(sink.rows), len(recorder.rows))
	}
}

// TestPlainRowEmitterPushesThenRecords covers the fallback used without a
// session gate: the row lands in the stream and in the recorder, stamped with
// the live filter epoch, and a recorder result that is news still becomes a
// warning through the event loop.
func TestPlainRowEmitterPushesThenRecords(t *testing.T) {
	sink, recorder := &fakeEventSink{}, &fakeRowRecorder{}
	bindings := &fakeRuntimeBindings{sink: sink, rec: recorder, seq: &fakeSequencer{}, epoch: 9}
	s := newTUITestSession(t, bindings, nil)
	if s.rt.emitter != nil {
		t.Fatal("fake bindings offer no emitter; the plain fallback must be in use")
	}

	s.feed(2)

	if len(sink.rows) != 2 || len(recorder.rows) != 2 || recorder.epoch != 9 {
		t.Fatalf("sink %d rows, recorder %d rows at epoch %d, want 2, 2 at epoch 9", len(sink.rows), len(recorder.rows), recorder.epoch)
	}
}
