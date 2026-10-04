package tui

import (
	"errors"
	"sync"
	"testing"

	"ior/internal/runtime"
	"ior/internal/streamrow"
)

// benchRow is a realistically populated stream row (the same ~250-byte struct
// the event loop builds per event pair), so the benchmarks pay the copies the
// production path pays.
func benchRow() streamrow.Row {
	return streamrow.Row{
		Seq: 1, TimeNs: 123456789, Syscall: "openat", Family: "file", Comm: "nginx",
		PID: 42, TID: 84, FileName: "/var/www/html/index.html", DurationNs: 1500,
		GapNs: 250, Bytes: 4096, FD: 7,
	}
}

// deadRecorder models a recorder whose recording has died and whose failure
// was already claimed: every Record repeats the stored error and TakeFailure
// takes an exclusive lock to find there is nothing new, which is what each
// event pays from the first failure until the next Start.
type deadRecorder struct {
	runtime.RecordingController
	mu  sync.Mutex
	err error
}

func (d *deadRecorder) Record(streamrow.Row, uint64) error { return d.err }

func (d *deadRecorder) TakeFailure() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return nil
}

// benchSessionView returns a current session view over bindings whose recorder
// is the given one (nil keeps the idle real parquet recorder).
func benchSessionView(rec runtime.RecordingController) traceSessionBindings {
	r := newRuntimeBindings()
	if rec != nil {
		r.recorder = rec
	}
	return r.beginSession()
}

// recorderCases are the two recorder states every event can meet: idle (the
// common case: no recording running) and failed (every event after a
// recording died, until the next Start).
func recorderCases() []struct {
	name string
	rec  runtime.RecordingController
} {
	return []struct {
		name string
		rec  runtime.RecordingController
	}{
		{"idle", nil},
		{"failed", &deadRecorder{err: errors.New("disk full")}},
	}
}

// BenchmarkSessionPushThenRecordWarning is the per-event output of the TUI
// print callback as it was before task yp2: the gated sink's Push and the
// gated recorder's RecordWarning, two separate session gates.
func BenchmarkSessionPushThenRecordWarning(b *testing.B) {
	for _, c := range recorderCases() {
		b.Run(c.name, func(b *testing.B) {
			view := benchSessionView(c.rec)
			sink, rec := view.StreamBuffer(), view.Recorder().(runtime.WarningRecorder)
			row := benchRow()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sink.Push(row)
				rec.RecordWarning(row, view.FilterEpoch(), runtime.RecorderWarningText)
			}
		})
	}
}

// BenchmarkSessionEmitRow is the same per-event output through the session's
// single-gate emitter (task yp2): one read lock for the push, the record and
// the recorder warning.
func BenchmarkSessionEmitRow(b *testing.B) {
	for _, c := range recorderCases() {
		b.Run(c.name, func(b *testing.B) {
			emitter := benchSessionView(c.rec).RowEmitter()
			row := benchRow()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				emitter.EmitRow(row)
			}
		})
	}
}

// BenchmarkSessionDirect is the floor the two benchmarks above are measured
// against: the same Push and Record straight on the ring buffer and the
// recorder, with no session gate, closure or warning check at all.
func BenchmarkSessionDirect(b *testing.B) {
	for _, c := range recorderCases() {
		b.Run(c.name, func(b *testing.B) {
			r := newRuntimeBindings()
			if c.rec != nil {
				r.recorder = c.rec
			}
			row := benchRow()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				r.streamBuffer.Push(row)
				_ = r.recorder.Record(row, r.FilterEpoch())
			}
		})
	}
}

// opaqueEmitter hides the concrete emitter type from the compiler, as the
// trace core sees it: with a visible concrete type the compiler devirtualizes
// the call, and the allocation check below would measure something the
// production call never gets.
//
//go:noinline
func opaqueEmitter(e runtime.RowEmitter) runtime.RowEmitter { return e }

//go:noinline
func freshRow(i int) streamrow.Row {
	row := benchRow()
	row.Seq = uint64(i)
	return row
}

// BenchmarkSessionEmitRowFreshLocal is EmitRow as the print callback calls it:
// a row built per event and handed through the runtime.RowEmitter interface.
// It must stay at 0 allocs/op. With a *streamrow.Row parameter the same loop
// measured 1 alloc/op of 224 B (and ~240 ns/op): through an interface the
// per-event local escapes, which is why EmitRow takes the row by value.
func BenchmarkSessionEmitRowFreshLocal(b *testing.B) {
	emitter := opaqueEmitter(benchSessionView(nil).RowEmitter())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		emitter.EmitRow(freshRow(i))
	}
}
