package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"ior/internal/parquet"
	"ior/internal/probemanager"
	"ior/internal/runtime"
	"ior/internal/sampling"
	"ior/internal/streamrow"

	parquetgo "github.com/parquet-go/parquet-go"
)

// fakeRecordingSampling stands in for a trace session's sampling side: it
// accrues "kernel counts" that a flush hands to the session's gated recorder,
// the way the real drain loop does.
type fakeRecordingSampling struct {
	entries []sampling.Entry
	counter runtime.RecordingSamplingCounter
	pending map[string]uint64
	flushes int
}

func (f *fakeRecordingSampling) SampledSyscalls() []sampling.Entry { return f.entries }

func (f *fakeRecordingSampling) FlushAggregates() {
	f.flushes++
	for syscall, n := range f.pending {
		f.counter.CountKernelOnly(syscall, n)
	}
	clear(f.pending)
}

func (f *fakeRecordingSampling) accrue(syscall string, n uint64) { f.pending[syscall] += n }

// publishFakeSampling begins a session on m's bindings and publishes a fake
// sampling side for it: a 1-in-10 read and the aggregate-only futex default.
func publishFakeSampling(t *testing.T, m *Model) (traceSessionBindings, *fakeRecordingSampling) {
	t.Helper()
	view := m.runtime.beginSession()
	counter, ok := view.Recorder().(runtime.RecordingSamplingCounter)
	if !ok {
		t.Fatal("the session's recorder view does not forward sampling counts")
	}
	fake := &fakeRecordingSampling{
		entries: []sampling.Entry{{Syscall: "futex", Rate: 0}, {Syscall: "read", Rate: 10}},
		counter: counter,
		pending: map[string]uint64{},
	}
	view.SetRecordingSampling(fake)
	return view, fake
}

func recordingModel() *Model {
	m := NewModel(-1, func(context.Context, TraceRequest) error { return nil })
	m.router.showDashboard()
	return m
}

func footer(t *testing.T, path, key string) (string, bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	file, err := parquetgo.OpenFile(f, info.Size())
	if err != nil {
		t.Fatalf("open parquet %s: %v", path, err)
	}
	return file.Lookup(key)
}

func emitSyscallRows(view traceSessionBindings, syscalls ...string) {
	for i, syscall := range syscalls {
		view.RowEmitter().EmitRow(streamrow.Row{Seq: uint64(i + 1), Syscall: syscall})
	}
}

func recordWindow(t *testing.T, m *Model, name string, during func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording: %v", err)
	}
	during()
	if err := m.stopRecording(); err != nil {
		t.Fatalf("stopRecording: %v", err)
	}
	return path
}

// R pressed twice on one trace: each file carries the rates and the totals of
// its own window - the counts that accrued before, between and after the
// recordings belong to none of them, because the TUI flushes the kernel
// counters at every start and stop. The aggregate-only futex has no row in
// either file, and the footer is where its true count is.
func TestRRecordingsCarryRatesAndPerRecordingTotals(t *testing.T) {
	m := recordingModel()
	view, fake := publishFakeSampling(t, m)

	fake.accrue("futex", 1000) // before the first recording
	first := recordWindow(t, m, "first.parquet", func() {
		emitSyscallRows(view, "read", "write")
		fake.accrue("futex", 10)
		fake.accrue("read", 9)
	})
	fake.accrue("futex", 2000) // between the recordings
	second := recordWindow(t, m, "second.parquet", func() {
		emitSyscallRows(view, "read", "read")
		fake.accrue("futex", 20)
	})
	fake.accrue("futex", 3000) // after them

	if fake.flushes != 4 {
		t.Fatalf("flushes = %d, want one per start and stop", fake.flushes)
	}
	for _, tc := range []struct{ path, want string }{
		{first, `[{"syscall":"futex","rate":0,"traced":0,"counted_only":10,"total":10},{"syscall":"read","rate":10,"traced":1,"counted_only":9,"total":10}]`},
		{second, `[{"syscall":"futex","rate":0,"traced":0,"counted_only":20,"total":20},{"syscall":"read","rate":10,"traced":2,"counted_only":0,"total":2}]`},
	} {
		if got, _ := footer(t, tc.path, parquet.KeySampling); got != "futex=0,read=10" {
			t.Fatalf("%s: %s = %q, want futex=0,read=10", filepath.Base(tc.path), parquet.KeySampling, got)
		}
		if got, _ := footer(t, tc.path, parquet.KeySamplingTotals); got != tc.want {
			t.Fatalf("%s: totals = %s\nwant %s", filepath.Base(tc.path), got, tc.want)
		}
		if got, _ := footer(t, tc.path, "ior.mode"); got != "tui" {
			t.Fatalf("%s: ior.mode = %q, want tui", filepath.Base(tc.path), got)
		}
	}
}

// A session retired while a recording runs (a filter change that restarts the
// trace) gets its counters flushed into the recording first; whatever it still
// reports afterwards is dropped, and the next session's counts are added.
func TestSessionRestartDuringARecordingKeepsItsCounts(t *testing.T) {
	m := recordingModel()
	old, oldFake := publishFakeSampling(t, m)
	path := recordWindow(t, m, "restart.parquet", func() {
		oldFake.accrue("futex", 5)
		old.end()
		oldFake.counter.CountKernelOnly("futex", 100) // the retired session's late drain
		_, nextFake := publishFakeSampling(t, m)
		nextFake.accrue("futex", 7)
	})
	want := `[{"syscall":"futex","rate":0,"traced":0,"counted_only":12,"total":12}]`
	if got, _ := footer(t, path, parquet.KeySamplingTotals); got != want {
		t.Fatalf("totals = %s\nwant %s", got, want)
	}
}

// The rates announced at the start are those of the attached probes, as in the
// raw modes; a sampled syscall attached later still shows up in the totals.
func TestRRecordingAnnouncesTheAttachedSampledSyscalls(t *testing.T) {
	m := recordingModel()
	view, fake := publishFakeSampling(t, m)
	view.SetProbeManager(fakeProbeManager{states: []probemanager.ProbeState{
		{Syscall: "read", Active: true}, {Syscall: "futex", Active: false},
	}})
	path := recordWindow(t, m, "probes.parquet", func() {
		fake.accrue("futex", 3) // futex attached during the recording
	})
	if got, _ := footer(t, path, parquet.KeySampling); got != "read=10" {
		t.Fatalf("%s = %q, want read=10 (futex was not attached at the start)", parquet.KeySampling, got)
	}
	want := `[{"syscall":"futex","rate":0,"traced":0,"counted_only":3,"total":3}]`
	if got, _ := footer(t, path, parquet.KeySamplingTotals); got != want {
		t.Fatalf("totals = %s\nwant %s", got, want)
	}
}

// Without a session that published its sampling (nothing sampled, or no trace
// at all), a recording stays unmarked, exactly as before.
func TestRRecordingWithoutSamplingIsUnmarked(t *testing.T) {
	m := recordingModel()
	view := m.runtime.beginSession()
	path := recordWindow(t, m, "plain.parquet", func() { emitSyscallRows(view, "read") })
	for _, key := range []string{parquet.KeySampling, parquet.KeySamplingTotals} {
		if got, ok := footer(t, path, key); ok {
			t.Fatalf("%s = %q, want it absent", key, got)
		}
	}
}

// The sampled-syscall list outlives the session that published it (the rates
// are fixed for the process), but its flush does not: a recording started
// while the next session attaches is still marked, and nothing flushes a
// retired session.
func TestRecordingBetweenSessionsIsStillMarked(t *testing.T) {
	m := recordingModel()
	view, fake := publishFakeSampling(t, m)
	view.end()
	flushesAtEnd := fake.flushes
	path := recordWindow(t, m, "between.parquet", func() {})
	if fake.flushes != flushesAtEnd {
		t.Fatalf("a retired session was flushed %d more times", fake.flushes-flushesAtEnd)
	}
	if got, _ := footer(t, path, parquet.KeySampling); got != "futex=0,read=10" {
		t.Fatalf("%s = %q, want futex=0,read=10", parquet.KeySampling, got)
	}
}

// Quitting with a recording running flushes the counters into it too.
func TestQuitFlushesTheCountersIntoTheRecording(t *testing.T) {
	m := recordingModel()
	_, fake := publishFakeSampling(t, m)
	path := filepath.Join(t.TempDir(), "quit.parquet")
	if err := m.startRecording(path); err != nil {
		t.Fatalf("startRecording: %v", err)
	}
	fake.accrue("futex", 4)
	if err := m.stopRecordingAtQuit(); err != nil {
		t.Fatalf("stopRecordingAtQuit: %v", err)
	}
	want := `[{"syscall":"futex","rate":0,"traced":0,"counted_only":4,"total":4}]`
	if got, _ := footer(t, path, parquet.KeySamplingTotals); got != want {
		t.Fatalf("totals = %s\nwant %s", got, want)
	}
}
