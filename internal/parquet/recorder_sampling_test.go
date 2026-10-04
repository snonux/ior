package parquet

import (
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ior/internal/sampling"
)

// tuiSampled is a TUI trace's sampled syscalls: a 1-in-10 read and the
// aggregate-only futex default.
func tuiSampled() []sampling.Entry {
	return []sampling.Entry{{Syscall: "read", Rate: 10}, {Syscall: "futex", Rate: 0}}
}

// startTallied starts a recording that keeps its own sampling totals, the way
// the TUI starts an R recording, and returns its path.
func startTallied(t *testing.T, recorder *Recorder, name string) string {
	t.Helper()
	tally := sampling.NewTally(tuiSampled(), nil)
	meta := FileMetadata{Mode: "tui", Sampling: tally.Plan()}
	path := filepath.Join(t.TempDir(), name)
	if err := recorder.Start(path, StartOptions{Metadata: meta, SamplingTally: tally}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return path
}

func recordRows(t *testing.T, recorder *Recorder, syscalls ...string) {
	t.Helper()
	for i, syscall := range syscalls {
		if err := recorder.Record(testStreamRow(uint64(i+1), syscall, false), 0); err != nil {
			t.Fatalf("Record(%s): %v", syscall, err)
		}
	}
}

// A tallied recording writes the rates at the start and, at the stop, the
// totals of exactly its rows plus the kernel-only counts it was handed.
func TestTalliedRecordingWritesItsOwnTotals(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{QueueCapacity: 16, BatchSize: 2, FlushInterval: time.Hour})
	path := startTallied(t, recorder, "r.parquet")
	recordRows(t, recorder, "read", "write", "read", "read")
	recorder.CountKernelOnly("read", 27)
	recorder.CountKernelOnly("futex", 400)
	recorder.CountKernelOnly("write", 5) // not sampled: ignored
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got, ok := footerValue(t, path, KeySampling); !ok || got != "futex=0,read=10" {
		t.Fatalf("%s = %q, %v; want futex=0,read=10", KeySampling, got, ok)
	}
	want := `[{"syscall":"futex","rate":0,"traced":0,"counted_only":400,"total":400},` +
		`{"syscall":"read","rate":10,"traced":3,"counted_only":27,"total":30}]`
	if got, ok := footerValue(t, path, KeySamplingTotals); !ok || got != want {
		t.Fatalf("%s = %s, %v\nwant %s", KeySamplingTotals, got, ok, want)
	}
}

// R pressed twice: each recording's totals are its own delta. Counts that
// arrive while no recording runs belong to none.
func TestConsecutiveTalliedRecordingsHaveDeltaTotals(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{QueueCapacity: 16, BatchSize: 2, FlushInterval: time.Hour})
	recorder.CountKernelOnly("futex", 1000) // before any recording

	first := startTallied(t, recorder, "first.parquet")
	recordRows(t, recorder, "read")
	recorder.CountKernelOnly("futex", 10)
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop first: %v", err)
	}
	recorder.CountKernelOnly("futex", 2000) // between the recordings
	recorder.MarkSamplingLowerBound()       // no recording: must not stick
	recorder.MarkSamplingUnavailable("gap")

	second := startTallied(t, recorder, "second.parquet")
	recordRows(t, recorder, "read", "read")
	recorder.CountKernelOnly("futex", 20)
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop second: %v", err)
	}

	for _, tc := range []struct{ path, want string }{
		{first, `[{"syscall":"futex","rate":0,"traced":0,"counted_only":10,"total":10},{"syscall":"read","rate":10,"traced":1,"counted_only":0,"total":1}]`},
		{second, `[{"syscall":"futex","rate":0,"traced":0,"counted_only":20,"total":20},{"syscall":"read","rate":10,"traced":2,"counted_only":0,"total":2}]`},
	} {
		if got, _ := footerValue(t, tc.path, KeySamplingTotals); got != tc.want {
			t.Fatalf("%s totals = %s\nwant %s", filepath.Base(tc.path), got, tc.want)
		}
	}
}

func TestTalliedRecordingMarksLossAndIncompleteCounts(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{QueueCapacity: 16, BatchSize: 2, FlushInterval: time.Hour})
	lossy := startTallied(t, recorder, "lossy.parquet")
	recordRows(t, recorder, "read")
	recorder.MarkSamplingLowerBound()
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got, _ := footerValue(t, lossy, KeySamplingTotals); !strings.Contains(got, `"lower_bound":true`) {
		t.Fatalf("totals = %s, want lower_bound", got)
	}

	filtered := startTallied(t, recorder, "filtered.parquet")
	recorder.MarkSamplingUnavailable("the active filter cannot be applied to the kernel counters")
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got, _ := footerValue(t, filtered, KeySamplingTotals); got != "unavailable" {
		t.Fatalf("totals = %q, want unavailable", got)
	}
}

// A tally that samples nothing leaves the file unmarked, like an unsampled
// headless run, and a recording without a tally gets no totals of its own.
func TestRecordingWithoutSampledSyscallsStaysUnmarked(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{QueueCapacity: 16, BatchSize: 2, FlushInterval: time.Hour})
	path := filepath.Join(t.TempDir(), "plain.parquet")
	if err := recorder.Start(path, StartOptions{SamplingTally: sampling.NewTally(nil, nil)}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	recordRows(t, recorder, "read")
	recorder.CountKernelOnly("read", 5)
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	for _, key := range []string{KeySampling, KeySamplingTotals} {
		if got, ok := footerValue(t, path, key); ok {
			t.Fatalf("%s = %q, want it absent", key, got)
		}
	}
}

// footerRecordingWriter is a blockingWriter that also takes footer pairs, so a
// test can stall the writer (to shed rows) and still see the footer.
type footerRecordingWriter struct {
	*blockingWriter
	mu     sync.Mutex
	footer map[string]string
}

func (w *footerRecordingWriter) SetKeyValueMetadata(key, value string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.footer[key] = value
	return nil
}

// A row shed by the full shed-mode queue was emitted but is in neither the
// file nor the kernel count: the totals are then only a lower bound, and the
// shed row is not counted as traced.
func TestShedRowsMakeTheTalliedTotalsALowerBound(t *testing.T) {
	writer := &footerRecordingWriter{blockingWriter: newBlockingWriter(), footer: map[string]string{}}
	recorder := NewRecorder(RecorderConfig{
		QueueCapacity: 1, BatchSize: 1, FlushInterval: time.Hour,
		newWriter: func(string, WriterConfig, FileMetadata) (rowWriter, error) { return writer, nil },
	})
	tally := sampling.NewTally(tuiSampled(), nil)
	if err := recorder.Start("ignored.parquet", StartOptions{SamplingTally: tally}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	recordRows(t, recorder, "read") // taken by the writer, which then stalls
	<-writer.started
	if err := recorder.Record(testStreamRow(2, "read", false), 0); err != nil {
		t.Fatalf("Record (queued): %v", err)
	}
	if err := recorder.Record(testStreamRow(3, "read", false), 0); err == nil {
		t.Fatal("Record on a full queue succeeded, want it shed")
	}
	writer.releaseWrites()
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	writer.mu.Lock()
	footer := maps.Clone(writer.footer)
	writer.mu.Unlock()
	want := `[{"syscall":"read","rate":10,"traced":2,"counted_only":0,"total":2,"lower_bound":true}]`
	if got := footer[KeySamplingTotals]; got != want {
		t.Fatalf("totals = %s\nwant %s", got, want)
	}
}
