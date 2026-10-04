package parquet

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ior/internal/sampling"

	parquetgo "github.com/parquet-go/parquet-go"
)

// footerValue returns the footer key/value pair key of the parquet file at
// path, and whether it is present.
func footerValue(t *testing.T, path, key string) (string, bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	file, err := parquetgo.OpenFile(f, info.Size())
	if err != nil {
		t.Fatalf("open parquet %s: %v", path, err)
	}
	return file.Lookup(key)
}

func sampledRun() sampling.Summary {
	return sampling.New([]sampling.Entry{{Syscall: "read", Rate: 10, Traced: 110, Counted: 890}}, "")
}

// record runs one recording with meta, sets totals (when given) before the stop
// the way a headless run does, and returns the published path.
func record(t *testing.T, meta FileMetadata, totals *sampling.Summary) string {
	t.Helper()
	recorder := NewRecorder(RecorderConfig{QueueCapacity: 8, BatchSize: 2, FlushInterval: time.Hour})
	path := filepath.Join(t.TempDir(), "run.parquet")
	if err := recorder.Start(path, StartOptions{Metadata: meta}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := recorder.Record(testStreamRow(1, "read", false), 0); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if totals != nil {
		if err := recorder.SetSamplingTotals(*totals); err != nil {
			t.Fatalf("SetSamplingTotals: %v", err)
		}
	}
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	return recorder.Status().Path
}

func TestSampledRecordingIsMarkedInTheFooter(t *testing.T) {
	summary := sampledRun()
	meta := FileMetadata{Mode: "headless", Sampling: summary}
	path := record(t, meta, &summary)

	if got, ok := footerValue(t, path, KeySampling); !ok || got != "read=10" {
		t.Fatalf("%s = %q, %v; want read=10", KeySampling, got, ok)
	}
	want := `[{"syscall":"read","rate":10,"traced":110,"counted_only":890,"total":1000}]`
	if got, ok := footerValue(t, path, KeySamplingTotals); !ok || got != want {
		t.Fatalf("%s = %q, %v; want %s", KeySamplingTotals, got, ok, want)
	}
}

// A recording of a run that sampled nothing must be indistinguishable from
// before: neither key, so `ior.sampling` being present stays a reliable marker.
func TestUnsampledRecordingHasNoSamplingKeys(t *testing.T) {
	none := sampling.Summary{}
	path := record(t, FileMetadata{Mode: "headless"}, &none)
	for _, key := range []string{KeySampling, KeySamplingTotals} {
		if got, ok := footerValue(t, path, key); ok {
			t.Fatalf("%s = %q on an unsampled recording, want it absent", key, got)
		}
	}
}

// The rates are known from the start, so they mark the file even when the
// totals are never supplied (a recording stopped without SetSamplingTotals).
func TestSamplingRatesAreWrittenWithoutTotals(t *testing.T) {
	path := record(t, FileMetadata{Sampling: sampledRun()}, nil)
	if got, ok := footerValue(t, path, KeySampling); !ok || got != "read=10" {
		t.Fatalf("%s = %q, %v; want read=10", KeySampling, got, ok)
	}
	if got, ok := footerValue(t, path, KeySamplingTotals); ok {
		t.Fatalf("%s = %q, want it absent when no totals were set", KeySamplingTotals, got)
	}
}

// Totals that could not be determined are written as the word, not as counts.
func TestUnavailableSamplingTotalsAreNotInvented(t *testing.T) {
	summary := sampling.New([]sampling.Entry{{Syscall: "read", Rate: 10, Traced: 110}}, "filter")
	path := record(t, FileMetadata{Sampling: summary}, &summary)
	if got, ok := footerValue(t, path, KeySamplingTotals); !ok || got != "unavailable" {
		t.Fatalf("%s = %q, %v; want unavailable", KeySamplingTotals, got, ok)
	}
}

func TestSetSamplingTotalsWithoutASessionFails(t *testing.T) {
	recorder := NewRecorder(RecorderConfig{})
	if err := recorder.SetSamplingTotals(sampledRun()); !errors.Is(err, ErrRecorderNotActive) {
		t.Fatalf("SetSamplingTotals() error = %v, want ErrRecorderNotActive", err)
	}
	var nilRecorder *Recorder
	if err := nilRecorder.SetSamplingTotals(sampledRun()); !errors.Is(err, ErrRecorderNotActive) {
		t.Fatalf("nil recorder: error = %v, want ErrRecorderNotActive", err)
	}
}

func TestWriterSetKeyValueMetadataFailsOnceClosed(t *testing.T) {
	w, err := NewWriter(filepath.Join(t.TempDir(), "w.parquet"), WriterConfig{}, FileMetadata{})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	if err := w.SetKeyValueMetadata("k", "v"); err != nil {
		t.Fatalf("SetKeyValueMetadata on an open writer: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := w.SetKeyValueMetadata("k2", "v2"); err == nil {
		t.Fatal("SetKeyValueMetadata on a closed writer succeeded, want an error")
	}
	if got, ok := footerValue(t, w.FinalPath(), "k"); !ok || got != "v" {
		t.Fatalf("footer k = %q, %v; want v", got, ok)
	}
}

// An unsampled run wires nothing new, so handing the recorder its (empty)
// summary must succeed whatever state the session is in - in particular after
// the session already ended, which used to fail with ErrRecorderNotActive and
// turn a finished unsampled run into an error.
func TestSetSamplingTotalsOfAnUnsampledRunNeverFails(t *testing.T) {
	none := sampling.Summary{}
	var nilRecorder *Recorder
	if err := nilRecorder.SetSamplingTotals(none); err != nil {
		t.Fatalf("nil recorder: error = %v, want nil", err)
	}
	if err := NewRecorder(RecorderConfig{}).SetSamplingTotals(none); err != nil {
		t.Fatalf("recorder without a session: error = %v, want nil", err)
	}

	recorder := NewRecorder(RecorderConfig{QueueCapacity: 8, BatchSize: 2, FlushInterval: time.Hour})
	if err := recorder.Start(filepath.Join(t.TempDir(), "done.parquet"), StartOptions{}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := recorder.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := recorder.SetSamplingTotals(none); err != nil {
		t.Fatalf("after the session ended: error = %v, want nil", err)
	}
	// A sampled run, in contrast, must learn that its totals went nowhere.
	if err := recorder.SetSamplingTotals(sampledRun()); !errors.Is(err, ErrRecorderNotActive) {
		t.Fatalf("sampled totals after the session ended: error = %v, want ErrRecorderNotActive", err)
	}
}

// A run that sampled a family has a footer that names the family once, lists
// only the syscalls that were invoked, and flags ring-buffer losses.
func TestFamilyRunFooterIsCompactAndMarksLowerBounds(t *testing.T) {
	entries := []sampling.Entry{{Syscall: "read", Rate: 10, Family: "FS", Traced: 10, Counted: 90}}
	for i := range 100 {
		entries = append(entries, sampling.Entry{Syscall: "idle" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Rate: 10, Family: "FS"})
	}
	summary := sampling.New(entries, "").AtLeast()
	path := record(t, FileMetadata{Sampling: summary}, &summary)

	if got, _ := footerValue(t, path, KeySampling); got != "FS=10" {
		t.Fatalf("%s = %q, want FS=10", KeySampling, got)
	}
	want := `[{"syscall":"read","rate":10,"traced":10,"counted_only":90,"total":100,"lower_bound":true}]`
	if got, _ := footerValue(t, path, KeySamplingTotals); got != want {
		t.Fatalf("%s = %q, want %s", KeySamplingTotals, got, want)
	}
}
