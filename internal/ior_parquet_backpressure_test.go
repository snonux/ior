package internal

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"ior/internal/flags"
	"ior/internal/parquet"
)

// TestHeadlessRecorderConfigAppliesBackpressure pins the headless
// configuration of task 4s2: backpressure and the large bounded queue, because
// the zero RecorderConfig (the TUI's shed mode) loses ~2% of the rows at high
// syscall rates. It checks the helper only; that the headless run really uses
// it is TestRunHeadlessParquetBuildsABackpressuredRecorder.
func TestHeadlessRecorderConfigAppliesBackpressure(t *testing.T) {
	cfg := headlessRecorderConfig()
	if !cfg.BlockWhenFull {
		t.Fatal("headless recorder sheds rows on overflow; want backpressure (BlockWhenFull)")
	}
	if cfg.QueueCapacity != parquet.HeadlessQueueCapacity {
		t.Fatalf("headless QueueCapacity = %d, want %d", cfg.QueueCapacity, parquet.HeadlessQueueCapacity)
	}
}

// TestRunHeadlessParquetBuildsABackpressuredRecorder pins the call site: it
// runs the real headless lifecycle (fake trace setup) with newHeadlessRecorder
// wrapped to keep the recorder it builds, and checks that recorder's effective
// configuration. Reverting the call site to parquet.NewRecorder(RecorderConfig{})
// - the shed-mode zero config - fails here although every recorder- and
// helper-level test would still pass.
func TestRunHeadlessParquetBuildsABackpressuredRecorder(t *testing.T) {
	var built []*parquet.Recorder
	orig := newHeadlessRecorder
	newHeadlessRecorder = func(cfg parquet.RecorderConfig) *parquet.Recorder {
		rec := orig(cfg)
		built = append(built, rec)
		return rec
	}
	t.Cleanup(func() { newHeadlessRecorder = orig })

	path := filepath.Join(t.TempDir(), "headless.parquet")
	cfg := flags.NewFlags()
	cfg.ParquetPath = path
	probe := &headlessParquetRunProbe{}
	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetup(t, 2, probe, path)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}

	if len(built) != 1 {
		t.Fatalf("headless run built %d recorders, want 1", len(built))
	}
	got := built[0].Config()
	if !got.BlockWhenFull {
		t.Error("the headless run's recorder sheds rows on overflow; want backpressure (BlockWhenFull)")
	}
	if got.QueueCapacity != parquet.HeadlessQueueCapacity {
		t.Errorf("the headless run's recorder QueueCapacity = %d, want %d", got.QueueCapacity, parquet.HeadlessQueueCapacity)
	}
}

// TestHeadlessParquetSinkLosesNoRowUnderBackpressure drives the sink's print
// callback with many more pairs than a deliberately tiny queue holds, using
// the headless recorder configuration, and checks the file keeps every one:
// the drop counter stays 0 and the finish step prints no partial-recording
// warning.
func TestHeadlessParquetSinkLosesNoRowUnderBackpressure(t *testing.T) {
	cfg := headlessRecorderConfig()
	cfg.QueueCapacity = 2 // overflows constantly; only backpressure keeps the rows
	cfg.BatchSize = 8
	cfg.FlushInterval = time.Hour
	cfg.Writer = parquet.WriterConfig{MaxRowsPerRowGroup: 256}
	recorder := parquet.NewRecorder(cfg)
	path := filepath.Join(t.TempDir(), "headless.parquet")
	if err := recorder.Start(path, parquet.StartOptions{Metadata: parquet.FileMetadata{Mode: "headless"}}); err != nil {
		t.Fatalf("recorder.Start() error = %v", err)
	}

	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	sink := newHeadlessParquetSink(recorder, cancel)
	el := &eventLoop{}
	sink.configure(el)

	const pairs = 20000
	for i := 1; i <= pairs; i++ {
		el.printCb(testTracePair(uint64(i), "keep"))
	}

	var logged []any
	err := finishHeadlessParquetRecording(recorder, sink, el.samplingResult(), func(a ...any) { logged = append(logged, a...) })
	if err != nil {
		t.Fatalf("finishHeadlessParquetRecording() error = %v", err)
	}
	status := recorder.Status()
	if status.RowsWritten != pairs || status.RowsDropped != 0 {
		t.Fatalf("written %d, dropped %d; want %d written, 0 dropped", status.RowsWritten, status.RowsDropped, pairs)
	}
	for _, part := range logged {
		if s, ok := part.(string); ok && s == "Warning:" {
			t.Fatalf("finish step warned about a partial recording: %v", logged)
		}
	}
}
