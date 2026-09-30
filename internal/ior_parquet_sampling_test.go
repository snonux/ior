package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ior/internal/parquet"
	"ior/internal/statsengine"
	"ior/internal/types"

	parquetgo "github.com/parquet-go/parquet-go"
)

// parquetFooter returns the footer value of key in the parquet file at path.
func parquetFooter(t *testing.T, path, key string) (string, bool) {
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

// A headless -parquet run that samples used to write the recorded sample with
// no marker and never read the kernel counts of the rest. Here the recorded
// rows are 8 sync pairs while the kernel counted 30 more: the footer must say
// the file is sampled and carry the exact total of 38.
func TestRunHeadlessParquetMarksASampledRecordingWithExactTotals(t *testing.T) {
	const traced, counted = 8, 30
	path := filepath.Join(t.TempDir(), "sampled.parquet")
	cfg := mustParseArgs(t, "-parquet", path, "-syscall-sampling-syscalls", "sync=4")
	probe := &headlessParquetRunProbe{}

	newLoop := func() *eventLoop {
		el := newEmitOrderEventLoop(t)
		tally := newSamplingTally(rawModeSamplingRates(cfg))
		el.samplingTally = tally
		el.SetAggregateSink(tally)
		el.cfg.aggregateIngestTraceIDs = buildAggregateIngestTraceIDs(cfg)
		el.aggregateSrc = &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
			{{TraceID: types.SYS_ENTER_SYNC, Count: counted}},
		}}
		return el
	}
	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetupWithLoop(t, traced, probe, path, newLoop)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}

	if rows := readRecordedParquet(t, path); len(rows) != traced {
		t.Fatalf("recorded rows = %d, want %d", len(rows), traced)
	}
	if got, ok := parquetFooter(t, path, parquet.KeySampling); !ok || got != "sync=4" {
		t.Fatalf("%s = %q, %v; want sync=4", parquet.KeySampling, got, ok)
	}
	want := `[{"syscall":"sync","rate":4,"traced":8,"counted_only":30,"total":38}]`
	if got, ok := parquetFooter(t, path, parquet.KeySamplingTotals); !ok || got != want {
		t.Fatalf("%s = %q, %v; want %s", parquet.KeySamplingTotals, got, ok, want)
	}
}

// A run that samples nothing leaves the file exactly as it was before: no key
// in the footer, so the marker stays trustworthy.
func TestRunHeadlessParquetLeavesAnUnsampledRecordingUnmarked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain.parquet")
	cfg := mustParseArgs(t, "-parquet", path)
	probe := &headlessParquetRunProbe{}

	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetup(t, 3, probe, path)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}
	for _, key := range []string{parquet.KeySampling, parquet.KeySamplingTotals} {
		if got, ok := parquetFooter(t, path, key); ok {
			t.Fatalf("%s = %q on an unsampled recording, want it absent", key, got)
		}
	}
}

// With a filter the kernel counters cannot honour, the footer still marks the
// file sampled but says the totals are unavailable instead of giving a count.
func TestRunHeadlessParquetSampledWithUnusableCountersSaysUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sampled.parquet")
	cfg := mustParseArgs(t, "-parquet", path, "-syscall-sampling-syscalls", "sync=4")
	probe := &headlessParquetRunProbe{}

	newLoop := func() *eventLoop {
		el := newEmitOrderEventLoop(t)
		tally := newSamplingTally(rawModeSamplingRates(cfg))
		el.samplingTally = tally
		el.SetAggregateSink(tally)
		// A failing source: the final drain cannot read the counters.
		el.aggregateSrc = &aggregateSourceStub{err: os.ErrClosed}
		el.cfg.aggregateIngestTraceIDs = buildAggregateIngestTraceIDs(cfg)
		return el
	}
	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetupWithLoop(t, 2, probe, path, newLoop)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}
	if got, _ := parquetFooter(t, path, parquet.KeySampling); got != "sync=4" {
		t.Fatalf("%s = %q, want sync=4", parquet.KeySampling, got)
	}
	got, _ := parquetFooter(t, path, parquet.KeySamplingTotals)
	if got != "unavailable" || strings.Contains(got, "traced") {
		t.Fatalf("%s = %q, want unavailable", parquet.KeySamplingTotals, got)
	}
}
