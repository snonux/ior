package internal

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ior/internal/parquet"
	"ior/internal/statsengine"
	"ior/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
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
		tally := newSamplingTally(rawModeSamplingRates(cfg), rawModeSamplingFamilyRates(cfg))
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
		tally := newSamplingTally(rawModeSamplingRates(cfg), rawModeSamplingFamilyRates(cfg))
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

// useAggregateSource makes openAggregateSource hand out src (or err) instead
// of reading a BPF module, for the rest of the test.
func useAggregateSource(t *testing.T, src syscallAggregateSource, err error) (opened *int) {
	t.Helper()
	orig := openAggregateSource
	count := 0
	openAggregateSource = func(*bpf.Module) (syscallAggregateSource, error) {
		count++
		return src, err
	}
	t.Cleanup(func() { openAggregateSource = orig })
	return &count
}

// This is the wiring test of the production headless loop: the event loop
// comes from newHeadlessParquetEventLoop itself (not a hand-built one with the
// source assigned by the test), so dropping the `el.aggregateSrc = ...` line
// there leaves the file without its kernel counts and fails this test. The
// source is faked through openAggregateSource, which is what makes that
// possible without a BPF module.
func TestHeadlessParquetLoopWiresTheKernelCountsIntoTheFooter(t *testing.T) {
	const traced, counted = 8, 30
	path := filepath.Join(t.TempDir(), "wired.parquet")
	cfg := mustParseArgs(t, "-parquet", path, "-syscall-sampling-syscalls", "sync=4")
	opened := useAggregateSource(t, &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_SYNC, Count: counted}},
	}}, nil)

	newLoop := func() *eventLoop {
		el, err := newHeadlessParquetEventLoop(cfg, nil, func(...any) {})
		if err != nil {
			t.Fatalf("newHeadlessParquetEventLoop() error = %v", err)
		}
		el.setCachedComm(emitOrderTestTid, "emitorder")
		return el
	}
	probe := &headlessParquetRunProbe{}
	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetupWithLoop(t, traced, probe, path, newLoop)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}
	if *opened != 1 {
		t.Fatalf("aggregate source opened %d times, want once", *opened)
	}
	want := `[{"syscall":"sync","rate":4,"traced":8,"counted_only":30,"total":38}]`
	if got, ok := parquetFooter(t, path, parquet.KeySamplingTotals); !ok || got != want {
		t.Fatalf("%s = %q, %v; want %s (the kernel counts did not reach the footer)", parquet.KeySamplingTotals, got, ok, want)
	}
}

// The same production loop, with ring-buffer drops: the footer keeps the
// numbers but marks them as a lower bound instead of passing them for exact.
func TestHeadlessParquetFooterMarksLowerBoundsUnderRingbufDrops(t *testing.T) {
	for _, tc := range []struct {
		name string
		loss func(*eventLoop)
	}{
		{"ring-buffer drops", func(el *eventLoop) { el.numRingbufDrops.Store(17) }},
		{"records discarded at stop", func(el *eventLoop) { el.numDiscardedAtStop = 5 }},
		{"records left in the kernel ring", func(el *eventLoop) { el.numLeftInKernelRing = 4096 }},
	} {
		t.Run(tc.name, func(t *testing.T) { testHeadlessParquetFooterLowerBound(t, tc.loss) })
	}
}

// testHeadlessParquetFooterLowerBound runs the headless recording with the
// given loss injected into the loop and checks the footer marks its totals.
func testHeadlessParquetFooterLowerBound(t *testing.T, loss func(*eventLoop)) {
	path := filepath.Join(t.TempDir(), "dropped.parquet")
	cfg := mustParseArgs(t, "-parquet", path, "-syscall-sampling-syscalls", "sync=4")
	useAggregateSource(t, &aggregateSourceStub{rows: [][]statsengine.SyscallAggregate{
		{{TraceID: types.SYS_ENTER_SYNC, Count: 30}},
	}}, nil)
	newLoop := func() *eventLoop {
		el, err := newHeadlessParquetEventLoop(cfg, nil, func(...any) {})
		if err != nil {
			t.Fatalf("newHeadlessParquetEventLoop() error = %v", err)
		}
		el.setCachedComm(emitOrderTestTid, "emitorder")
		loss(el)
		return el
	}
	probe := &headlessParquetRunProbe{}
	if err := runHeadlessParquetWith(cfg, fakeHeadlessParquetSetupWithLoop(t, 8, probe, path, newLoop)); err != nil {
		t.Fatalf("runHeadlessParquetWith() error = %v, want nil", err)
	}
	want := `[{"syscall":"sync","rate":4,"traced":8,"counted_only":30,"total":38,"lower_bound":true}]`
	if got, _ := parquetFooter(t, path, parquet.KeySamplingTotals); got != want {
		t.Fatalf("%s = %q; want %s", parquet.KeySamplingTotals, got, want)
	}
}

// A sampled recording whose kernel counters cannot be opened must fail to
// start rather than silently produce a file with no totals; an unsampled one
// never opens them.
func TestHeadlessParquetLoopOpensTheKernelCountsOnlyWhenSampling(t *testing.T) {
	boom := errors.New("no map")
	opened := useAggregateSource(t, nil, boom)

	if _, err := newHeadlessParquetEventLoop(mustParseArgs(t, "-parquet", "x.parquet", "-syscall-sampling-syscalls", "sync=4"), nil, func(...any) {}); !errors.Is(err, boom) {
		t.Fatalf("sampled: error = %v, want it to wrap %v", err, boom)
	}
	el, err := newHeadlessParquetEventLoop(mustParseArgs(t, "-parquet", "x.parquet"), nil, func(...any) {})
	if err != nil {
		t.Fatalf("unsampled: error = %v, want nil", err)
	}
	defer el.shutdownCommResolver()
	if *opened != 1 || el.aggregateSrc != nil {
		t.Fatalf("opened %d times, aggregateSrc = %v; want one open (the sampled run) and none wired for the unsampled run", *opened, el.aggregateSrc)
	}
}
