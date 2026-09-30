package internal

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"ior/internal/flags"
	"ior/internal/statsengine"
	"ior/internal/types"
)

// aggregateDrainStep is one Drain of TestSyscallAggregateConsumerDrainEmitsDeltas:
// the per-CPU cumulative values to load first (nil keeps the map unchanged)
// and the delta row Drain must emit (nil means no row at all).
type aggregateDrainStep struct {
	name   string
	perCPU []rawSyscallAggregate
	want   *statsengine.SyscallAggregate
}

func TestBuildSyscallSamplingRatesFamilyAndSyscallOverride(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 100
	cfg.SyscallSamplingRates["clock_gettime"] = 3

	rates := buildSyscallSamplingRates(cfg)
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 100 {
		t.Fatalf("nanosleep rate = %d, want 100", got)
	}
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 3 {
		t.Fatalf("clock_gettime rate = %d, want 3", got)
	}
}

// TestBuildSyscallSamplingRatesPromotesFamilyZerosInRawModes locks audit
// domain-06 F2: raw output modes have no aggregate sink, so an explicit
// family rate of 0 (aggregate-only) must be promoted to 1 instead of
// silently erasing the family's events from the output.
func TestBuildSyscallSamplingRatesPromotesFamilyZerosInRawModes(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PlainMode = true
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 0

	rates := buildSyscallSamplingRates(cfg)
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 1 {
		t.Fatalf("nanosleep rate = %d, want 1 (family zero promoted in raw mode)", got)
	}
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 1 {
		t.Fatalf("clock_gettime rate = %d, want 1 (family zero promoted in raw mode)", got)
	}
}

// TestBuildSyscallSamplingRatesPreservesExplicitSyscallZerosInRawModes
// locks the precedence: the family promotion must never override an explicit
// -syscall-sampling-syscalls rate.
func TestBuildSyscallSamplingRatesPreservesExplicitSyscallZerosInRawModes(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.PlainMode = true
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 0
	cfg.SyscallSamplingRates["nanosleep"] = 0
	cfg.SyscallSamplingRates["clock_gettime"] = 2

	rates := buildSyscallSamplingRates(cfg)
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 0 {
		t.Fatalf("nanosleep rate = %d, want 0 (explicit per-syscall override)", got)
	}
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 2 {
		t.Fatalf("clock_gettime rate = %d, want 2 (explicit per-syscall override)", got)
	}
}

// TestBuildSyscallSamplingRatesKeepsFamilyZerosInTUIMode locks the TUI side of
// the same contract: with an aggregate sink available, an explicit family rate
// of 0 stays 0 (aggregate-only) exactly as the user asked.
func TestBuildSyscallSamplingRatesKeepsFamilyZerosInTUIMode(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 0

	rates := buildSyscallSamplingRates(cfg)
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 0 {
		t.Fatalf("nanosleep rate = %d, want 0 (aggregate-only in TUI mode)", got)
	}
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 0 {
		t.Fatalf("clock_gettime rate = %d, want 0 (aggregate-only in TUI mode)", got)
	}
}

// samplingRatesFromCLI resolves the per-trace-ID sampling rates for a config
// produced by the real CLI path (flags.ParseArgs), which — unlike
// flags.NewFlags() — carries the built-in futex*/clock_gettime defaults. The
// hand-built configs above missed that defaults used to override explicit
// family rates.
func samplingRatesFromCLI(t *testing.T, args ...string) map[types.TraceId]uint32 {
	t.Helper()
	cfg, err := flags.ParseArgs(args)
	if err != nil {
		t.Fatalf("ParseArgs(%v): %v", args, err)
	}
	return buildSyscallSamplingRates(cfg)
}

// TestBuildSyscallSamplingRatesFamilyRateBeatsBuiltInDefaults locks task jq2:
// an explicit -syscall-sampling-families rate must reach the syscalls that
// carry a built-in aggregate-only default (clock_gettime in Time, futex* in
// IPC), in TUI and raw modes alike.
func TestBuildSyscallSamplingRatesFamilyRateBeatsBuiltInDefaults(t *testing.T) {
	cases := []struct {
		name string
		args []string
		id   types.TraceId
		want uint32
	}{
		{"Time=100 reaches clock_gettime (help example)", []string{"-syscall-sampling-families", "Time=100"}, types.SYS_ENTER_CLOCK_GETTIME, 100},
		{"Time=100 raw mode", []string{"-plain", "-syscall-sampling-families", "Time=100"}, types.SYS_ENTER_CLOCK_GETTIME, 100},
		{"IPC=1 reaches futex in TUI mode", []string{"-syscall-sampling-families", "IPC=1"}, types.SYS_ENTER_FUTEX, 1},
		{"IPC=7 reaches futex", []string{"-syscall-sampling-families", "IPC=7"}, types.SYS_ENTER_FUTEX, 7},
		{"IPC=0 keeps futex aggregate-only in TUI mode", []string{"-syscall-sampling-families", "IPC=0"}, types.SYS_ENTER_FUTEX, 0},
		{"IPC=0 is promoted to 1 in raw mode", []string{"-flamegraph", "-syscall-sampling-families", "IPC=0"}, types.SYS_ENTER_FUTEX, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rates := samplingRatesFromCLI(t, tc.args...)
			if got, ok := rates[tc.id]; !ok || got != tc.want {
				t.Fatalf("%s rate = %d (present %v), want %d", tc.id.String(), got, ok, tc.want)
			}
		})
	}
}

// TestBuildSyscallSamplingRatesExplicitSyscallBeatsFamilyAndDefault checks the
// top of the precedence chain through the CLI: an explicit syscall rate wins
// over both the family rate and the built-in default, and its family siblings
// still follow the family rate.
func TestBuildSyscallSamplingRatesExplicitSyscallBeatsFamilyAndDefault(t *testing.T) {
	rates := samplingRatesFromCLI(t,
		"-syscall-sampling-families", "Time=100",
		"-syscall-sampling-syscalls", "clock_gettime=3")
	if got := rates[types.SYS_ENTER_CLOCK_GETTIME]; got != 3 {
		t.Fatalf("clock_gettime rate = %d, want 3 (explicit syscall rate)", got)
	}
	if got := rates[types.SYS_ENTER_NANOSLEEP]; got != 100 {
		t.Fatalf("nanosleep rate = %d, want 100 (family rate)", got)
	}
}

// TestBuildSyscallSamplingRatesBuiltInDefaultsWithoutFamilyRate is the negative
// case: with no family or syscall rate for their family, the built-in defaults
// still apply (aggregate-only in TUI mode, promoted to 1 in raw modes), and an
// unrelated family rate does not disturb them.
func TestBuildSyscallSamplingRatesBuiltInDefaultsWithoutFamilyRate(t *testing.T) {
	rates := samplingRatesFromCLI(t, "-syscall-sampling-families", "FS=5")
	for _, id := range []types.TraceId{types.SYS_ENTER_FUTEX, types.SYS_ENTER_CLOCK_GETTIME} {
		if got, ok := rates[id]; !ok || got != 0 {
			t.Fatalf("%s TUI rate = %d (present %v), want built-in 0", id.String(), got, ok)
		}
	}
	rates = samplingRatesFromCLI(t, "-plain", "-syscall-sampling-families", "FS=5")
	for _, id := range []types.TraceId{types.SYS_ENTER_FUTEX, types.SYS_ENTER_CLOCK_GETTIME} {
		if got := rates[id]; got != 1 {
			t.Fatalf("%s raw-mode rate = %d, want promoted 1", id.String(), got)
		}
	}
	// An explicit zero on a defaulted syscall stays zero in raw mode.
	rates = samplingRatesFromCLI(t, "-plain", "-syscall-sampling-syscalls", "futex=0")
	if got := rates[types.SYS_ENTER_FUTEX]; got != 0 {
		t.Fatalf("explicit futex=0 in raw mode = %d, want 0", got)
	}
}

// TestBuildAggregateIngestTraceIDsCoversAggregateOnlyAndSampled locks the fix
// for the sampled-count under-report: the ingest set must contain every
// syscall whose sampling rate is not 1 — aggregate-only (0) and sampled
// 1-in-N (N>1) alike — because the kernel aggregates exactly the events it
// does not emit. Fully traced (rate 1) syscalls must stay out of the set.
func TestBuildAggregateIngestTraceIDsCoversAggregateOnlyAndSampled(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 10
	cfg.SyscallSamplingRates["futex"] = 0
	cfg.SyscallSamplingRates["clock_gettime"] = 0
	cfg.SyscallSamplingRates["read"] = 1

	ids := buildAggregateIngestTraceIDs(cfg)
	if _, ok := ids[types.SYS_ENTER_FUTEX]; !ok {
		t.Fatal("expected futex (rate 0) in aggregate ingest set")
	}
	if _, ok := ids[types.SYS_ENTER_CLOCK_GETTIME]; !ok {
		t.Fatal("expected clock_gettime (rate 0) in aggregate ingest set")
	}
	if _, ok := ids[types.SYS_ENTER_NANOSLEEP]; !ok {
		t.Fatal("expected nanosleep (rate 10) in aggregate ingest set: sampled syscalls need their kernel counts merged")
	}
	if _, ok := ids[types.SYS_ENTER_READ]; ok {
		t.Fatal("did not expect read (rate 1) in aggregate ingest set: fully traced syscalls are counted per event")
	}
	if _, ok := ids[types.SYS_ENTER_WRITE]; ok {
		t.Fatal("did not expect write (unconfigured, kernel default rate 1) in aggregate ingest set")
	}
}

func TestDecodeRawSyscallAggregate(t *testing.T) {
	want := rawSyscallAggregate{
		Count:         7,
		Errors:        2,
		TotalDuration: 1234,
		MinDuration:   12,
		MaxDuration:   456,
		Histogram:     [8]uint64{1, 2, 3, 4, 5, 6, 7, 8},
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, want); err != nil {
		t.Fatalf("binary write: %v", err)
	}

	got, err := decodeRawSyscallAggregate(buf.Bytes())
	if err != nil {
		t.Fatalf("decodeRawSyscallAggregate error: %v", err)
	}
	if got != want {
		t.Fatalf("decoded aggregate = %+v, want %+v", got, want)
	}
}

func TestDecodeRawSyscallAggregateRejectsBadSize(t *testing.T) {
	if _, err := decodeRawSyscallAggregate([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short value")
	}
}

func TestDecodeRawSyscallAggregatePerCPUSumsActiveCPUs(t *testing.T) {
	raw := encodeRawAggregates(t,
		rawSyscallAggregate{
			Count:         2,
			Errors:        1,
			TotalDuration: 30,
			MinDuration:   10,
			MaxDuration:   20,
			Histogram:     [8]uint64{1, 0, 1},
		},
		rawSyscallAggregate{},
		rawSyscallAggregate{
			Count:         3,
			Errors:        0,
			TotalDuration: 90,
			MinDuration:   5,
			MaxDuration:   50,
			Histogram:     [8]uint64{0, 2, 1},
		},
	)

	got, err := decodeRawSyscallAggregatePerCPU(raw)
	if err != nil {
		t.Fatalf("decodeRawSyscallAggregatePerCPU error: %v", err)
	}

	want := rawSyscallAggregate{
		Count:         5,
		Errors:        1,
		TotalDuration: 120,
		MinDuration:   5,
		MaxDuration:   50,
		Histogram:     [8]uint64{1, 2, 2},
	}
	if got != want {
		t.Fatalf("per-cpu aggregate = %+v, want %+v", got, want)
	}
}

func TestDecodeRawSyscallAggregatePerCPURejectsBadSize(t *testing.T) {
	raw := encodeRawAggregates(t, rawSyscallAggregate{Count: 1})
	raw = append(raw, 0)

	if _, err := decodeRawSyscallAggregatePerCPU(raw); err == nil {
		t.Fatal("expected error for non-stride-aligned value")
	}
}

func TestDecodeRawSyscallAggregatePerCPURejectsEmptyValue(t *testing.T) {
	if _, err := decodeRawSyscallAggregatePerCPU(nil); err == nil {
		t.Fatal("expected error for empty per-cpu value")
	}
}

func TestSyscallAggregateConsumerDrainEmitsDeltas(t *testing.T) {
	const traceID = uint32(types.SYS_ENTER_FUTEX)
	steps := syscallAggregateDrainSteps(types.TraceId(traceID))
	fakeMap := newFakeSyscallAggregateMap(traceID, encodeRawAggregates(t, steps[0].perCPU...))
	consumer := &syscallAggregateConsumer{
		aggregateMap: fakeMap,
		last:         make(map[types.TraceId]rawSyscallAggregate),
	}

	for i, step := range steps {
		if i > 0 && step.perCPU != nil {
			fakeMap.values[traceID] = encodeRawAggregates(t, step.perCPU...)
		}
		rows, err := consumer.Drain()
		if err != nil {
			t.Fatalf("%s Drain error: %v", step.name, err)
		}
		if step.want == nil {
			if len(rows) != 0 {
				t.Fatalf("%s Drain rows = %+v, want none for zero delta", step.name, rows)
			}
			continue
		}
		assertAggregateRows(t, rows, *step.want)
	}
}

// syscallAggregateDrainSteps is the per-CPU cumulative map content before each
// Drain of TestSyscallAggregateConsumerDrainEmitsDeltas and the delta row that
// Drain must emit for traceID.
func syscallAggregateDrainSteps(traceID types.TraceId) []aggregateDrainStep {
	return []aggregateDrainStep{
		{
			name: "first",
			perCPU: []rawSyscallAggregate{
				{Count: 2, Errors: 1, TotalDuration: 30, MinDuration: 10, MaxDuration: 20, Histogram: [8]uint64{1, 0, 1}},
				{Count: 3, TotalDuration: 90, MinDuration: 5, MaxDuration: 50, Histogram: [8]uint64{0, 2, 1}},
			},
			want: &statsengine.SyscallAggregate{
				TraceID: traceID, Count: 5, Errors: 1, TotalLatencyNs: 120, MinLatencyNs: 5, MaxLatencyNs: 50,
				LatencyHistogramNs: [8]uint64{1, 2, 2},
			},
		},
		{
			// The second CPU's slot gained one timed invocation (histogram 3 -> 4),
			// so it gained one count as well: a slot's count is never below its
			// histogram total.
			name: "second",
			perCPU: []rawSyscallAggregate{
				{Count: 4, Errors: 2, TotalDuration: 80, MinDuration: 4, MaxDuration: 40, Histogram: [8]uint64{2, 1, 1}},
				{Count: 4, TotalDuration: 110, MinDuration: 5, MaxDuration: 70, Histogram: [8]uint64{0, 2, 1, 1}},
			},
			want: &statsengine.SyscallAggregate{
				TraceID: traceID, Count: 3, Errors: 1, TotalLatencyNs: 70, MinLatencyNs: 4, MaxLatencyNs: 70,
				LatencyHistogramNs: [8]uint64{1, 1, 0, 1},
			},
		},
		{
			// Unchanged cumulative extrema fall back to the delta's bucket bounds
			// (bucket 0: 0..999), clamped to the merged cumulative range 4..70.
			name: "third",
			perCPU: []rawSyscallAggregate{
				{Count: 5, Errors: 2, TotalDuration: 100, MinDuration: 4, MaxDuration: 40, Histogram: [8]uint64{3, 1, 1}},
				{Count: 4, TotalDuration: 110, MinDuration: 5, MaxDuration: 70, Histogram: [8]uint64{0, 2, 1, 1}},
			},
			want: &statsengine.SyscallAggregate{
				TraceID: traceID, Count: 1, Errors: 0, TotalLatencyNs: 20, MinLatencyNs: 4, MaxLatencyNs: 70,
				LatencyHistogramNs: [8]uint64{1},
			},
		},
		// An unchanged map yields a zero delta and therefore no row.
		{name: "fourth"},
	}
}

func TestRawSyscallAggregateDiffReturnsOnlyNewCounts(t *testing.T) {
	prev := rawSyscallAggregate{
		Count:         5,
		Errors:        1,
		TotalDuration: 100,
		MinDuration:   10,
		MaxDuration:   40,
		Histogram:     [8]uint64{1, 2, 2},
	}
	current := rawSyscallAggregate{
		Count:         9,
		Errors:        3,
		TotalDuration: 190,
		MinDuration:   5,
		MaxDuration:   80,
		Histogram:     [8]uint64{2, 5, 2, 1},
	}

	got := current.diff(prev)
	want := rawSyscallAggregate{
		Count:         4,
		Errors:        2,
		TotalDuration: 90,
		MinDuration:   5,
		MaxDuration:   80,
		Histogram:     [8]uint64{1, 3, 0, 1},
	}
	if got != want {
		t.Fatalf("aggregate diff = %+v, want %+v", got, want)
	}
}

func encodeRawAggregates(t *testing.T, values ...rawSyscallAggregate) []byte {
	t.Helper()

	var buf bytes.Buffer
	for _, value := range values {
		if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
			t.Fatalf("binary write: %v", err)
		}
	}
	return buf.Bytes()
}

func assertAggregateRows(t *testing.T, got []statsengine.SyscallAggregate, want statsengine.SyscallAggregate) {
	t.Helper()

	if len(got) != 1 {
		t.Fatalf("Drain rows = %+v, want one row", got)
	}
	if got[0] != want {
		t.Fatalf("Drain row = %+v, want %+v", got[0], want)
	}
}

type fakeSyscallAggregateMap struct {
	keys   [][]byte
	values map[uint32][]byte
}

func newFakeSyscallAggregateMap(traceID uint32, value []byte) *fakeSyscallAggregateMap {
	key := make([]byte, 4)
	binary.LittleEndian.PutUint32(key, traceID)
	return &fakeSyscallAggregateMap{
		keys: [][]byte{key},
		values: map[uint32][]byte{
			traceID: value,
		},
	}
}

func (m *fakeSyscallAggregateMap) Iterator() syscallAggregateIterator {
	return &fakeSyscallAggregateIterator{keys: m.keys}
}

func (m *fakeSyscallAggregateMap) GetValue(keyPtr unsafe.Pointer) ([]byte, error) {
	key := *(*uint32)(keyPtr)
	value, ok := m.values[key]
	if !ok {
		return nil, fmt.Errorf("missing value for key %d", key)
	}
	return append([]byte(nil), value...), nil
}

type fakeSyscallAggregateIterator struct {
	keys [][]byte
	next int
}

func (i *fakeSyscallAggregateIterator) Next() bool {
	if i.next >= len(i.keys) {
		return false
	}
	i.next++
	return i.next <= len(i.keys)
}

func (i *fakeSyscallAggregateIterator) Key() []byte {
	if i.next == 0 || i.next > len(i.keys) {
		return nil
	}
	return i.keys[i.next-1]
}

func (i *fakeSyscallAggregateIterator) Err() error {
	return nil
}
