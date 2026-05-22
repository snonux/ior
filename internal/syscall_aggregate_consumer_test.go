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

func TestBuildAggregateOnlyTraceIDs(t *testing.T) {
	cfg := flags.NewFlags()
	cfg.SyscallFamilySamplingRates[types.FamilyTime] = 10
	cfg.SyscallSamplingRates["futex"] = 0
	cfg.SyscallSamplingRates["clock_gettime"] = 0

	ids := buildAggregateOnlyTraceIDs(cfg)
	if _, ok := ids[types.SYS_ENTER_FUTEX]; !ok {
		t.Fatal("expected futex in aggregate-only set")
	}
	if _, ok := ids[types.SYS_ENTER_CLOCK_GETTIME]; !ok {
		t.Fatal("expected clock_gettime in aggregate-only set")
	}
	if _, ok := ids[types.SYS_ENTER_NANOSLEEP]; ok {
		t.Fatal("did not expect nanosleep in aggregate-only set")
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
	fakeMap := newFakeSyscallAggregateMap(traceID, encodeRawAggregates(t,
		rawSyscallAggregate{
			Count:         2,
			Errors:        1,
			TotalDuration: 30,
			MinDuration:   10,
			MaxDuration:   20,
			Histogram:     [8]uint64{1, 0, 1},
		},
		rawSyscallAggregate{
			Count:         3,
			TotalDuration: 90,
			MinDuration:   5,
			MaxDuration:   50,
			Histogram:     [8]uint64{0, 2, 1},
		},
	))
	consumer := &syscallAggregateConsumer{
		aggregateMap: fakeMap,
		last:         make(map[types.TraceId]rawSyscallAggregate),
	}

	rows, err := consumer.Drain()
	if err != nil {
		t.Fatalf("first Drain error: %v", err)
	}
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID:        types.TraceId(traceID),
		Count:          5,
		Errors:         1,
		TotalLatencyNs: 120,
		MinLatencyNs:   5,
		MaxLatencyNs:   50,
		LatencyHistogramNs: [8]uint64{
			1, 2, 2,
		},
	})

	fakeMap.values[traceID] = encodeRawAggregates(t,
		rawSyscallAggregate{
			Count:         4,
			Errors:        2,
			TotalDuration: 80,
			MinDuration:   4,
			MaxDuration:   40,
			Histogram:     [8]uint64{2, 1, 1},
		},
		rawSyscallAggregate{
			Count:         3,
			TotalDuration: 110,
			MinDuration:   5,
			MaxDuration:   70,
			Histogram:     [8]uint64{0, 2, 1, 1},
		},
	)
	rows, err = consumer.Drain()
	if err != nil {
		t.Fatalf("second Drain error: %v", err)
	}
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID:        types.TraceId(traceID),
		Count:          2,
		Errors:         1,
		TotalLatencyNs: 70,
		MinLatencyNs:   4,
		MaxLatencyNs:   70,
		LatencyHistogramNs: [8]uint64{
			1, 1, 0, 1,
		},
	})

	fakeMap.values[traceID] = encodeRawAggregates(t,
		rawSyscallAggregate{
			Count:         5,
			Errors:        2,
			TotalDuration: 100,
			MinDuration:   4,
			MaxDuration:   40,
			Histogram:     [8]uint64{3, 1, 1},
		},
		rawSyscallAggregate{
			Count:         3,
			TotalDuration: 110,
			MinDuration:   5,
			MaxDuration:   70,
			Histogram:     [8]uint64{0, 2, 1, 1},
		},
	)
	rows, err = consumer.Drain()
	if err != nil {
		t.Fatalf("third Drain error: %v", err)
	}
	assertAggregateRows(t, rows, statsengine.SyscallAggregate{
		TraceID:        types.TraceId(traceID),
		Count:          1,
		Errors:         0,
		TotalLatencyNs: 20,
		MinLatencyNs:   0,
		MaxLatencyNs:   999,
		LatencyHistogramNs: [8]uint64{
			1,
		},
	})

	rows, err = consumer.Drain()
	if err != nil {
		t.Fatalf("fourth Drain error: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("fourth Drain rows = %+v, want none for zero delta", rows)
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
