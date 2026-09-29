package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"ior/internal/flags"
	"ior/internal/statsengine"
	"ior/internal/types"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	syscallAggregateMapName    = "syscall_aggregate_map"
	syscallSamplingRateMapName = "syscall_sampling_rate_map"
)

var syscallAggregateLatencyBucketLowerNs = [8]uint64{
	0,
	1_000,
	10_000,
	100_000,
	1_000_000,
	10_000_000,
	100_000_000,
	1_000_000_000,
}

var syscallAggregateLatencyBucketUpperNs = [8]uint64{
	1_000,
	10_000,
	100_000,
	1_000_000,
	10_000_000,
	100_000_000,
	1_000_000_000,
	0,
}

type rawSyscallAggregate struct {
	Count         uint64
	Errors        uint64
	TotalDuration uint64
	MinDuration   uint64
	MaxDuration   uint64
	Histogram     [8]uint64
}

type syscallAggregateConsumer struct {
	aggregateMap syscallAggregateMap
	last         map[types.TraceId]rawSyscallAggregate
}

type syscallAggregateMap interface {
	Iterator() syscallAggregateIterator
	GetValue(unsafe.Pointer) ([]byte, error)
}

type syscallAggregateIterator interface {
	Next() bool
	Key() []byte
	Err() error
}

type bpfSyscallAggregateMap struct {
	*bpf.BPFMap
}

func (m bpfSyscallAggregateMap) Iterator() syscallAggregateIterator {
	return m.BPFMap.Iterator()
}

func newSyscallAggregateConsumer(module *bpf.Module) (*syscallAggregateConsumer, error) {
	if module == nil {
		return nil, errors.New("nil bpf module")
	}
	aggregateMap, err := module.GetMap(syscallAggregateMapName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", syscallAggregateMapName, err)
	}
	return &syscallAggregateConsumer{
		aggregateMap: bpfSyscallAggregateMap{BPFMap: aggregateMap},
		last:         make(map[types.TraceId]rawSyscallAggregate),
	}, nil
}

func (c *syscallAggregateConsumer) Drain() ([]statsengine.SyscallAggregate, error) {
	if c == nil || c.aggregateMap == nil {
		return nil, nil
	}

	iter := c.aggregateMap.Iterator()
	rows := make([]statsengine.SyscallAggregate, 0, 64)
	for iter.Next() {
		keyRaw := append([]byte(nil), iter.Key()...)
		if len(keyRaw) != 4 {
			continue
		}
		key := binary.LittleEndian.Uint32(keyRaw)
		valueRaw, err := c.aggregateMap.GetValue(unsafe.Pointer(&key))
		if err != nil {
			return nil, fmt.Errorf("drain aggregate for trace id %d: %w", key, err)
		}
		raw, err := decodeRawSyscallAggregateValue(valueRaw)
		if err != nil {
			return nil, fmt.Errorf("decode aggregate for trace id %d: %w", key, err)
		}
		traceID := types.TraceId(key)
		delta := raw.diff(c.last[traceID])
		c.last[traceID] = raw
		if delta.Count == 0 {
			continue
		}
		rows = append(rows, statsengine.SyscallAggregate{
			TraceID:            traceID,
			Count:              delta.Count,
			Errors:             delta.Errors,
			TotalLatencyNs:     delta.TotalDuration,
			MinLatencyNs:       delta.MinDuration,
			MaxLatencyNs:       delta.MaxDuration,
			LatencyHistogramNs: delta.Histogram,
			UntimedCount:       delta.untimedCount(),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", syscallAggregateMapName, err)
	}
	return rows, nil
}

func decodeRawSyscallAggregate(raw []byte) (rawSyscallAggregate, error) {
	var out rawSyscallAggregate
	expectedSize := binary.Size(out)
	if len(raw) != expectedSize {
		return rawSyscallAggregate{}, fmt.Errorf("invalid aggregate value size %d (want %d)", len(raw), expectedSize)
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &out); err != nil {
		return rawSyscallAggregate{}, err
	}
	return out, nil
}

func decodeRawSyscallAggregateValue(raw []byte) (rawSyscallAggregate, error) {
	var sample rawSyscallAggregate
	valueSize := binary.Size(sample)
	if len(raw) == valueSize {
		return decodeRawSyscallAggregate(raw)
	}
	return decodeRawSyscallAggregatePerCPU(raw)
}

func decodeRawSyscallAggregatePerCPU(raw []byte) (rawSyscallAggregate, error) {
	var sample rawSyscallAggregate
	valueSize := binary.Size(sample)
	stride := roundUp(valueSize, 8)
	if valueSize <= 0 || stride <= 0 || len(raw) == 0 || len(raw)%stride != 0 {
		return rawSyscallAggregate{}, fmt.Errorf("invalid per-cpu aggregate value size %d (element size %d, stride %d)", len(raw), valueSize, stride)
	}

	var out rawSyscallAggregate
	for offset := 0; offset < len(raw); offset += stride {
		next, err := decodeRawSyscallAggregate(raw[offset : offset+valueSize])
		if err != nil {
			return rawSyscallAggregate{}, err
		}
		out = out.add(next)
	}
	return out, nil
}

func roundUp(value, alignment int) int {
	if alignment <= 0 {
		return value
	}
	remainder := value % alignment
	if remainder == 0 {
		return value
	}
	return value + alignment - remainder
}

// timedCount returns how many of r's invocations carry a measured duration.
// Every timed kernel update bumps exactly one histogram bucket, while an
// invocation counted by ior_count_untimed_syscall (internal/c/filter.c, the
// fallback for a failed syscall_enter_state_map write) bumps only Count.
func (r rawSyscallAggregate) timedCount() uint64 {
	var timed uint64
	for _, bucket := range r.Histogram {
		timed += bucket
	}
	return timed
}

// untimedCount returns how many of r's invocations have no duration: Count
// minus the histogram total, saturating at zero.
func (r rawSyscallAggregate) untimedCount() uint64 {
	return subtractU64(r.Count, r.timedCount())
}

// add merges one CPU's slot of the per-CPU aggregate into r. Min/max come only
// from slots with timed invocations: a slot holding nothing but untimed counts
// carries min = max = 0, which are not latencies and would otherwise pin the
// merged minimum to zero. Likewise r's own min is replaced, not compared, as
// long as r has no timed invocation yet.
func (r rawSyscallAggregate) add(next rawSyscallAggregate) rawSyscallAggregate {
	if next.Count == 0 {
		return r
	}
	if next.timedCount() > 0 {
		if r.timedCount() == 0 || next.MinDuration < r.MinDuration {
			r.MinDuration = next.MinDuration
		}
		if next.MaxDuration > r.MaxDuration {
			r.MaxDuration = next.MaxDuration
		}
	}
	r.Count += next.Count
	r.Errors += next.Errors
	r.TotalDuration += next.TotalDuration
	for i, value := range next.Histogram {
		r.Histogram[i] += value
	}
	return r
}

func (r rawSyscallAggregate) diff(prev rawSyscallAggregate) rawSyscallAggregate {
	if r.Count < prev.Count || prev.Count == 0 {
		return r
	}
	histogram := diffHistogram(r.Histogram, prev.Histogram)
	minLatency, maxLatency := r.deltaExtrema(prev, histogram)
	return rawSyscallAggregate{
		Count:         r.Count - prev.Count,
		Errors:        subtractU64(r.Errors, prev.Errors),
		TotalDuration: subtractU64(r.TotalDuration, prev.TotalDuration),
		MinDuration:   minLatency,
		MaxDuration:   maxLatency,
		Histogram:     histogram,
	}
}

// deltaExtrema returns the latency extrema of the invocations r added since
// prev, whose delta histogram is histogram. Cumulative extrema only say
// something about the delta when they moved; otherwise the delta's bucket
// bounds are the best available estimate.
//
// While prev holds no timed invocation (only untimed counts, see timedCount)
// its min/max of 0 are not latencies, and every timed invocation in r is new,
// so r's own extrema are exact for the delta.
func (r rawSyscallAggregate) deltaExtrema(prev rawSyscallAggregate, histogram [8]uint64) (uint64, uint64) {
	if prev.timedCount() == 0 {
		return r.MinDuration, r.MaxDuration
	}
	minLatency, maxLatency, ok := latencyExtremaFromHistogram(histogram)
	if !ok {
		minLatency = r.MinDuration
		maxLatency = r.MaxDuration
	}
	if r.MinDuration < prev.MinDuration {
		minLatency = r.MinDuration
	}
	if r.MaxDuration > prev.MaxDuration {
		maxLatency = r.MaxDuration
	}
	return minLatency, maxLatency
}

func latencyExtremaFromHistogram(histogram [8]uint64) (minLatency uint64, maxLatency uint64, ok bool) {
	minIndex := -1
	maxIndex := -1
	for i, count := range histogram {
		if count == 0 {
			continue
		}
		if minIndex < 0 {
			minIndex = i
		}
		maxIndex = i
	}
	if minIndex < 0 {
		return 0, 0, false
	}
	minLatency = syscallAggregateLatencyBucketLowerNs[minIndex]
	maxLatency = syscallAggregateLatencyBucketUpperNs[maxIndex]
	if maxLatency == 0 {
		maxLatency = syscallAggregateLatencyBucketLowerNs[maxIndex]
	} else {
		maxLatency--
	}
	return minLatency, maxLatency, true
}

func diffHistogram(current, previous [8]uint64) [8]uint64 {
	var out [8]uint64
	for i, value := range current {
		out[i] = subtractU64(value, previous[i])
	}
	return out
}

func subtractU64(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func applySyscallSamplingRates(cfg flags.Config, module *bpf.Module) error {
	samplingMap, err := module.GetMap(syscallSamplingRateMapName)
	if err != nil {
		return fmt.Errorf("get %s: %w", syscallSamplingRateMapName, err)
	}
	for traceID, rate := range buildSyscallSamplingRates(cfg) {
		key := uint32(traceID)
		value := rate
		if err := samplingMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			return fmt.Errorf("set sampling rate for %s to %d: %w", traceID.String(), rate, err)
		}
	}
	return nil
}

func buildSyscallSamplingRates(cfg flags.Config) map[types.TraceId]uint32 {
	rates := make(map[types.TraceId]uint32)
	for _, enterID := range types.EnterTraceIDs() {
		if rate, ok := cfg.SyscallFamilySamplingRates[enterID.Family()]; ok {
			rates[enterID] = rate
		}
	}
	// Raw output modes (-plain, -flamegraph, headless -parquet) have no
	// aggregate sink, so an explicit family rate of 0 (aggregate-only)
	// would suppress every ring-buffer event for that family and silently
	// erase it from the output. Promote those family-derived zeros to 1;
	// the per-syscall entries below still override, so an explicit
	// -syscall-sampling-syscalls X=0 keeps its zero. This mirrors the
	// default-syscall promotion in flags.promoteAggregateOnlyForRawOutput.
	if cfg.IsRawOutputMode() {
		for enterID, rate := range rates {
			if rate == 0 {
				rates[enterID] = 1
			}
		}
	}
	for syscallName, rate := range cfg.SyscallSamplingRates {
		enterID, ok := types.EnterTraceIDByName(syscallName)
		if !ok {
			continue
		}
		rates[enterID] = rate
	}
	return rates
}

// buildAggregateIngestTraceIDs returns the trace IDs whose kernel aggregate
// rows must be merged into the stats engine: every syscall whose sampling rate
// is not 1, i.e. aggregate-only (rate 0) and sampled 1-in-N (rate N>1).
//
// The kernel only aggregates syscalls it does NOT emit as ring-buffer events
// (ior_on_syscall_exit in internal/c/filter.c), so the two paths are disjoint:
//   - rate 0: no events at all, the aggregate carries the whole count.
//   - rate N: the ~1/N emitted pairs are counted by per-event ingestion, the
//     remaining (N-1)/N by the aggregate — summing to the true count instead
//     of under-reporting by roughly a factor of N.
//   - rate 1: everything is emitted and the kernel writes no aggregate row at
//     all; excluding those trace IDs here keeps the gate fail-safe (a stale
//     BPF object loaded via IOR_BPF_OBJECT would under-report rather than
//     double-count).
func buildAggregateIngestTraceIDs(cfg flags.Config) map[types.TraceId]struct{} {
	ids := make(map[types.TraceId]struct{})
	for traceID, rate := range buildSyscallSamplingRates(cfg) {
		if rate != 1 {
			ids[traceID] = struct{}{}
		}
	}
	return ids
}
