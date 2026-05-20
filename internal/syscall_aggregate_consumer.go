package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
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

type rawSyscallAggregate struct {
	Count         uint64
	Errors        uint64
	TotalDuration uint64
	MinDuration   uint64
	MaxDuration   uint64
	Histogram     [8]uint64
}

type syscallAggregateConsumer struct {
	aggregateMap *bpf.BPFMap
}

func newSyscallAggregateConsumer(module *bpf.Module) (*syscallAggregateConsumer, error) {
	if module == nil {
		return nil, errors.New("nil bpf module")
	}
	aggregateMap, err := module.GetMap(syscallAggregateMapName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", syscallAggregateMapName, err)
	}
	return &syscallAggregateConsumer{aggregateMap: aggregateMap}, nil
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
		valueRaw, err := c.aggregateMap.GetValueAndDeleteKey(unsafe.Pointer(&key))
		if err != nil {
			if errors.Is(err, syscall.ENOENT) {
				continue
			}
			return nil, fmt.Errorf("drain aggregate for trace id %d: %w", key, err)
		}
		raw, err := decodeRawSyscallAggregate(valueRaw)
		if err != nil {
			return nil, fmt.Errorf("decode aggregate for trace id %d: %w", key, err)
		}
		rows = append(rows, statsengine.SyscallAggregate{
			TraceID:            types.TraceId(key),
			Count:              raw.Count,
			Errors:             raw.Errors,
			TotalLatencyNs:     raw.TotalDuration,
			MinLatencyNs:       raw.MinDuration,
			MaxLatencyNs:       raw.MaxDuration,
			LatencyHistogramNs: raw.Histogram,
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
	for syscallName, rate := range cfg.SyscallSamplingRates {
		enterID, ok := types.EnterTraceIDByName(syscallName)
		if !ok {
			continue
		}
		rates[enterID] = rate
	}
	return rates
}

func buildAggregateOnlyTraceIDs(cfg flags.Config) map[types.TraceId]struct{} {
	ids := make(map[types.TraceId]struct{})
	for traceID, rate := range buildSyscallSamplingRates(cfg) {
		if rate == 0 {
			ids[traceID] = struct{}{}
		}
	}
	return ids
}
