package internal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

// ringbufDropMapName is the single-slot PERCPU_ARRAY declared in
// internal/c/maps.h. Every generated tracepoint handler bumps this CPU's slot
// when bpf_ringbuf_reserve() returns NULL, i.e. when an event is lost because
// event_map is full (audit findings D2 F1 / D9 Y2).
const ringbufDropMapName = "ringbuf_drop_map"

// ringbufDropValueStride is the per-CPU element stride libbpfgo returns for a
// __u64 per-CPU value: the element size rounded up to 8 bytes.
const ringbufDropValueStride = 8

// ringbufDropValueMap is the minimal read surface of the kernel drop-counter
// map, so tests can exercise the decoding without a live BPF module.
type ringbufDropValueMap interface {
	GetValue(unsafe.Pointer) ([]byte, error)
}

// ringbufDropCounter reads the kernel-side ring-buffer drop counter.
type ringbufDropCounter struct {
	dropMap ringbufDropValueMap
}

func newRingbufDropCounter(module *bpf.Module) (*ringbufDropCounter, error) {
	if module == nil {
		return nil, errors.New("nil bpf module")
	}
	dropMap, err := module.GetMap(ringbufDropMapName)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", ringbufDropMapName, err)
	}
	return &ringbufDropCounter{dropMap: dropMap}, nil
}

// Total returns the cumulative number of events dropped kernel-side since the
// program was loaded, summed over all CPUs. The counter is monotonic: each
// per-CPU slot is only ever incremented by its own CPU.
func (c *ringbufDropCounter) Total() (uint64, error) {
	if c == nil || c.dropMap == nil {
		return 0, nil
	}
	key := uint32(0)
	raw, err := c.dropMap.GetValue(unsafe.Pointer(&key))
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", ringbufDropMapName, err)
	}
	return sumPerCPUCounters(raw)
}

// sumPerCPUCounters adds up the little-endian __u64 counters libbpfgo returns
// for a per-CPU map value (one element per possible CPU, 8-byte stride).
func sumPerCPUCounters(raw []byte) (uint64, error) {
	if len(raw) == 0 || len(raw)%ringbufDropValueStride != 0 {
		return 0, fmt.Errorf("invalid per-cpu drop counter size %d (want a non-zero multiple of %d)", len(raw), ringbufDropValueStride)
	}
	var total uint64
	for offset := 0; offset+ringbufDropValueStride <= len(raw); offset += ringbufDropValueStride {
		total += binary.LittleEndian.Uint64(raw[offset : offset+ringbufDropValueStride])
	}
	return total, nil
}
