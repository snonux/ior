package internal

import (
	"context"
	"fmt"
	"time"
)

// ringbufDropResult is one observation of the kernel-side drop counter.
// total is the cumulative count since the BPF program was loaded, delta the
// increase since the previous observation, and warning is set instead of the
// counters when the counter could not be read.
type ringbufDropResult struct {
	total   uint64
	delta   uint64
	warning string
}

// ringbufDropMonitor polls the kernel-side ring-buffer drop counter and turns
// it into per-interval deltas. A non-zero delta means the kernel could not
// reserve ring-buffer space, which is how userspace backpressure manifests:
// the libbpfgo ring-buffer callback blocks on a full Go channel, event_map
// fills up, and bpf_ringbuf_reserve() starts returning NULL.
type ringbufDropMonitor struct {
	source ringbufDropSource
	last   uint64
}

func newRingbufDropMonitor(source ringbufDropSource) *ringbufDropMonitor {
	return &ringbufDropMonitor{source: source}
}

// Tick reads the counter once and reports the delta since the previous Tick.
func (m *ringbufDropMonitor) Tick() ringbufDropResult {
	if m == nil || m.source == nil {
		return ringbufDropResult{}
	}
	total, err := m.source.Total()
	if err != nil {
		return ringbufDropResult{warning: fmt.Sprintf("ring buffer drop counter read failed: %v", err)}
	}
	// The per-CPU counters are monotonic, but guard against a reset (or a
	// short read) so a wrapped-looking value never produces a bogus delta.
	delta := uint64(0)
	if total > m.last {
		delta = total - m.last
	}
	m.last = total
	return ringbufDropResult{total: total, delta: delta}
}

// Start polls the counter every `every` until ctx is cancelled or the returned
// stop function runs; stop performs one final read so drops occurring in the
// last partial interval are still reported.
func (m *ringbufDropMonitor) Start(ctx context.Context, every time.Duration, handle func(ringbufDropResult)) func() {
	if m == nil || m.source == nil {
		return func() {}
	}
	return startPollLoop(ctx, every, func() { handle(m.Tick()) })
}

// formatRingbufDropWarning renders the user-facing message for a drop burst.
// It names the cause (a full ring buffer) and both the burst and run totals so
// a single stream/TUI warning row is self-contained.
func formatRingbufDropWarning(result ringbufDropResult) string {
	return fmt.Sprintf(
		"Ring buffer full: %d events dropped kernel-side (%d total this run) - consider a larger -mapSize",
		result.delta, result.total,
	)
}
