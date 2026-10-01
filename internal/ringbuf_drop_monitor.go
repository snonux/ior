package internal

import (
	"context"
	"fmt"
	"sync"
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
//
// Besides the poll loop, Flush reads the counter on demand: the TUI flushes it
// together with the aggregate drain at the edges of a Parquet recording, so
// drops of the last partial poll interval reach the recording before its
// footer is written, and drops of before its start are consumed (baselined)
// before it starts (task qs2).
type ringbufDropMonitor struct {
	// mu serialises every read-and-handle cycle (poll ticks, the final read
	// and Flush), so last advances in order and each delta is handled once.
	// It also guards source (once Start ran), handle and stopping.
	mu     sync.Mutex
	source ringbufDropSource
	last   uint64
	// handle is the sink Start wired; nil before Start and once retired.
	handle func(ringbufDropResult)
	// stopping is set by the stop function Start returns; the next poll cycle
	// (normally the final read) then retires the monitor under mu by clearing
	// handle and source, so a late Flush never reads a closed BPF map (the
	// same rule as aggregateDrainer).
	stopping bool
}

func newRingbufDropMonitor(source ringbufDropSource) *ringbufDropMonitor {
	return &ringbufDropMonitor{source: source}
}

// Tick reads the counter once and reports the delta since the previous Tick.
// Once Start ran it is called only under mu (pollCycle, Flush); tests call it
// directly on a monitor that was never started.
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
// last partial interval are still reported, and retires the monitor in that
// same locked cycle (see pollCycle).
func (m *ringbufDropMonitor) Start(ctx context.Context, every time.Duration, handle func(ringbufDropResult)) func() {
	if m == nil || m.source == nil {
		return func() {}
	}
	m.mu.Lock()
	m.handle = handle
	m.mu.Unlock()
	stopLoop := startPollLoop(ctx, every, m.pollCycle)
	return func() {
		m.mu.Lock()
		m.stopping = true
		m.mu.Unlock()
		stopLoop()
	}
}

// Flush reads the counter now and hands the result to the sink, under the
// same lock as the poll ticks; a no-op before Start and once retired.
func (m *ringbufDropMonitor) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushLocked()
}

// pollCycle is one poll-loop cycle: read and handle under mu and, once stop
// was requested, retire the monitor in that same critical section.
func (m *ringbufDropMonitor) pollCycle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushLocked()
	if m.stopping {
		m.handle = nil
		m.source = nil
	}
}

func (m *ringbufDropMonitor) flushLocked() {
	if m.handle != nil {
		m.handle(m.Tick())
	}
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
