package internal

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ringbufDropResult is one observation of the kernel-side drop counter.
// total is the cumulative count since the BPF program was loaded, delta the
// increase since the previous observation, and warning is set instead of the
// counters when the counter could not be read.
//
// The skipped fields are the same observation of the other counter, the
// program runs the kernel skipped (skippedRunSource): skippedCounted says
// that the source has such a counter and that it was read, skipped and
// skippedDelta are its total and increase, and skippedWarning is set instead
// when it could not be read. The two counters are read apart and reported
// apart: a result may carry a ring-buffer total next to a skippedWarning, or
// the reverse. All of them are zero with a source that counts no skipped
// runs.
type ringbufDropResult struct {
	total   uint64
	delta   uint64
	warning string

	skippedCounted bool
	skipped        uint64
	skippedDelta   uint64
	skippedWarning string
}

// lost reports whether the observation gives a reason to think records are
// missing since the previous one: a counter that grew, or one that could not
// be read. A skipped run counts although it only says that a record MAY be
// missing (skippedRunCounter): what is marked or refreshed on the strength
// of it errs towards saying less or reading more.
func (r ringbufDropResult) lost() bool {
	return r.grew() || r.warning != "" || r.skippedWarning != ""
}

// grew reports whether either counter moved since the previous observation.
func (r ringbufDropResult) grew() bool {
	return r.delta > 0 || r.skippedDelta > 0
}

// ringbufDropMonitor polls the kernel-side ring-buffer drop counter and turns
// it into per-interval deltas. A non-zero delta means the kernel could not
// reserve ring-buffer space, which is how userspace backpressure manifests:
// the libbpfgo ring-buffer callback blocks on a full Go channel, event_map
// fills up, and bpf_ringbuf_reserve() starts returning NULL. With a source
// that counts them (skippedRunSource) it polls the program runs the kernel
// skipped as well, which may lose a record without any backpressure, and
// reports them beside the drops (ringbufDropResult).
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
	// lastSkipped is last for the skipped program runs.
	lastSkipped uint64
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

// Tick reads the counters once and reports the deltas since the previous
// Tick. Once Start ran it is called only under mu (pollCycle, Flush); tests
// call it directly on a monitor that was never started.
func (m *ringbufDropMonitor) Tick() ringbufDropResult {
	if m == nil || m.source == nil {
		return ringbufDropResult{}
	}
	var result ringbufDropResult
	total, err := m.source.Total()
	if err != nil {
		result.warning = fmt.Sprintf("ring buffer drop counter read failed: %v", err)
	} else {
		// The per-CPU counters are monotonic, but guard against a reset (or
		// a short read) so a wrapped-looking value never produces a bogus
		// delta.
		result.total, result.delta = total, growth(m.last, total)
		m.last = total
	}
	m.tickSkippedRuns(&result)
	return result
}

// tickSkippedRuns adds the reading of the skipped program runs to result,
// for a source that counts them. It is a read of its own: whether the ring
// counter could be read decides nothing here, and a failure here leaves the
// ring-buffer fields as they are.
func (m *ringbufDropMonitor) tickSkippedRuns(result *ringbufDropResult) {
	source, ok := m.source.(skippedRunSource)
	if !ok {
		return
	}
	skipped, err := source.SkippedRuns()
	if err != nil {
		result.skippedWarning = fmt.Sprintf("skipped probe run counter read failed: %v", err)
		return
	}
	result.skippedCounted = true
	result.skipped, result.skippedDelta = skipped, growth(m.lastSkipped, skipped)
	m.lastSkipped = skipped
}

// growth returns how far a cumulative counter moved up from last to now, and
// 0 for one that went down.
func growth(last, now uint64) uint64 {
	if now > last {
		return now - last
	}
	return 0
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

// formatRingbufDropWarning renders the user-facing message for what a poll
// found lost, "" when neither counter grew. It names the cause and both the
// burst and run totals so a single stream/TUI warning row is self-contained:
// a full ring buffer for the records it refused, the kernel for the program
// runs it skipped (which a larger -mapSize does nothing about), and both
// when a poll saw both.
//
// The two parts claim different things. A ring-buffer drop is a record ior
// wanted and lost. A skipped run is counted before ior's filter and for
// every task on the host, so the text says that events MAY be missing and
// that the count is not the traced tasks' alone (skippedRunsMeaning) - with
// a -pid filter and a busy real-time task elsewhere on the CPU, all of it
// can be other tasks' runs.
func formatRingbufDropWarning(result ringbufDropResult) string {
	var parts []string
	if result.delta > 0 {
		parts = append(parts, fmt.Sprintf(
			"Ring buffer full: %d events dropped kernel-side (%d total this run) - consider a larger -mapSize",
			result.delta, result.total,
		))
	}
	if result.skippedDelta > 0 {
		parts = append(parts, fmt.Sprintf(
			"Kernel skipped %d probe runs (%d total this run): %s - "+
				"a task was preempted inside a BPF program or map operation",
			result.skippedDelta, result.skipped, skippedRunsMeaning,
		))
	}
	return strings.Join(parts, "; ")
}
