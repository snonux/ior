package statsengine

import (
	"cmp"
	"math/bits"
	"slices"
	"sync"
)

// sampleBufferPool recycles the scratch buffers that Engine.Snapshot copies
// stale latency reservoirs into. Handing buffers to the capture before the
// engine lock is taken keeps allocation (and any GC assist it triggers) out of
// the lock: under the lock the capture only copies samples into ready buffers.
//
// Sizing follows demand, not the number of tracked syscalls: after each
// capture the caller records the sample count of every stale reservoir
// (recordDemand), and the next acquire hands out one buffer per recorded
// reservoir with a capacity of that count rounded up to a power of two (capped
// at bufCap), so a reservoir that is still filling up fits next time too. The
// pool is trimmed to one buffer of roughly that size per recorded reservoir
// (see trimLocked), i.e. memory proportional to the stale sample volume of the
// last capture, never 80KB per tracked syscall. A job that finds no fitting buffer falls back to
// an exact-size allocation under the lock, as the very first snapshot does.
// Unlike sync.Pool, retained buffers survive garbage collections, so a
// steady-state refresh allocates nothing.
type sampleBufferPool struct {
	mu     sync.Mutex
	bufCap int
	free   [][]uint64
	demand []int // sample counts of the stale reservoirs of the last capture
}

func newSampleBufferPool(bufCap int) *sampleBufferPool {
	return &sampleBufferPool{bufCap: bufCap}
}

// acquire returns one empty buffer per reservoir recorded by the last
// recordDemand, reusing the best-fitting pooled buffer and allocating the
// rest. It returns nil when the last capture had nothing stale. Callers must
// not hold the engine lock.
func (p *sampleBufferPool) acquire() [][]uint64 {
	p.mu.Lock()
	demand := p.demand
	out := make([][]uint64, 0, len(demand))
	var missing []int
	for _, n := range demand {
		want := p.bucketCap(n)
		if buf, ok := takeBestFit(&p.free, want); ok {
			out = append(out, buf)
			continue
		}
		missing = append(missing, want)
	}
	p.mu.Unlock()

	for _, want := range missing {
		out = append(out, make([]uint64, 0, want))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// recordDemand remembers the sample counts of the stale reservoirs a capture
// copied, which sizes the next acquire and bounds retention, and trims the
// pool to the new bound.
func (p *sampleBufferPool) recordDemand(jobs []percentileJob) {
	demand := make([]int, 0, len(jobs))
	for i := range jobs {
		demand = append(demand, len(jobs[i].samples))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.demand = demand
	p.trimLocked()
}

// release returns buffers to the pool, then trims it to the recorded demand
// so the pool shrinks again when fewer reservoirs go stale (idle syscalls,
// Reset).
func (p *sampleBufferPool) release(bufs [][]uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, buf := range bufs {
		if cap(buf) > 0 {
			p.free = append(p.free, buf[:0])
		}
	}
	p.trimLocked()
}

// retainedCap returns the total capacity (in samples) of the pooled buffers.
func (p *sampleBufferPool) retainedCap() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	for _, buf := range p.free {
		total += cap(buf)
	}
	return total
}

// trimLocked keeps, for each recorded demand entry (largest first), the
// smallest pooled buffer whose capacity lies in [bucketCap, 2*bucketCap) and
// drops everything else. Retention is thereby bounded by one suitably sized
// buffer per stale reservoir of the last capture: normally exactly the
// bucketed sizes (<= 2x the stale sample volume), in the worst case twice
// that. p.mu must be held.
func (p *sampleBufferPool) trimLocked() {
	wants := make([]int, 0, len(p.demand))
	for _, n := range p.demand {
		wants = append(wants, p.bucketCap(n))
	}
	slices.SortFunc(wants, func(a, b int) int { return cmp.Compare(b, a) })

	kept := make([][]uint64, 0, min(len(wants), len(p.free)))
	for _, want := range wants {
		buf, ok := takeBestFit(&p.free, want)
		if !ok {
			continue
		}
		if cap(buf) < 2*want {
			kept = append(kept, buf)
		}
	}
	clear(p.free)
	p.free = kept
}

// bucketCap rounds a reservoir length up to the next power of two, capped at
// bufCap (the reservoir capacity, which a full reservoir needs exactly).
func (p *sampleBufferPool) bucketCap(n int) int {
	if n <= 1 {
		return 1
	}
	return min(p.bufCap, 1<<bits.Len(uint(n-1)))
}

// takeBestFit removes and returns the buffer in *bufs with the smallest
// capacity of at least want, if any. It keeps a small reservoir from taking a
// large buffer that a full one will need.
func takeBestFit(bufs *[][]uint64, want int) ([]uint64, bool) {
	best := -1
	for i, buf := range *bufs {
		if cap(buf) >= want && (best < 0 || cap(buf) < cap((*bufs)[best])) {
			best = i
		}
	}
	if best < 0 {
		return nil, false
	}
	s := *bufs
	buf := s[best]
	last := len(s) - 1
	s[best] = s[last]
	s[last] = nil
	*bufs = s[:last]
	return buf[:0], true
}
