package statsengine

import "sync"

// sampleBufferPool recycles the scratch buffers that Engine.Snapshot copies
// latency reservoirs into. Handing buffers to the capture before the engine
// lock is taken keeps allocation (and any GC assist it triggers) out of the
// lock: under the lock the capture only copies samples into ready buffers.
//
// Unlike sync.Pool, the retained buffers survive garbage collections, so a
// steady-state refresh allocates nothing. Retention is bounded by trimming to
// the number of buffers the last snapshot could have needed (one per tracked
// syscall), i.e. at most as much memory as the reservoirs themselves hold.
type sampleBufferPool struct {
	mu     sync.Mutex
	bufCap int
	free   [][]uint64
}

func newSampleBufferPool(bufCap int) *sampleBufferPool {
	return &sampleBufferPool{bufCap: bufCap}
}

// acquire returns n empty buffers of capacity bufCap, reusing released ones
// and allocating the rest. Callers must not hold the engine lock.
func (p *sampleBufferPool) acquire(n int) [][]uint64 {
	if n <= 0 {
		return nil
	}
	out := make([][]uint64, 0, n)

	p.mu.Lock()
	take := min(n, len(p.free))
	out = append(out, p.free[len(p.free)-take:]...)
	clear(p.free[len(p.free)-take:])
	p.free = p.free[:len(p.free)-take]
	p.mu.Unlock()

	for len(out) < n {
		out = append(out, make([]uint64, 0, p.bufCap))
	}
	return out
}

// release returns buffers to the pool, keeping at most keep of them in total
// so the pool shrinks again after a Reset or when syscalls go idle. Buffers
// smaller than bufCap (allocated to size by a capture that ran out of scratch)
// are dropped: handing them out again could force a regrow under the lock.
func (p *sampleBufferPool) release(bufs [][]uint64, keep int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, buf := range bufs {
		if len(p.free) >= keep {
			return
		}
		if cap(buf) >= p.bufCap {
			p.free = append(p.free, buf[:0])
		}
	}
}
