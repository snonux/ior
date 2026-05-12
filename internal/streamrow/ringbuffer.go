package streamrow

import "sync"

const RingBufferCapacity = 10000

// RingBuffer is a fixed-capacity circular buffer of stream rows used by the
// tracing engine (write side) and the TUI stream view (read side). It
// satisfies the runtime.EventSink interface (Push + Len + Snapshot).
type RingBuffer struct {
	mu          sync.RWMutex
	buf         []Row
	start       int
	size        int
	totalPushed uint64
}

// NewRingBuffer allocates an empty RingBuffer with the default capacity.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{buf: make([]Row, RingBufferCapacity)}
}

// Push appends a row to the ring buffer, overwriting the oldest entry when full.
func (r *RingBuffer) Push(ev Row) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size < RingBufferCapacity {
		idx := (r.start + r.size) % RingBufferCapacity
		r.buf[idx] = ev
		r.size++
	} else {
		r.buf[r.start] = ev
		r.start = (r.start + 1) % RingBufferCapacity
	}
	r.totalPushed++
}

// Snapshot returns a copy of all rows in insertion order.
func (r *RingBuffer) Snapshot() []Row {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.size == 0 {
		return make([]Row, 0)
	}

	out := make([]Row, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.start+i)%RingBufferCapacity]
	}
	return out
}

// Len returns the current number of rows in the buffer.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// TotalPushed returns the total number of rows pushed since construction or
// the last Reset, including those that have been overwritten.
func (r *RingBuffer) TotalPushed() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalPushed
}

// Reset clears all rows and resets the total-pushed counter.
func (r *RingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	clear(r.buf)
	r.start = 0
	r.size = 0
	r.totalPushed = 0
}
