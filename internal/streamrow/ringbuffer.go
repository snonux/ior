package streamrow

import "sync"

// RingBufferCapacity is the number of rows the stream ring buffer retains;
// the oldest rows are dropped once the buffer is full.
const RingBufferCapacity = 10000

// RingBuffer is a fixed-capacity circular buffer of stream rows used by the
// tracing engine (write side) and the TUI stream view (read side). It
// satisfies the runtime.EventSink interface (Push + Len + Snapshot).
//
// It also keeps an exact count of the synthetic warning rows (Row.IsWarning)
// it currently holds, so the dashboard can point a user on another tab at
// the Stream tab's warnings (WarningCount, task ys2) without snapshotting
// and scanning 10k rows on every frame.
type RingBuffer struct {
	mu          sync.RWMutex
	buf         []Row
	start       int
	size        int
	totalPushed uint64
	// warnings is the number of rows in buf[start:start+size] (wrapped)
	// with IsWarning set. Push adjusts it for the row it adds and for the
	// row a full buffer overwrites, Reset zeroes it, all under mu, so it
	// always equals a scan of the retained rows.
	warnings int
}

// NewRingBuffer allocates an empty RingBuffer with the default capacity.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{buf: make([]Row, RingBufferCapacity)}
}

// Push appends a row to the ring buffer, overwriting the oldest entry when
// full. The warning count follows both ends: the new row adds to it when it
// is a warning, and an evicted warning row (the oldest one, overwritten on a
// wrap) leaves it.
func (r *RingBuffer) Push(ev Row) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size < RingBufferCapacity {
		idx := (r.start + r.size) % RingBufferCapacity
		r.buf[idx] = ev
		r.size++
	} else {
		if r.buf[r.start].IsWarning {
			r.warnings--
		}
		r.buf[r.start] = ev
		r.start = (r.start + 1) % RingBufferCapacity
	}
	if ev.IsWarning {
		r.warnings++
	}
	r.totalPushed++
}

// Snapshot returns a copy of all rows in insertion order in a freshly
// allocated slice the caller owns outright (safe to hand to another
// goroutine). Callers that snapshot repeatedly on one goroutine should use
// AppendSnapshot with a reused buffer instead.
func (r *RingBuffer) Snapshot() []Row {
	return r.AppendSnapshot(make([]Row, 0, r.Len()))
}

// AppendSnapshot appends a copy of all rows in insertion order to dst and
// returns the extended slice, like append. Passing a reused buffer truncated
// to length zero (buf[:0]) lets a periodic reader such as the Stream tab
// refresh snapshot a full buffer without allocating once buf has grown to
// capacity. The rows are copied under the read lock, so the result never
// aliases the ring's internal storage.
func (r *RingBuffer) AppendSnapshot(dst []Row) []Row {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Copy the ring as its (at most) two contiguous segments: the run from
	// start to the end of buf, then the wrapped-around run from index 0.
	first := min(r.size, RingBufferCapacity-r.start)
	dst = append(dst, r.buf[r.start:r.start+first]...)
	return append(dst, r.buf[:r.size-first]...)
}

// Len returns the current number of rows in the buffer.
func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

// WarningCount returns the number of synthetic warning rows (Row.IsWarning)
// the buffer currently holds: warnings pushed and not yet evicted by a wrap
// or cleared by Reset. It is read under the read lock, so it is safe to call
// from the UI goroutine while the event loop pushes.
func (r *RingBuffer) WarningCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.warnings
}

// TotalPushed returns the total number of rows pushed since construction or
// the last Reset, including those that have been overwritten.
func (r *RingBuffer) TotalPushed() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalPushed
}

// Reset clears all rows and resets the total-pushed and warning counters.
func (r *RingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	clear(r.buf)
	r.start = 0
	r.size = 0
	r.totalPushed = 0
	r.warnings = 0
}
