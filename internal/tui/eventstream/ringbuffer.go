package eventstream

import "sync"

const ringBufferCapacity = 10000

type RingBuffer struct {
	mu          sync.RWMutex
	buf         []StreamEvent
	start       int
	size        int
	totalPushed uint64
}

func NewRingBuffer() *RingBuffer {
	return &RingBuffer{buf: make([]StreamEvent, ringBufferCapacity)}
}

func (r *RingBuffer) Push(ev StreamEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.size < ringBufferCapacity {
		idx := (r.start + r.size) % ringBufferCapacity
		r.buf[idx] = ev
		r.size++
	} else {
		r.buf[r.start] = ev
		r.start = (r.start + 1) % ringBufferCapacity
	}
	r.totalPushed++
}

func (r *RingBuffer) Snapshot() []StreamEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.size == 0 {
		return make([]StreamEvent, 0)
	}

	out := make([]StreamEvent, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.start+i)%ringBufferCapacity]
	}
	return out
}

func (r *RingBuffer) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.size
}

func (r *RingBuffer) TotalPushed() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.totalPushed
}

func (r *RingBuffer) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	clear(r.buf)
	r.start = 0
	r.size = 0
	r.totalPushed = 0
}
