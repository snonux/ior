package eventstream

import "ior/internal/streamrow"

// RingBuffer is a type alias for streamrow.RingBuffer. The concrete
// implementation lives in the lower-level streamrow package so the core
// tracing engine can use it without importing internal/tui/eventstream.
type RingBuffer = streamrow.RingBuffer

// ringBufferCapacity mirrors the capacity constant for use in this package
// (e.g. stream table rendering).
const ringBufferCapacity = streamrow.RingBufferCapacity

// NewRingBuffer allocates an empty RingBuffer with the default capacity.
func NewRingBuffer() *RingBuffer {
	return streamrow.NewRingBuffer()
}
