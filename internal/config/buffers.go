package config

const (
	// DefaultChannelBufferSize is the shared default for high-volume trace and
	// TUI event channels.
	DefaultChannelBufferSize = 4096

	// DefaultEventMapSize is the default BPF event ring-buffer map size.
	DefaultEventMapSize = DefaultChannelBufferSize * 16

	// PairChannelBufferSize is the capacity of the channel that hands decoded
	// syscall pairs from the raw-event decode goroutine to the emit loop.
	// With an unbuffered channel every pair cost a goroutine park and wake
	// on both sides, which dominated the pipeline profile. A buffer lets
	// each side run through a burst without a handoff while still bounding
	// how far decoding can run ahead of emission, so backpressure still
	// reaches the raw channel and, through it, the BPF ring buffer. Larger
	// buffers measured no faster but keep more pooled pairs in flight (and
	// out of their pools); see perf/ for the numbers.
	PairChannelBufferSize = 256
)
