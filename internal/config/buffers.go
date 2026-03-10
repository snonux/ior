package config

const (
	// DefaultChannelBufferSize is the shared default for high-volume trace and
	// TUI event channels.
	DefaultChannelBufferSize = 4096

	// DefaultEventMapSize is the default BPF event ring-buffer map size.
	DefaultEventMapSize = DefaultChannelBufferSize * 16
)
