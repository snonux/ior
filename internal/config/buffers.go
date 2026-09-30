package config

const (
	// DefaultChannelBufferSize is the shared default for high-volume trace and
	// TUI event channels.
	DefaultChannelBufferSize = 4096

	// DefaultEventMapSize is the default size, in BYTES, of the BPF event ring
	// buffer (event_map). It equals the max_entries that internal/c/maps.h
	// declares (1 << 24, pinned by TestDefaultEventMapSizeMatchesMapsH), so the
	// -mapSize override no longer silently shrinks the map.
	//
	// Why 16 MiB: the ring buffer is the only slack between the kernel
	// producers and the single userspace consumer. A busy producer fills 64 KiB
	// (~1,300 read/write records, ~200 open records) in well under a
	// millisecond, so any consumer pause longer than that (GC, stats/trie
	// locks, the ~50ms LiveTrie compaction) dropped events: a bursty ~300k
	// records/s load lost 0.12-0.21% of them at 64 KiB (1,706 to 3,015 kernel
	// drops per 5s run) and none at 16 MiB.
	//
	// Cost: ring-buffer pages are allocated up front and are non-swappable
	// kernel memory (charged to the memory cgroup on kernel >= 5.11, to
	// RLIMIT_MEMLOCK before that), shared by all CPUs, not per-CPU. Use
	// -mapSize to trade it back on memory-constrained hosts; libbpf rounds the
	// value up to a power-of-two multiple of the page size.
	DefaultEventMapSize = 1 << 24
)
