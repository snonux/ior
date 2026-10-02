//+build ignore

// event_map is the ring buffer carrying every event to userspace. max_entries
// is its size in BYTES and must stay equal to config.DefaultEventMapSize
// (internal/config/buffers.go, pinned by TestDefaultEventMapSizeMatchesMapsH):
// userspace overrides it at load time from -mapSize (resizeBPFMaps), and the
// default is 16 MiB because a smaller buffer drops events whenever the consumer
// pauses for more than a fraction of a millisecond under load.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_map SEC(".maps");

// pending_filename carries a user-space string pointer from sys_enter to
// sys_exit: the path argument of a syscall whose sys_enter
// bpf_probe_read_user_str faulted (open, stat, access, unlink, rename, ...), so
// the sys_exit handler can read the string once the kernel has faulted the page
// in, and the output buffer of getcwd (outputPathSyscalls in
// internal/generate/classify.go), whose path the kernel only writes during the
// call. pending_filename2 is the same for the second path of the rename/link
// family (newname) and of move_mount (to_pathname); either of the two reads
// can fault, both or neither. 0 means "nothing to read" and is the state
// ior_on_syscall_enter leaves behind for every other syscall (the struct is
// zero-initialised there).
struct syscall_enter_state {
    __u64 start_ns;
    __u64 pending_filename;
    __u64 pending_filename2;
    __u32 enter_trace_id;
    __u8 emit_event;
};

// count must stay the first field: userspace may read a slot while the
// kernel updates it, the copy runs in ascending address order, and
// ior_update_syscall_aggregate (filter.c) stores count last so that a torn
// read sees count no newer than any other field. Moving count down would let
// a torn read see it ahead of the histogram and book a timed invocation as
// untimed. internal/generate/enterstate_fallback_test.go pins this.
struct syscall_aggregate {
    __u64 count;
    __u64 errors;
    __u64 total_duration_ns;
    __u64 min_duration_ns;
    __u64 max_duration_ns;
    __u64 duration_histogram[8];
};

struct socketpair_ctx {
    __u64 usockvec;
    __s32 family;
    __s32 type;
    __s32 protocol;
};

struct pipe_ctx {
    __u64 upipefd;
    __s32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct socketpair_ctx);
} socketpair_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct pipe_ctx);
} pipe_ctx_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __s32);
} eventfd_flags_map SEC(".maps");

// syscall_enter_state_map carries each tid's in-flight syscall from sys_enter
// to sys_exit. It is bounded, so a write can fail on a host with more threads
// parked in traced syscalls than entries; ior_on_syscall_enter and
// ior_on_syscall_exit (internal/c/filter.c, "Enter state and its two
// fallbacks") keep the aggregate/ring-buffer partition exact when it does.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, struct syscall_enter_state);
} syscall_enter_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct syscall_aggregate);
} syscall_aggregate_map SEC(".maps");

// syscall_sampling_rate_map holds the sampling rate of each enter trace ID
// (task 2s2). It is an ARRAY indexed by the trace ID, not a HASH: every
// traced syscall reads it at sys_enter and again at sys_exit, and an array
// lookup is inlined by the verifier where a hash lookup is a helper call
// (~280 ns per traced syscall in total was measured, a good part of it these
// helper calls). Trace IDs top out near 1900, far below max_entries; an ID
// beyond it looks up NULL and gets the default rate, like an unconfigured one.
//
// An array has no "absent" state - an untouched slot reads 0, which as a
// rate would mean aggregate-only - so a slot stores rate + 1 and 0 means
// "not configured, use the default rate 1" (ior_sampling_rate decodes it;
// applySyscallSamplingRates in internal/syscall_aggregate_consumer.go
// encodes it).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} syscall_sampling_rate_map SEC(".maps");

// ringbuf_drop_map counts events lost because bpf_ringbuf_reserve() found
// event_map full. A full ring buffer is the kernel-side symptom of userspace
// backpressure (the libbpfgo ring-buffer callback blocks on a full Go channel),
// and without this counter those losses are completely silent.
//
// PERCPU_ARRAY with a single slot: the increment sits on the hot drop path, so
// each CPU bumps its own private u64 without atomics or contention; userspace
// sums the per-CPU values when reporting.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drop_map SEC(".maps");

// restart_pending_map remembers, per task, that its last traced syscall exit
// carried a restart code the kernel may answer by carrying the call on - by
// re-executing it (-512/-513/-514) or through restart_syscall (-516) - until
// the signal path has decided (restart.c, tasks 103 and t13).
//
// It is a direct-mapped ARRAY indexed by the low bits of the tid, each slot
// one __u64 word holding the owning tid and its state (ior_restart_entry in
// restart.c), not a HASH keyed by tid: every traced syscall enter has to ask
// "does this task have a pending restart?", and an array lookup is inlined by
// the verifier where a hash lookup is a helper call (the cost task 2s2 took
// out of this path). The price is that two tasks whose tids collide share a
// slot: the later interrupted exit evicts the earlier one, whose call is then
// simply not folded. One word per slot makes every update a single store, so
// a slot never mixes one task's tid with another task's state.
//
// Userspace writes it too: it stores 0 in every slot whenever a syscall's
// probes are attached or detached at runtime, because an entry cannot tell
// that its continuation ran while the tracepoints were off (task o03,
// "Runtime probe changes" in restart.c; internal/restart_pending_map.go).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} restart_pending_map SEC(".maps");
