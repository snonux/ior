//+build ignore

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_map SEC(".maps");

struct syscall_enter_state {
    __u64 start_ns;
    __u32 enter_trace_id;
    __u8 emit_event;
};

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
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
