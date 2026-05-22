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
