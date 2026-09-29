//+build ignore

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_map SEC(".maps");

// pending_filename carries a user-space string pointer from sys_enter to
// sys_exit: the filename of an open whose sys_enter bpf_probe_read_user_str
// faulted, so the sys_exit handler can read the string once the kernel has
// faulted the page in, and the output buffer of getcwd (outputPathSyscalls in
// internal/generate/classify.go), whose path the kernel only writes during the
// call. 0 means "nothing to read" and is the state ior_on_syscall_enter leaves
// behind for every other syscall (the struct is zero-initialised there).
struct syscall_enter_state {
    __u64 start_ns;
    __u64 pending_filename;
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
