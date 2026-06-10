//+build ignore

#define ACCEPT 0
#define FILTER 1
#define IOR_HISTOGRAM_BUCKETS 8

static __always_inline __u32 ior_histogram_bucket_index(__u64 duration_ns) {
    if (duration_ns < 1000)
        return 0;
    if (duration_ns < 10000)
        return 1;
    if (duration_ns < 100000)
        return 2;
    if (duration_ns < 1000000)
        return 3;
    if (duration_ns < 10000000)
        return 4;
    if (duration_ns < 100000000)
        return 5;
    if (duration_ns < 1000000000)
        return 6;
    return 7;
}

static __always_inline void ior_update_syscall_aggregate(__u32 enter_trace_id, __u64 duration_ns, __s64 ret) {
    __u32 bucket_idx;
    struct syscall_aggregate *existing;
    struct syscall_aggregate fresh = {};

    existing = bpf_map_lookup_elem(&syscall_aggregate_map, &enter_trace_id);
    bucket_idx = ior_histogram_bucket_index(duration_ns);
    if (bucket_idx >= IOR_HISTOGRAM_BUCKETS)
        bucket_idx = IOR_HISTOGRAM_BUCKETS - 1;

    if (existing) {
        existing->count += 1;
        existing->total_duration_ns += duration_ns;
        if (ret < 0)
            existing->errors += 1;
        if (existing->count == 1 || duration_ns < existing->min_duration_ns)
            existing->min_duration_ns = duration_ns;
        if (duration_ns > existing->max_duration_ns)
            existing->max_duration_ns = duration_ns;
        existing->duration_histogram[bucket_idx] += 1;
        return;
    }

    fresh.count = 1;
    fresh.total_duration_ns = duration_ns;
    fresh.min_duration_ns = duration_ns;
    fresh.max_duration_ns = duration_ns;
    if (ret < 0)
        fresh.errors = 1;
    fresh.duration_histogram[bucket_idx] = 1;
    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);
}

static __always_inline int ior_should_emit_trace(__u32 enter_trace_id) {
    __u32 default_rate = 1;
    __u32 *configured = bpf_map_lookup_elem(&syscall_sampling_rate_map, &enter_trace_id);
    __u32 rate = configured ? *configured : default_rate;

    // A zero rate means aggregate-only mode for this syscall.
    if (rate == 0)
        return 0;
    if (rate == 1)
        return 1;
    return (bpf_get_prandom_u32() % rate) == 0;
}

static __always_inline int ior_on_syscall_enter(__u32 tid, __u32 enter_trace_id) {
    struct syscall_enter_state state = {};

    state.start_ns = bpf_ktime_get_boot_ns();
    state.enter_trace_id = enter_trace_id;
    state.emit_event = ior_should_emit_trace(enter_trace_id) ? 1 : 0;
    bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY);
    return state.emit_event != 0;
}

// ior_on_noreturn_syscall_enter is the enter hook for noreturn syscalls
// (exit, exit_group, rt_sigreturn). Unlike ior_on_syscall_enter it deliberately
// does NOT write a per-tid entry into syscall_enter_state_map. A noreturn
// syscall never returns to the syscall site (exit/exit_group terminate;
// rt_sigreturn restores the pre-signal context), so its sys_exit tracepoint
// never fires and the matching
// exit handler is suppressed by the generator (see internal/generate/codegen.go
// isNoreturnSyscall). With no exit handler, nothing would ever look up or
// bpf_map_delete_elem that enter-state entry, so recording it would only leave
// stale per-tid entries crowding the bounded (32768) map on hosts churning many
// distinct tids. We still honor the sampling decision so the enter null_event is
// emitted (or dropped) exactly as a normal syscall's enter would be, but without
// the dead, unreclaimable map write.
static __always_inline int ior_on_noreturn_syscall_enter(__u32 enter_trace_id) {
    return ior_should_emit_trace(enter_trace_id);
}

static __always_inline int ior_on_syscall_exit(__u32 tid, __u32 enter_trace_id, __s64 ret) {
    __u64 now;
    __u64 duration = 0;
    __u8 emit_event = 1;
    struct syscall_enter_state *state;

    state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);
    if (!state)
        return 1;

    now = bpf_ktime_get_boot_ns();
    if (now >= state->start_ns)
        duration = now - state->start_ns;

    // Pair aggregate stats using the explicit enter_trace_id passed by the
    // generated exit handler, avoiding any numeric adjacency assumption
    // between kernel-assigned enter and exit tracepoint IDs.
    if (state->enter_trace_id == enter_trace_id)
        ior_update_syscall_aggregate(state->enter_trace_id, duration, ret);

    emit_event = state->emit_event;
    bpf_map_delete_elem(&syscall_enter_state_map, &tid);
    return emit_event != 0;
}

// filter() decides whether the current task's syscall is in scope. Today this is
// a single-TGID gate (PID_FILTER, with -1 meaning trace-all) plus an optional
// TID_FILTER. ior does NOT follow forks: a traced process's children run under a
// different TGID and are excluded here, which also means their syscalls miss the
// aggregate-count path downstream. A planned opt-in process-tree-following mode
// would extend this gate to also accept descendant TGIDs from a BPF-maintained
// set seeded with the root PID and updated via sched_process_fork/exit — see
// docs/follow-forks-plan.md for the full design.
static __always_inline int filter(__u32 *pid, __u32 *tid) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    *pid = pid_tgid >> 32;

    // Ignore ior userland process itself
    if (*pid == IOR_PID_FILTER) {
        return FILTER;
    }
    
    *tid = pid_tgid & 0xFFFFFFFF;
    if (-1 == PID_FILTER || *pid == PID_FILTER) {
        if (-1 == TID_FILTER || *tid == TID_FILTER) {
            return ACCEPT;
        }
    }

    return FILTER;
}
