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

static __always_inline int ior_on_syscall_exit(__u32 tid, __u32 exit_trace_id, __s64 ret) {
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

    // A tracepoint pair uses enter_id == exit_id + 1 in this codebase.
    if (state->enter_trace_id == exit_trace_id + 1)
        ior_update_syscall_aggregate(state->enter_trace_id, duration, ret);

    emit_event = state->emit_event;
    bpf_map_delete_elem(&syscall_enter_state_map, &tid);
    return emit_event != 0;
}

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
