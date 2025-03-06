//+build ignore

#define ACCEPT 0
#define FILTER 1

static __always_inline int filter(__u32 *pid, __u32 *tid) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    *pid = pid_tgid >> 32;
    *tid = pid_tgid & 0xFFFFFFFF;

    if (-1 == PID_FILTER || *pid == PID_FILTER) {
        if (-1 == TID_FILTER || *tid == TID_FILTER)
            return ACCEPT;
    }

    return FILTER;
}

