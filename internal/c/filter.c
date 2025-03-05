//+build ignore

#define ACCEPT 0
#define FILTER 1

static __always_inline int filter(__u32 *pid, __u32 *tid) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    *pid = pid_tgid >> 32;
    *tid = pid_tgid & 0xFFFFFFFF;

    if (PID_FILTER == *pid) {
        if (TID_FILTER == *tid) {
            return ACCEPT;
        } else if (TID_FILTER == -1) {
            return ACCEPT;
        }
    } else if (PID_FILTER == -1) {
        if (TID_FILTER == *tid) {
            return ACCEPT;
        } else if (TID_FILTER == -1) {
            return ACCEPT;
        }
    }

    return FILTER;
}

