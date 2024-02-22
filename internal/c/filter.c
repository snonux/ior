//+build ignore

static __always_inline int filter() {
    if ((bpf_get_current_pid_tgid() >> 32) == PID_FILTER)
        return 0;

    /*
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) == UID_FILTER)
        return 0;
    */

    return 1;
}
