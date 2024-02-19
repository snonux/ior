//+build ignore

static __always_inline int filter() {
    return (bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER;
}
