//+build ignore

static __always_inline int _handle_enter_open(struct trace_event_raw_sys_enter *ctx, __u32 op_id) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct open_enter_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct open_enter_event), 0);
    if (!ev)
        return 0;

    ev->op_id = op_id;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;

    // Reset memory, as structure is re-used (ringbuffer)
    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]);
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

static __always_inline int _handle_exit_open(struct trace_event_raw_sys_exit *ctx, __u32 op_id) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->op_id = op_id;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = ctx->ret;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    return _handle_enter_open(ctx, OPENAT_ENTER_OP_ID);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    return _handle_exit_open(ctx, OPENAT_EXIT_OP_ID);
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_enter_open(struct trace_event_raw_sys_enter *ctx) {
    return _handle_enter_open(ctx, OPEN_ENTER_OP_ID);
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx) {
    return _handle_exit_open(ctx, OPEN_EXIT_OP_ID);
}
