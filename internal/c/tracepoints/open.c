//+build ignore

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if (filter())
        return 0;

    struct openat_enter_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct openat_enter_event), 0);
    if (!ev)
        return 0;

    ev->op_id = OPENAT_ENTER_OP_ID;
    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();

    __builtin_memset(&(ev->filename), 0, sizeof(ev->filename) + sizeof(ev->comm));
    bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)ctx->args[1]);
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    if (filter())
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->op_id = OPENAT_EXIT_OP_ID;
    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();
    ev->fd = ctx->ret;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_enter_open(struct trace_event_raw_sys_enter *ctx) {
    return handle_enter_openat(ctx);
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx) {
    return handle_exit_openat(ctx);
}

