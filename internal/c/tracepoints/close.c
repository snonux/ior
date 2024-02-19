//+build ignore

SEC("tracepoint/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx) {
    if (filter())
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->op_id = CLOSE_ENTER_OP_ID;
    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int handle_exit_close(struct trace_event_raw_sys_enter *ctx) {
    if (filter())
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->op_id = CLOSE_EXIT_OP_ID;
    ev->pid_tgid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

