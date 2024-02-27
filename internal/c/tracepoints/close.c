//+build ignore

// SEC("tracepoint/syscalls/sys_enter_close")
/*
int handle_enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
*/

// SEC("tracepoint/syscalls/sys_exit_close")
/*
int handle_exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct null_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct null_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_CLOSE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000000;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}
*/
