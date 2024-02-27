//+build ignore

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_ENTER_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;
    ev->fd = (int)ctx->args[0];

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int handle_exit_write(struct trace_event_raw_sys_exit *ctx) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;

    struct rw_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct rw_event), 0);
    if (!ev)
        return 0;

    ev->syscall_id = SYS_EXIT_WRITE;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_ns() / 1000;

    ev->size = ctx->ret;
    bpf_ringbuf_submit(ev, 0);

    return 0;
}
