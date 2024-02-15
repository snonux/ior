//+build ignore

#include "vmlinux.h"
#include "opids.h"
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"

static inline int filter() {
    u32 key = 1;
    struct flags *flagsp = bpf_map_lookup_elem(&flags_map, &key);
    return flagsp == NULL || (bpf_get_current_uid_gid() & 0xFFFFFFFF) != flagsp->uid_filter;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if (filter())
        return 0;

    struct openat_enter_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct openat_enter_event), 0);
    if (!ev)
        return 0;

    ev->op_id = OPENAT_ENTER_OP_ID;
    ev->tid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();

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
    ev->tid = bpf_get_current_pid_tgid();
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

SEC("tracepoint/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx) {
    if (filter())
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev)
        return 0;

    ev->op_id = CLOSE_ENTER_OP_ID;
    ev->tid = bpf_get_current_pid_tgid();
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
    ev->tid = bpf_get_current_pid_tgid();
    ev->time = bpf_ktime_get_ns();

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
