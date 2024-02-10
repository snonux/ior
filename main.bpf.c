//+build ignore

#include "vmlinux.h"
#include "opids.h"

#include <bpf/bpf_helpers.h>

// TODO: Split out this file into several *.bpf.c programs.

// TODO: Make UID_FILTER configurable via a flag from the userland part.
// For now, this is set to my own user for development purposes.
#define UID_FILTER 1001 

// Helper structs for opening file(s)

struct open_event {
    int fd;
    int op_id;
    u32 tid;
    char filename[256];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} open_event_map SEC(".maps");

// Map to temporarily store the filename from sys_enter_openat
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct open_event));
    __uint(max_entries, 128); // Adjust size as needed
} open_event_temp_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int handle_enter_open(struct trace_event_raw_sys_enter *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct open_event event = { .op_id = OPEN };

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.tid = tid;
    bpf_map_update_elem(&open_event_temp_map, &tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct trace_event_raw_sys_exit *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct open_event *eventp = bpf_map_lookup_elem(&open_event_temp_map, &tid);
    if (!eventp) {
        return 0;
    }
    eventp->fd = ctx->ret;
    bpf_perf_event_output(ctx, &open_event_map, BPF_F_CURRENT_CPU, eventp, sizeof(struct open_event));
    bpf_map_delete_elem(&open_event_temp_map, &tid);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct open_event event = { .op_id = OPEN_AT };

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[1]);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.tid = tid;
    bpf_map_update_elem(&open_event_temp_map, &tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    return handle_exit_open(ctx);
}

// Helper structs for other syscalls on FDs

struct fd_event {
    int fd;
    int op_id;
    u32 tid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} fd_event_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    struct fd_event event = {
        .fd = (int)ctx->args[0],
        .op_id = CLOSE,
        .tid = bpf_get_current_pid_tgid(),
    };
    bpf_perf_event_output(ctx, &fd_event_map, BPF_F_CURRENT_CPU, &event, sizeof(struct fd_event));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
