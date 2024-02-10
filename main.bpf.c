//+build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

// TODO: Make this configurable via a flag from the userland part.
// For now, this is set to my own user for development purposes.
#define UID_FILTER 1001 

struct openat_event {
    int fd;
    int syscall_id;
    u32 tid;
    char filename[256];
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Map to temporarily store the filename from sys_enter_openat
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct openat_event));
    __uint(max_entries, 128); // Adjust size as needed
} temp_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_open")
int handle_enter_open(struct trace_event_raw_sys_enter *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct openat_event event = { .syscall_id = ctx->id };

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[0]);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.tid = tid;
    bpf_map_update_elem(&temp_events, &tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int handle_exit_open(struct trace_event_raw_sys_exit *args) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct openat_event *eventp = bpf_map_lookup_elem(&temp_events, &tid);
    if (!eventp) {
        return 0;
    }
    eventp->fd = args->ret;
    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, eventp, sizeof(struct openat_event));
    bpf_map_delete_elem(&temp_events, &tid);

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    u32 tid = bpf_get_current_pid_tgid();
    struct openat_event event = { .syscall_id = ctx->id };

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[1]);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.tid = tid;
    bpf_map_update_elem(&temp_events, &tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *args) {
    if ((bpf_get_current_uid_gid() & 0xFFFFFFFF) != UID_FILTER)
        return 0;

    return handle_exit_open(args);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
