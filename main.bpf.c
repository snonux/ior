//+build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

struct value {
    int x;
    char y;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct value);
    __uint(max_entries, 1 << 24);
} tester SEC(".maps");

struct openat_event {
    int fd;
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

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    struct openat_event event = {};

    // Capture the filename. Note: You need to handle possible user-space pointer issues
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)ctx->args[1]);
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.tid = tid;
    bpf_map_update_elem(&temp_events, &tid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *args) {
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
