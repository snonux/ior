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

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat(struct trace_event_raw_sys_exit *args) {
    struct openat_event event = {};
    event.fd = args->ret;
    event.tid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_perf_event_output(args, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
