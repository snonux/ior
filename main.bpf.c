//+build ignore

#include <vmlinux.h>

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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    char *foo = "foo";
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, foo, sizeof(char) * 3);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
