//+build ignore

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

