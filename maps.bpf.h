//+build ignore

#define TEMP_MAP_SIZES 1024 // Adjust size as needed
#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

struct config {
   int x;
   char y;
};

struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, u32);
   __type(value, struct config);
   __uint(max_entries, 1 << 24);
} config_map SEC(".maps");

struct open_event {
    __s32 fd;
    __s32 op_id;
    __u32 tid;
    __u64 enter_time;
    __u64 exit_time;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
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
    __uint(max_entries, TEMP_MAP_SIZES);
} open_event_temp_map SEC(".maps");

struct fd_event {
    __s32 fd;
    __s32 op_id;
    __u32 tid;
    __u64 enter_time;
    __u64 exit_time;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} fd_event_map SEC(".maps");

// Map to temporarily store info from the enter tracepoinut for the exit one
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct fd_event));
    __uint(max_entries, TEMP_MAP_SIZES);
} fd_event_temp_map SEC(".maps");
