//+build ignore

#define TEMP_MAP_SIZES 1024 // Adjust size as needed
#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

struct flags {
   __u32 uid_filter;
};

// To pass command line flags from userspace to BPF kernel space.
struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, u32);
   __type(value, struct flags);
   __uint(max_entries, 1 << 24);
} flags_map SEC(".maps");

#define OPENAT_ENTER_OP_ID 1
#define OPENAT_EXIT_OP_ID 2
#define CLOSE_ENTER_OP_ID 1
#define CLOSE_EXIT_OP_ID 2

struct openat_enter_event {
    __u32 op_id; 
    __u32 tid;
    __u64 time;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};

struct fd_event {
    __u32 op_id;
    __u32 tid;
    __u64 time;
    __s32 fd;
};

struct null_event {
    __u32 op_id;
    __u32 tid;
    __u64 time;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} event_map SEC(".maps");
