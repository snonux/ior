//+build ignore

// These types mirror the Go types from internal/types/types.go
//
#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

#define OPENAT_ENTER_OP_ID 1
#define OPENAT_EXIT_OP_ID 2
#define CLOSE_ENTER_OP_ID 3
#define CLOSE_EXIT_OP_ID 4
#define WRITE_ENTER_OP_ID 5
#define WRITE_EXIT_OP_ID 6
#define WRITEV_ENTER_OP_ID 7
#define WRITEV_EXIT_OP_ID 8

struct null_event {
    __u32 op_id;
    __u32 pid_tgid;
    __u64 time;
};

struct fd_event {
    __u32 op_id;
    __u32 pid_tgid;
    __u64 time;
    __s32 fd;
};

struct openat_enter_event {
    __u32 op_id; 
    __u32 pid_tgid;
    __u64 time;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};

struct flags {
   __u32 uid_filter;
};

