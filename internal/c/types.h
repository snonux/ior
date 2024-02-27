//+build ignore

#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

struct null_event {
    __u32 syscall_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
};

struct fd_event {
    __u32 syscall_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
    __s32 fd;
};

struct ret_event {
    __u32 syscall_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
    __u64 ret;
};

struct open_enter_event {
    __u32 syscall_id; 
    __u32 pid;
    __u32 tid;
    __u32 time;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};
