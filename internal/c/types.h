//+build ignore

#define MAX_FILENAME_LENGTH 256
#define MAX_PROGNAME_LENGTH 16

#define ENTER_OPEN_EVENT 1
#define EXIT_OPEN_EVENT 2
#define ENTER_NULL_EVENT 3
#define EXIT_NULL_EVENT 4
#define ENTER_FD_EVENT 5
#define EXIT_FD_EVENT 6
#define ENTER_RET_EVENT 7
#define EXIT_RET_EVENT 8
#define ENTER_NAME_EVENT 9
#define EXIT_NAME_EVENT 10
#define ENTER_PATH_EVENT 11
#define EXIT_PATH_EVENT 12
#define ENTER_FCNTL_EVENT 13
#define EXIT_FCNTL_EVENT 14
#define ENTER_DUP3_EVENT 15
#define EXIT_DUP3_EVENT 16

struct open_event {
    __u32 event_type;
    __u32 trace_id; 
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};

struct null_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
};

struct fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
};

struct ret_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __s64 ret;
    __u32 pid;
    __u32 tid;
};

struct name_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char oldname[MAX_FILENAME_LENGTH];
    char newname[MAX_FILENAME_LENGTH];
};

struct path_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char pathname[MAX_FILENAME_LENGTH];
};

struct fcntl_event {
    __u32 event_type;
    __u32 trace_id; 
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 fd;
    __u32 cmd;
    __u64 arg;
};

// dup and dup2 are just fd_events, but dup3 also has the additional flags
struct dup3_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s32 flags;
};
