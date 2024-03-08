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

struct open_event {
    __u32 event_type;
    __u32 trace_id; 
    __u32 pid;
    __u32 tid;
    __u32 time;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
};

struct null_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
};

struct fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
    __s32 fd;
};

struct ret_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 pid;
    __u32 tid;
    __s64 ret;
    __u32 time;
};

struct name_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
    char oldname[MAX_FILENAME_LENGTH];
    char newname[MAX_FILENAME_LENGTH];
};

struct path_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 pid;
    __u32 tid;
    __u32 time;
    char pathname[MAX_FILENAME_LENGTH];
};
