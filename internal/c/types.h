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
#define ENTER_OPEN_BY_HANDLE_AT_EVENT 17
#define EXIT_OPEN_BY_HANDLE_AT_EVENT 18
#define ENTER_SOCKET_EVENT 19
#define EXIT_SOCKET_EVENT 20
#define ENTER_SOCKETPAIR_EVENT 21
#define EXIT_SOCKETPAIR_EVENT 22
#define ENTER_ACCEPT_EVENT 23
#define EXIT_ACCEPT_EVENT 24
#define ENTER_PIPE_EVENT 25
#define EXIT_PIPE_EVENT 26
#define ENTER_EVENTFD_EVENT 27
#define EXIT_EVENTFD_EVENT 28

#define UNCLASSIFIED 0
#define READ_CLASSIFIED 1
#define WRITE_CLASSIFIED 2
#define TRANSFER_CLASSIFIED 3

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
    __u32 ret_type;
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

struct open_by_handle_at_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
};

struct socket_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 family;
    __s32 type;
    __s32 protocol;
};

struct socketpair_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 family;
    __s32 type;
    __s32 protocol;
    __s32 sv0;
    __s32 sv1;
    __s64 ret;
};

struct accept_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s64 ret;
};

struct pipe_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    __s32 fd0;
    __s32 fd1;
    __s64 ret;
};

struct eventfd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    __s64 ret;
};
