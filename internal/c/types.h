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
#define ENTER_EPOLL_CTL_EVENT 29
#define EXIT_EPOLL_CTL_EVENT 30
#define ENTER_POLL_EVENT 31
#define EXIT_POLL_EVENT 32
#define ENTER_MEM_EVENT 33
#define EXIT_MEM_EVENT 34
#define ENTER_SLEEP_EVENT 35
#define EXIT_SLEEP_EVENT 36
#define ENTER_TWO_FD_EVENT 37
#define EXIT_TWO_FD_EVENT 38
#define ENTER_KEYCTL_EVENT 39
#define EXIT_KEYCTL_EVENT 40
#define ENTER_PTRACE_EVENT 41
#define EXIT_PTRACE_EVENT 42
#define ENTER_PERF_OPEN_EVENT 43
#define EXIT_PERF_OPEN_EVENT 44
#define ENTER_EXEC_EVENT 45
#define EXIT_EXEC_EVENT 46
#define PROCESS_EXEC_EVENT 47
#define OPEN_NAME_FIXUP_EVENT 48
#define PROCESS_EXIT_EVENT 49
#define ENTER_MMAP_EVENT 50
#define EXIT_MMAP_EVENT 51
#define ENTER_BPF_EVENT 52
#define EXIT_BPF_EVENT 53

#define UNCLASSIFIED 0
#define READ_CLASSIFIED 1
#define WRITE_CLASSIFIED 2
#define TRANSFER_CLASSIFIED 3

// Status of one pathname pointer captured with bpf_probe_read_user_str.
// A valid empty string is PATH_READ_OK; PATH_READ_NULL records an actual NULL
// syscall argument, and PATH_READ_FAILED records a non-NULL pointer the nofault
// helper could not read. Userspace may attribute an empty OK/NULL value to a
// concrete dirfd only when that exact syscall, side, flags, and result permit
// descriptor semantics; it must never do so for FAILED.
#define PATH_READ_OK 0
#define PATH_READ_NULL 1
#define PATH_READ_FAILED 2

// Whether a successful path syscall necessarily validated its target. Most
// path syscalls always do. utimensat is exceptional: two UTIME_OMIT values
// return success before validating the path, dirfd, or flags. UNKNOWN records
// a non-NULL timespec array that the enter probe could not safely read.
#define PATH_TARGET_REQUIRED 0
#define PATH_TARGET_SKIPPED 1
#define PATH_TARGET_UNKNOWN 2
#define IOR_UTIME_OMIT 1073741822

// The first open_event schema ended after comm and occupied 300 bytes before
// C tail padding (304 bytes in the ring buffer). Keep that field prefix stable
// and append new fields so userspace can distinguish legacy payloads by size.
// dirfd alone would still collide with the legacy 304-byte kernel layout. The
// schema version, filename status and reserved word make the final v3 layout
// 320 bytes. Intermediate development layouts were never released and are not
// part of the decoder compatibility contract.
#define OPEN_EVENT_SCHEMA_VERSION 3
#define PATH_EVENT_SCHEMA_VERSION 3
#define NAME_EVENT_SCHEMA_VERSION 2
#define EVENTFD_EVENT_SCHEMA_VERSION 2
#define TWO_FD_EVENT_SCHEMA_VERSION 2

struct open_event {
    __u32 event_type;
    __u32 trace_id; 
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    char filename[MAX_FILENAME_LENGTH];
    char comm[MAX_PROGNAME_LENGTH];
    __s32 dirfd;
    __u32 schema_version;
    __u32 filename_status;
    __u32 schema_reserved;
};

struct open_name_fixup_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 tid;
    char filename[MAX_FILENAME_LENGTH];
};

struct exec_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 dirfd;
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
    __s32 olddirfd;
    __s32 newdirfd;
    __u32 oldname_status;
    __u32 newname_status;
    __u32 flags;
    __u32 schema_version;
};

struct path_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char pathname[MAX_FILENAME_LENGTH];
    __s32 dirfd;
    __u32 pathname_status;
    __u32 flags;
    __u32 schema_version;
    __u32 target_status;
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
    __s32 fd;
    char filename[MAX_FILENAME_LENGTH];
    __u32 filename_status;
    __u32 schema_version;
};

struct epoll_ctl_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 epfd;
    __s32 op;
    __s32 fd;
    __u32 events;
};

struct poll_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 nfds;
    __s64 timeout_ns;
};

struct mem_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u64 addr;
    __u64 length;
    __u64 length2;
    __u64 flags;
};

struct mmap_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u64 addr;
    __u64 length;
    __u64 prot;
    __u64 flags;
    __s32 fd;
};

struct sleep_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s64 requested_ns;
};

struct two_fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd_a;
    __s32 fd_b;
    __u64 extra;
    char oldname[MAX_FILENAME_LENGTH];
    char newname[MAX_FILENAME_LENGTH];
    __u32 oldname_status;
    __u32 newname_status;
    __u32 schema_version;
};

struct bpf_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 cmd;
};

struct keyctl_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 option;
    __s32 key_serial;
    __u64 value;
};

struct ptrace_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s64 request;
    __s32 target_pid;
    __s32 _pad;
    __u64 data;
};

struct perf_open_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 attr_type;
    __u32 attr_size;
    __u64 config;
    __s32 target_pid;
    __s32 cpu;
    __s32 group_fd;
    __u32 flags;
};

// process_exec_event is not a syscall tracepoint event: it is emitted by the
// hand-written sched:sched_process_exec handler in exec.c, which fires after
// the kernel has already installed the new program's name in task->comm but
// before the new program executes its first syscall. Userspace consumes it as
// a control event (no enter/exit pair, never rendered as a row) that refreshes
// the pid->comm cache, so the first post-exec syscalls are labelled with the
// post-exec comm instead of the pre-exec one.
struct process_exec_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char comm[MAX_PROGNAME_LENGTH];
};

// process_exit_event is not a syscall tracepoint event: it is emitted by the
// hand-written sched:sched_process_exit handler in exec.c, which fires when a
// task exits. Userspace consumes it as a control event (no enter/exit pair,
// never rendered as a row) that evicts the exited task's process (tgid) from
// the fdTracker's per-(pid, fd) maps, so descriptors of processes that are
// gone do not linger until LRU eviction. Like process_exec_event it carries no
// comm: the only payload userspace needs is the identity of the process.
struct process_exit_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
};
