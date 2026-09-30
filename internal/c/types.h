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
#define ENTER_FD_PATH_EVENT 54
#define EXIT_FD_PATH_EVENT 55
// The rare payloads of fd_event, two_fd_event and eventfd_event travel in
// their own records so that the hot kinds stay lean (task 89). Only the enter
// side exists: the exits of these syscalls are ret_event or the lean
// eventfd_event.
#define ENTER_FD_SIZE_EVENT 56
#define EXIT_FD_SIZE_EVENT 57
#define ENTER_TWO_FD_NAMES_EVENT 58
#define EXIT_TWO_FD_NAMES_EVENT 59
#define ENTER_EVENTFD_NAME_EVENT 60
#define EXIT_EVENTFD_NAME_EVENT 61
// Control record of the hand-written task:task_newtask handler (exec.c).
#define TASK_NEWTASK_EVENT 62

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
// 320 bytes. path_event v4 appends requested-size metadata to its v3
// 300/304-byte layout. Intermediate development layouts were never released
// and are not part of the decoder compatibility contract.
//
// fd_size_event is the fd_event v1 layout (the legacy 28/32-byte fd_event plus
// requested-size metadata) under its own event type; fd_event itself is the
// legacy layout again. eventfd_name_event is the eventfd_event v2 layout and
// eventfd_event the name-less 48-byte layout that preceded it. Older BPF
// objects still send the wide layouts under ENTER_FD_EVENT/ENTER_EVENTFD_EVENT;
// userspace tells them apart by size.
#define OPEN_EVENT_SCHEMA_VERSION 3
#define FD_SIZE_EVENT_SCHEMA_VERSION 1
// Compatibility names for userspace decoders of records from older BPF objects.
#define FD_EVENT_SCHEMA_VERSION 1
#define PATH_EVENT_SCHEMA_VERSION 4
#define NAME_EVENT_SCHEMA_VERSION 2
#define EVENTFD_NAME_EVENT_SCHEMA_VERSION 2
#define EVENTFD_EVENT_SCHEMA_VERSION 2
// accept_event v1 appends flags and a discriminator after ret. Keeping the
// legacy prefix intact lets userspace decode old 36/40-byte payloads without
// mistaking the old kernel padding before ret for creation flags.
#define ACCEPT_EVENT_SCHEMA_VERSION 1
// Schema 2 predates the kcmp pid1/type packing used for safe file attribution.
// Schema 3 is shared by the lean two_fd_event (close_range, kcmp) and by
// two_fd_names_event (move_mount), which is the former 568-byte two_fd_event
// layout under its own event type.
#define TWO_FD_EVENT_PRE_KCMP_OWNER_SCHEMA_VERSION 2
#define TWO_FD_EVENT_SCHEMA_VERSION 3
#define FD_PATH_EVENT_SCHEMA_VERSION 1
// poll_event v1 appends the optional descriptor and a schema discriminator to
// the legacy nfds/timeout prefix. Timeout sentinels are part of the exported
// stream contract: -1 means an intentional infinite wait, while -2 means the
// timeout was unreadable, invalid, unrepresentable in nanoseconds, or has no
// capture recipe.
#define POLL_EVENT_SCHEMA_VERSION 1
// exec_event v1 appends the filename read status and a schema discriminator
// to the legacy 304-byte layout (task 9p2), for 312 bytes with no padding.
// Without the status an unreadable execveat name was indistinguishable from
// the "" of an AT_EMPTY_PATH fexecve, so userspace had to guess. Legacy
// 304-byte records still decode, with the status reported as PATH_READ_OK.
#define EXEC_EVENT_SCHEMA_VERSION 1
#define POLL_TIMEOUT_INFINITE_NS -1
#define POLL_TIMEOUT_UNKNOWN_NS -2

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
    __u32 filename_status;
    __u32 schema_version;
};

struct null_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
};

// fd_event is the hot single-descriptor record (read, write, close, ...): 32
// bytes in the ring buffer. It has no schema field; its layout is the legacy
// one, which userspace has always decoded.
struct fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
};

// fd_size_event is fd_event plus the requested output-buffer size, captured
// only for the fd-based xattr reads (fgetxattr, flistxattr) whose zero-size
// call is a size probe.
struct fd_size_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u64 size;
    __u32 size_valid;
    __u32 schema_version;
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
    __u32 size_valid;
    __u64 size;
};

// Notification group fd and watched pathname are different identities. Keep
// this separate from path_event so older BPF objects retain their old layouts.
struct fd_path_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s32 dirfd;
    char pathname[MAX_FILENAME_LENGTH];
    __u32 pathname_status;
    __u32 flags;
    __u32 schema_version;
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
    __s32 flags;
    __u32 schema_version;
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

// eventfd_event serves the descriptor-creating calls without an identifying
// name (eventfd2, epoll_create1, signalfd4, timerfd_create, pidfd_open, ...)
// and every exit of the family: 48 bytes in the ring buffer.
struct eventfd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    __s64 ret;
    __s32 fd;
};

// eventfd_name_event is the enter record of memfd_create and fsopen, the two
// calls whose descriptor is identified by a user-supplied name.
struct eventfd_name_event {
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
    __s32 fd;
    __u32 schema_version;
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

// two_fd_event carries two descriptor arguments and a third word (close_range
// first/last/flags, kcmp's KCMP_FILE indices and packed owner/type): 48 bytes
// in the ring buffer.
struct two_fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd_a;
    __s32 fd_b;
    __u64 extra;
    __u32 schema_version;
};

// two_fd_names_event is two_fd_event plus the two pathnames only move_mount
// passes alongside its descriptors.
struct two_fd_names_event {
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
//
// old_tid is the tid the exec'ing thread had before the exec (the
// tracepoint's old_pid). It differs from tid when a non-leader thread
// exec'd: de_thread() hands it the leader's tid (== pid), so the execve that
// entered under old_tid returns under tid. Userspace re-keys the parked
// execve enter from old_tid to tid on this record so the exit still pairs
// (eventLoop.rekeyExecCaller); the BPF side moves the syscall_enter_state_map
// entry the same way (ior_on_exec_tid_change in filter.c).
//
// exit_untraced (0 or 1; a __u32 because the Go type generator maps only
// 32/64-bit integers) is set when only the pre-exec caller was in scope:
// -tid traced a non-leader thread, whose post-exec (leader) tid the filter
// rejects, so the execve's sys_exit record will never arrive. Userspace then
// completes the parked execve enter from this record
// (eventLoop.completeUntracedExec). The word occupies what used to be an
// explicit tail pad, so the layout stays 48 bytes with no implicit padding
// and kernel and binary.Write payloads share one size.
struct process_exec_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char comm[MAX_PROGNAME_LENGTH];
    __u32 old_tid;
    __u32 exit_untraced;
};

// process_exit_event is not a syscall tracepoint event: it is emitted by the
// hand-written sched:sched_process_exit handler in exec.c, which fires when a
// task (thread) exits. Userspace consumes it as a control event (no enter/exit
// pair, never rendered as a row): tid-keyed state is dropped on every record,
// while the process's (tgid) fdTracker entries are evicted only when
// group_dead is set, i.e. when the last thread of the group has exited - a
// sibling thread's exit must not discard descriptors the process still holds.
// group_dead is a __u32 (0 or 1) because the Go type generator maps only
// 32/64-bit integers; the explicit reserved word keeps the layout at 32 bytes
// with no implicit padding, so kernel and binary.Write payloads share one size.
// Like process_exec_event's siblings it carries no comm: the only payload
// userspace needs is the identity of the task and whether its process died.
struct process_exit_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 group_dead;
    __u32 reserved;
};

// task_newtask_event is not a syscall tracepoint event: it is emitted by the
// hand-written task:task_newtask handler in exec.c when the kernel creates a
// task (fork, vfork, clone or clone3; a new thread is a task too). Userspace
// consumes it as a control event (no enter/exit pair, never rendered as a
// row) that seeds the tid->comm cache with the name the child inherited from
// its parent, before the child's first syscall. The seed is provisional: a
// thread that renames itself is corrected by one later /proc read.
//
// Why: a task's comm was otherwise resolved lazily and asynchronously from
// /proc/<tid>/comm, which loses the race against short-lived tasks (the
// thread has exited before the read, so its rows carry an empty comm) and,
// under -comm, gave the first rows of every new tid whose name was not cached
// yet an empty comm, which the exit-side comm check drops.
//
// pid is the *child's* thread-group id and tid the child's task id: the
// record is emitted from the parent's context, but describes the child.
// clone_flags is the raw flag word of the creating clone (CLONE_THREAD tells
// a new thread from a new process; CLONE_VM/CLONE_FILES tell which resources
// are shared - the basis for fd-table inheritance and shared-table tracking).
// The layout has no implicit padding (clone_flags starts at offset 40), so
// the kernel record and a binary.Write payload share one size, 48 bytes.
struct task_newtask_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char comm[MAX_PROGNAME_LENGTH];
    __u64 clone_flags;
};
