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
// Control record of the hand-written task:task_rename handler (exec.c).
#define TASK_RENAME_EVENT 63
// Control record of the restart-fold probes (restart.c): what the kernel does
// with a call a signal interrupted.
#define SYSCALL_RESTART_EVENT 64
// Control record carrying the file handle a successful name_to_handle_at
// returned (ior_emit_file_handle, handle.c).
#define FILE_HANDLE_EVENT 65
// close's enter record when the file it releases has a name to report:
// fd_event plus the last path component (ior_emit_fd_name_enter, fdname.c).
// Only the enter side exists; the exit of close is a ret_event.
#define ENTER_FD_NAME_EVENT 66
// Control record carrying the registered-ring table entries a successful
// io_uring_register(IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS)
// set or released (ior_emit_ring_fds, iouring.c). 66 is ENTER_FD_NAME_EVENT;
// the ids only have to be distinct, not dense.
#define RING_FDS_EVENT 67

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

// Control record carrying a pathname re-read at sys_exit (see "Recovering a
// path whose sys_enter read faulted" in filter.c). slot says which of the
// enter event's path fields it belongs to: OPEN_NAME_FIXUP_SLOT_FIRST for the
// only (or first) path - filename, pathname, oldname - and
// OPEN_NAME_FIXUP_SLOT_SECOND for the newname of the rename/link family and
// move_mount (whose from/to pathnames travel as oldname/newname). slot
// trails the string so the 268-byte prefix (tid at 8, filename at 12) stays
// what older readers decoded; a record of that size reads as slot FIRST.
#define OPEN_NAME_FIXUP_SLOT_FIRST 0
#define OPEN_NAME_FIXUP_SLOT_SECOND 1
struct open_name_fixup_event {
    __u32 event_type;
    __u32 trace_id;
    __u32 tid;
    char filename[MAX_FILENAME_LENGTH];
    __u32 slot;
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
// one, which userspace has always decoded. A close of a file that has a last
// path component is sent as the wider fd_name_event instead (below).
//
// file_ident says which file fd named when the call entered: the low 32 bits
// of its inode number, or 0 for "unknown" (ior_file_ident in fileident.c,
// task 603). It occupies what was the tail padding of the 28-byte record, so
// the size did not change and cannot tell an older object's record apart:
// that one leaves stale ring-buffer bytes there. Userspace therefore reads
// the word only in a run whose object has the IOR_FILE_IDENT global and had
// it switched on (flags.h).
struct fd_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 file_ident;
};

// fd_size_event is fd_event plus the capacity of the caller's output buffer,
// captured for the syscalls whose return value is not by itself a count of
// bytes copied:
//   - the fd-based xattr reads (fgetxattr, flistxattr), whose zero-size call
//     is a size probe returning the required capacity;
//   - recvfrom and recvmsg, where MSG_TRUNC makes the return the datagram's
//     real length rather than the bytes copied into the buffer, and MSG_PEEK
//     copies without consuming.
// flags occupies what was the alignment padding after fd, so the record stays
// 48 bytes. It carries the recv flags argument for recvfrom/recvmsg and is 0
// for every other user; older BPF objects left those four bytes as padding, and
// userspace only interprets flags for the recv syscalls, which older objects
// never sent in this record (they used the size-less fd_event).
struct fd_size_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 flags;
    __u64 size;
    __u32 size_valid;
    __u32 schema_version;
};

// ret_event is the exit record of most syscalls. file_ident is, for the exits
// of the open kinds, the identity of the file behind the descriptor the call
// returned (ior_file_ident_of_ret in fileident.c; 0 = unknown, as in
// fd_event), so that the fd table entry userspace registers knows which file
// it stands for. Every other exit writes 0. Like fd_event's, the word took
// the place of the tail padding of the 36-byte record and is only read in a
// run that switched IOR_FILE_IDENT on.
struct ret_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __s64 ret;
    __u32 pid;
    __u32 tid;
    __u32 ret_type;
    __u32 file_ident;
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

// dup and dup2 are just fd_events, but dup3 also has the additional flags.
//
// file_ident is fd_event's identity word for the old descriptor: which file
// fd named when the call entered (ior_file_ident in fileident.c, task d23),
// 0 = unknown. dup3 copies the fd table entry of fd to the new number, so
// userspace checks that entry against the word exactly as it does for dup
// and dup2. The 32-byte record had no padding to take, so it grew to 40
// (36 bytes of fields plus tail padding); an older object's 32-byte record
// decodes with identity 0. As for fd_event, userspace reads the word only
// in a run that switched IOR_FILE_IDENT on (flags.h).
struct dup3_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __s32 flags;
    __u32 file_ident;
};

// A struct file_handle as the handle syscalls pass it: handle_bytes says how
// many bytes of f_handle are the handle, handle_type how the filesystem encoded
// them, and the two together are what the kernel resolves to a file.
// IOR_MAX_HANDLE_SZ is the kernel's MAX_HANDLE_SZ: name_to_handle_at never
// returns a longer handle and open_by_handle_at rejects one with EINVAL.
//
// handle_status says what the record's handle fields hold:
//   - FILE_HANDLE_NONE: nothing; the record predates the capture (the value an
//     older, shorter record decodes with).
//   - FILE_HANDLE_OK: handle_bytes (0..IOR_MAX_HANDLE_SZ) and handle_type are
//     the caller's, and the first handle_bytes bytes of f_handle are the
//     handle. A zero handle_bytes is reported as it is; no file has such a
//     handle and the kernel rejects it.
//   - FILE_HANDLE_NULL: the handle pointer was NULL.
//   - FILE_HANDLE_READ_FAILED: the nofault read of the header or of the bytes
//     failed (the page is not resident). handle_bytes and handle_type are the
//     header's when only the bytes could not be read, else 0.
//   - FILE_HANDLE_TOO_LARGE: handle_bytes (reported) exceeds
//     IOR_MAX_HANDLE_SZ, so no bytes were read.
//
// Only FILE_HANDLE_OK identifies a handle; userspace treats every other status
// as "handle unknown". f_handle is zero-filled before the read, so a record
// holds the handle and zeros and never stale ring-buffer bytes: these syscalls
// are rare, and the bytes are binary, so there is no terminator a reader could
// stop at (compare "String fields in ring-buffer records" in filter.c).
#define IOR_MAX_HANDLE_SZ 128
#define FILE_HANDLE_NONE 0
#define FILE_HANDLE_OK 1
#define FILE_HANDLE_NULL 2
#define FILE_HANDLE_READ_FAILED 3
#define FILE_HANDLE_TOO_LARGE 4

// The handle fields were appended (task k03): handle_status sits in what was
// the implicit tail pad of the 32-byte record, which an older object leaves
// unwritten, so a record of that size is decoded by its length as
// FILE_HANDLE_NONE rather than by that word. The layout has no implicit
// padding: 168 bytes for the kernel record and a binary.Write payload alike.
struct open_by_handle_at_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 flags;
    __u32 handle_status;
    __u32 handle_bytes;
    __s32 handle_type;
    __u8 f_handle[IOR_MAX_HANDLE_SZ];
};

// file_handle_event is a control record, not a syscall event: the exit handler
// of name_to_handle_at emits it after a successful return, with the handle the
// kernel wrote into the caller's buffer, and reserves it before the exit
// record of the same call (ior_emit_file_handle, handle.c). Userspace files
// the pathname of the still-pending enter under that handle, so that an
// open_by_handle_at carrying the same handle - on any thread or process - can
// be named (handleFileHandleEvent, internal/eventloop_handle.go). It is never
// rendered as a row.
//
// trace_id is the ENTER trace ID of the call (SYS_ENTER_NAME_TO_HANDLE_AT).
// The record names both ends of its call by their clock reads, because
// userspace must not pair it by position:
//   - time is the exit handler's single clock read and therefore equals the
//     time of the exit record that follows, bit for bit; userspace accepts the
//     handle only for an exit with that time, so a record whose exit was lost
//     is not claimed by a later call of the tid.
//   - enter_time is the start_ns of the enter state the exit handler found,
//     i.e. the time of the call's own enter record (the enter handler stamps
//     both with one clock read). Userspace accepts the record only while the
//     enter it has pending for the tid carries that time: the pathname it
//     files is the pending enter's, and that enter is an EARLIER call's when
//     that call's exit record and this call's enter record were both lost (or
//     the enter was shed by the raw path filter).
// Both checks compare clock reads of one tid that have at least a syscall
// entry or exit between them; a clock too coarse to tell those apart could
// make two calls look alike, which is accepted.
//
// Only a handle that was read completely is submitted, so handle_status is
// always FILE_HANDLE_OK; the word is kept so that the handle fields sit at
// the offsets they have in open_by_handle_at_event (reserved is where that
// record has flags, and is 0). enter_time was appended behind them for the
// same reason. No implicit padding, 176 bytes.
struct file_handle_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 reserved;
    __u32 handle_status;
    __u32 handle_bytes;
    __s32 handle_type;
    __u8 f_handle[IOR_MAX_HANDLE_SZ];
    __u64 enter_time;
};

// The two io_uring_register opcodes that change a thread's registered-ring
// table (<linux/io_uring.h>: IORING_REGISTER_RING_FDS and
// IORING_UNREGISTER_RING_FDS), the table's size (IO_RINGFD_REG_MAX, the most
// entries one call takes) and the size of one array element, struct
// io_uring_rsrc_update {__u32 offset; __u32 resv; __u64 data;}. All four are
// syscall ABI.
#define IOR_REGISTER_RING_FDS 20
#define IOR_UNREGISTER_RING_FDS 21
#define IOR_RING_FDS_MAX 16
#define IOR_RING_FD_UPDATE_SIZE 16
#define IOR_RING_FDS_BYTES 256

// Status of the array read of a ring_fds_event:
//   - RING_FDS_OK: updates holds count entries.
//   - RING_FDS_READ_FAILED: the nofault read of the array failed.
//   - RING_FDS_TOO_MANY: the call returned more entries than the table has,
//     which these opcodes cannot; nothing was read.
// For both failures count is 0, and userspace forgets the thread's table.
#define RING_FDS_OK 1
#define RING_FDS_READ_FAILED 2
#define RING_FDS_TOO_MANY 3

// ring_fds_event is a control record, not a syscall event: the exit handler
// of io_uring_register emits it for the two opcodes above after a return
// that processed at least one entry, ahead of the call's exit record and
// whether or not the sampling rate emits that one (ior_emit_ring_fds,
// iouring.c). It is never rendered as a row; userspace applies it to the
// registered-ring table of the thread tid (handleRingFdsEvent,
// internal/eventloop_ringfds.go).
//
// trace_id is the ENTER trace ID of the call (SYS_ENTER_IO_URING_REGISTER),
// opcode the io_uring_register opcode without the
// IORING_REGISTER_USE_REGISTERED_RING bit. time is the exit handler's single
// clock read and therefore equals the time of the exit record that follows,
// bit for bit: an exit of such a call without a record of that time tells
// userspace that the record was lost.
//
// updates holds the first count elements of the caller's array as the kernel
// left them, IOR_RING_FD_UPDATE_SIZE bytes each in host byte order: offset
// (the index, after IORING_REGISTER_RING_FDS the one the kernel allocated),
// resv, and data (the ring descriptor of a registration, 0 of a release).
// The bytes past them are zeros. No implicit padding, 296 bytes.
struct ring_fds_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 opcode;
    __u32 status;
    __u32 count;
    __u32 reserved;
    __u8 updates[IOR_RING_FDS_BYTES];
};

// fd_name_event is fd_event plus the last path component of the file the
// descriptor names while the call enters. The enter handler of close sends
// it instead of an fd_event when that file has such a name
// (ior_emit_fd_name_enter in fdname.c, task xz2): userspace cannot ask procfs
// about a descriptor that is closed by the time its row is processed, so the
// close of a descriptor ior never saw opened had no name at all
// (internal/eventloop_procfs_close.go). Every other close - a pipe, a
// socket, an anonymous-inode file, the root of a mount (the root directory
// of a filesystem, a mounted subvolume, a bind-mounted directory or single
// file: its dentry is named after its source, not after what was opened),
// any close on a kernel that cannot run the walk or in a run that switched
// IOR_FILE_IDENT off - is the plain 32-byte fd_event as before.
//
// The first 32 bytes are fd_event's, file_ident included, so userspace
// decodes the record into the same event and handles the pair as any close.
// name is the dentry's own name, NUL-terminated and cut to
// IOR_FD_NAME_LENGTH - 1 bytes (the bytes after the NUL are stale ring-buffer
// memory, see "String fields in ring-buffer records" in filter.c); name_len
// is its real length, so a value of IOR_FD_NAME_LENGTH or more says the name
// was cut - provided the text also fills the field. 0 says there is no name
// after all (the read failed). The name can hold an earlier NUL than
// name_len says when the close raced a rename of its file (fdname.c);
// userspace stops at the first one and then does not take the name for a cut
// one, whatever the length (FdEvent.LeafName). The
// length is a compromise: every close of a file below a directory pays for
// the record, a component may be 255 bytes long, and 67 hold a 64-digit
// content hash with a short suffix. The layout has no implicit padding, so
// the kernel record and a binary.Write payload share one size, 104 bytes.
#define IOR_FD_NAME_LENGTH 68
struct fd_name_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __s32 fd;
    __u32 file_ident;
    __u32 name_len;
    char name[IOR_FD_NAME_LENGTH];
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
// 32/64-bit integers; the explicit exit_flags word keeps the layout at 32 bytes
// with no implicit padding, so kernel and binary.Write payloads share one size.
// exit_flags bit 0 (IOR_EXIT_TID_INHERITED, exec.c) marks the exit of a
// thread-group leader that another thread's execve killed in de_thread(): the
// exec'ing thread takes over the leader's tid (and start time), so the tid
// lives on in the new program although this task died. The word was the
// always-zero "reserved" before, so an older object reads as "tid gone".
// Like process_exec_event's siblings it carries no comm: the only payload
// userspace needs is the identity of the task and whether its process died.
struct process_exit_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 group_dead;
    __u32 exit_flags;
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
// creator_pid is the tgid of the task that called clone (the handler's own
// context): the process whose descriptor table a fork()ed child starts from,
// which the child's pid/tid alone cannot name. A record of a pre-creator_pid
// IOR_BPF_OBJECT is 48 bytes long and decodes with creator_pid 0 ("unknown").
// The layout has no implicit padding (clone_flags starts at offset 40 and the
// explicit scope_flags word completes the trailing 8-byte alignment), so the
// kernel record and a binary.Write payload share one size, 56 bytes.
// scope_flags bit 0 (IOR_NEWTASK_CHILD_OUT_OF_SCOPE) marks the one record
// emitted for a child the PID/TID filter excludes: a CLONE_FILES process child
// of an in-scope creator, whose invisible descriptor-table writes change the
// creator's table. The word was the always-zero "reserved" before, so an older
// object reads as "child in scope".
struct task_newtask_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char comm[MAX_PROGNAME_LENGTH];
    __u64 clone_flags;
    __u32 creator_pid;
    __u32 scope_flags;
};

// task_rename_event is a control record, not a syscall event: the hand-written
// task:task_rename handler in exec.c emits it whenever the kernel changes a
// task's comm (prctl(PR_SET_NAME), pthread_setname_np, a /proc/<tid>/comm
// write, and the exec's own rename). Userspace applies it to the tid->comm
// cache (handleTaskRenameEvent); it is never rendered as a row.
//
// pid is the renamed task's thread-group id and tid its task id - the
// *renamed* task, which a /proc/<tid>/comm write makes different from the
// task that emitted the record. comm is the new name, NUL-terminated by the
// handler (bytes after the NUL are stale ring-buffer memory, see "String
// fields in ring-buffer records" in filter.c). The layout has no implicit
// padding, so the kernel record and a binary.Write payload share one size,
// 40 bytes.
struct task_rename_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    char comm[MAX_PROGNAME_LENGTH];
};

// Phase of a syscall_restart_event (see there).
#define RESTART_PHASE_HANDLER 1
#define RESTART_PHASE_RESUME 2

// syscall_restart_event is a control record, not a syscall event: restart.c
// emits it for a task whose last traced syscall exit carried -ERESTARTSYS,
// -ERESTARTNOINTR, -ERESTARTNOHAND or -ERESTART_RESTARTBLOCK
// (-512/-513/-514/-516), so userspace can fold the interrupted row and the
// kernel's continuation of the call - its re-execution, or for -516 its
// restart_syscall - into one row (tasks 103 and t13,
// internal/eventloop_restart.go). It is never rendered as a row.
//
// phase says which of two things happened:
//   - RESTART_PHASE_HANDLER: the signal:signal_deliver probe saw the first
//     user handler being run for the interrupted call. sa_restart is 1 when
//     that handler was installed with SA_RESTART, else 0; with the return code
//     userspace holds it decides, by the kernel's handle_signal rules, whether
//     the call still restarts once the handler returns or the program gets
//     EINTR.
//   - RESTART_PHASE_RESUME: the task's syscall enter that follows this record
//     is the kernel's continuation of the interrupted call: the same syscall
//     again, or restart_syscall after -516 (when restart_syscall is traced;
//     otherwise the record precedes some later enter, which userspace tells
//     by its syscall). It is the only record that licenses a fold; sa_restart
//     is 0.
//
// time is the boot clock, as in every record. For RESUME it is more than a
// timestamp: it equals the time field of the enter record the RESUME
// announces, bit for bit (both are the enter handler's single clock read).
// That enter may be sampled out or lost after RESUME was emitted, so
// userspace accepts as the continuation only an enter with this exact time;
// the task's next call of the same syscall has a later one. For HANDLER it is
// the time of the delivery.
//
// pid/tid name the interrupted task (every such record is emitted in its own
// context). sa_restart is a __u32 (0 or 1) because the Go type generator maps
// only 32/64-bit integers; with phase it completes the 8-byte alignment, so
// the layout has no implicit padding and the kernel record and a binary.Write
// payload share one size, 32 bytes.
struct syscall_restart_event {
    __u32 event_type;
    __u32 trace_id;
    __u64 time;
    __u32 pid;
    __u32 tid;
    __u32 phase;
    __u32 sa_restart;
};
