//+build ignore

const volatile u32 IOR_PID_FILTER = -1;
const volatile u32 PID_FILTER = -1;
const volatile u32 TID_FILTER = -1;
// TID_FILTER_TGID is the thread group owning the TID_FILTER thread (resolved
// by userspace at setup, -1 when no tid filter or unresolvable). It scopes the
// group-dead sched_process_exit bypass of the tid filter to that one process;
// see ior_process_exit_in_scope in exec.c.
const volatile u32 TID_FILTER_TGID = -1;
// IOR_FILE_IDENT switches the file-identity capture on (1) or off (0); see
// fileident.c. It is off in the object and switched on by userspace before
// the load, which is also how userspace knows that the file_ident words of
// fd_event and ret_event are written at all: an object built before the
// capture has no such symbol (and leaves those bytes as stale padding).
const volatile u32 IOR_FILE_IDENT = 0;
