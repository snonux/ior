//+build ignore

const volatile u32 IOR_PID_FILTER = -1;
const volatile u32 PID_FILTER = -1;
const volatile u32 TID_FILTER = -1;
// TID_FILTER_TGID is the thread group owning the TID_FILTER thread (resolved
// by userspace at setup, -1 when no tid filter or unresolvable). It scopes the
// group-dead sched_process_exit bypass of the tid filter to that one process;
// see ior_process_exit_in_scope in exec.c.
const volatile u32 TID_FILTER_TGID = -1;
