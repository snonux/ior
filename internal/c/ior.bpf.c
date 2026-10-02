//+build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "types.h"
#include "maps.h"
#include "flags.h"

/**
 * Including .c files, as linking several .o files into one single .o file doesn't work
 * with shared BPF state such as ring buffers, maps and globals so well. Other BPF projects
 * come along with one huuuuughe .c file with all the BPF code in it. I am rather 
 * splitting the code up into several smaller files.
 */
#include "filter.c"

// Receive-side capture helpers used by the generated recvmsg handler.
#include "recv.c"

// select timeout normalisation used by the generated select handler.
#include "poll.c"

// File-handle capture used by the generated name_to_handle_at and
// open_by_handle_at handlers.
#include "handle.c"

// File identity of a descriptor (the inode behind an fd number), used by the
// generated single-descriptor enter handlers and the exits of the open kinds.
#include "fileident.c"

// Restart fold: the pending-restart state behind filter.c's enter/exit hooks
// and its two probes (signal:signal_deliver, a second sys_enter_rt_sigreturn).
#include "restart.c"

// Hand-written non-syscall tracepoints (sched:sched_process_exec, sched:sched_process_exit).
#include "exec.c"

// Auto-generated tracepoints.
#include "generated_tracepoints.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
