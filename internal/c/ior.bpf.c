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

// Hand-written non-syscall tracepoints (sched:sched_process_exec, sched:sched_process_exit).
#include "exec.c"

// Auto-generated tracepoints.
#include "generated_tracepoints.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
