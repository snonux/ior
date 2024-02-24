//+build ignore

#include "vmlinux.h"
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

// Tracepoints with custom handling.
#include "tracepoints/open.c"
#include "tracepoints/close.c"
#include "tracepoints/write.c"

// More tracepoints, but auto-generated. May lack per-syscall special case handling.
// #include "generated/tracepoints.c"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
