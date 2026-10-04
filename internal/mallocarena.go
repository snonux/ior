package internal

/*
#include <malloc.h>
#include <stdlib.h>

// ior_limit_malloc_arenas runs before the Go runtime starts its threads
// (a constructor), so glibc's malloc never creates the extra per-thread
// arenas. An explicit MALLOC_ARENA_MAX from the user is left alone.
static void __attribute__((constructor)) ior_limit_malloc_arenas(void) {
    if (getenv("MALLOC_ARENA_MAX") == NULL)
        mallopt(M_ARENA_MAX, 1);
}

static void ior_malloc_trim(void) {
    malloc_trim(0);
}
*/
import "C"

// Task yr2: every TUI trace restart loads and tears down a BPF module, and
// libbpf's load allocations (object, maps, programs, BTF, relocations) are
// made from whichever glibc arena the loading thread has. Go runs the load on
// a different OS thread each time, so with the default arena limit (8 x the
// core count) each restart can grow a new arena and the freed memory is never
// returned: measured anonymous RSS went from 2 MB to ~155-175 MB over 12
// load/close cycles in one process (Go heap ~5 MB, fds and programs back at
// baseline), a glibc arena retention, not a leak. Two mitigations, measured in
// the same loop: a single arena (the constructor above, or MALLOC_ARENA_MAX=1)
// plateaus at ~35 MB; malloc_trim after each teardown alone reaches 60-75 MB.
// Both are applied: the arena cap stops the growth at its source and the trim
// hands the freed pages of the one arena back to the kernel.
//
// releaseFreedHeap returns freed malloc memory to the operating system. It is
// called after a trace session's BPF module is closed (closeTraceInfra).
func releaseFreedHeap() {
	C.ior_malloc_trim()
}
