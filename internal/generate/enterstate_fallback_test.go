package generate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The syscall accounting in internal/c/filter.c keeps syscall_aggregate_map
// and the ring-buffer stream an exact partition of the invocations, also when
// syscall_enter_state_map has no entry for a sys_exit ("Enter state and its
// two fallbacks" there). Instead of pinning source text, these tests cut the
// real accounting functions out of filter.c, compile them with the host C
// compiler against simulated BPF maps, and drive them through the scenarios
// that matter: sampling, full maps, failed replacements, clone-child and
// mismatched exits, untimed counts, min/max seeding and the enter-state move
// of a non-leader execve (ior_on_exec_tid_change). Each scenario is also
// run against mutated sources, so the suite is shown to catch the
// regressions it exists for.

// accountingFunctions are the filter.c functions the harness compiles, in
// dependency order.
var accountingFunctions = []string{
	"ior_is_restart_ret",
	"ior_is_errno_ret",
	"ior_histogram_bucket_index",
	"ior_aggregate_has_timed_samples",
	"ior_update_syscall_aggregate",
	"ior_count_untimed_syscall",
	"ior_sampling_rate",
	"ior_sample_rate_emits",
	"ior_on_enter_state_lost",
	"ior_stateless_exit_emits",
	"ior_on_syscall_enter_impl",
	"ior_on_syscall_enter",
	"ior_on_syscall_enter_stateful",
	"ior_on_syscall_exit_impl",
	"ior_on_syscall_exit",
	"ior_on_syscall_exit_take_filename",
	"ior_on_syscall_exit_take_filenames",
	"ior_stash_pending_filename",
	"ior_stash_pending_filename2",
	"ior_on_exec_tid_change",
}

// accountingHarnessTemplate provides the BPF helpers the functions use as a
// small in-process map simulation. Updates of a new key fail with -E2BIG once
// the map holds cap entries (as a full BPF hash does); "fail 1" makes every
// update of the enter-state map fail with -EBUSY, including replacements.
// "exectid old new scope" runs the sched_process_exec move of a non-leader
// exec (ior_on_exec_tid_change). Every command prints exactly one line.
const accountingHarnessTemplate = `#include <errno.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_ANY 0

%s
%s

#define SIM_SLOTS 64
struct sim_map {
    unsigned cap, vsize;
    int fail;
    int used[SIM_SLOTS];
    __u32 keys[SIM_SLOTS];
    unsigned char vals[SIM_SLOTS][128];
};
static struct sim_map syscall_enter_state_map = { SIM_SLOTS, sizeof(struct syscall_enter_state) };
static struct sim_map syscall_aggregate_map = { SIM_SLOTS, sizeof(struct syscall_aggregate) };
static struct sim_map syscall_sampling_rate_map = { SIM_SLOTS, sizeof(__u32) };
static __u32 sim_rand;

/* filter.c's stand-in for the kernel errno must match it. */
_Static_assert(IOR_E2BIG == E2BIG, "IOR_E2BIG differs from E2BIG");

static int sim_find(struct sim_map *m, __u32 key) {
    for (int i = 0; i < SIM_SLOTS; i++)
        if (m->used[i] && m->keys[i] == key)
            return i;
    return -1;
}

static unsigned sim_len(struct sim_map *m) {
    unsigned n = 0;
    for (int i = 0; i < SIM_SLOTS; i++)
        n += m->used[i] != 0;
    return n;
}

static void *bpf_map_lookup_elem(void *map, const void *key) {
    struct sim_map *m = map;
    int i = sim_find(m, *(const __u32 *)key);
    return i < 0 ? NULL : m->vals[i];
}

static long bpf_map_update_elem(void *map, const void *key, const void *value, __u64 flags) {
    struct sim_map *m = map;
    __u32 k = *(const __u32 *)key;
    int i = sim_find(m, k);
    (void)flags;
    if (m->fail)
        return -EBUSY;
    if (i < 0) {
        if (sim_len(m) >= m->cap)
            return -E2BIG;
        for (i = 0; m->used[i]; i++)
            ;
        m->used[i] = 1;
        m->keys[i] = k;
    }
    memcpy(m->vals[i], value, m->vsize);
    return 0;
}

static long bpf_map_delete_elem(void *map, const void *key) {
    struct sim_map *m = map;
    int i = sim_find(m, *(const __u32 *)key);
    if (i < 0)
        return -ENOENT;
    m->used[i] = 0;
    /* A deleted element's memory is not defined (the kernel frees or reuses it):
     * poison it, so a hook that reads the entry after deleting it (the pending
     * filename pointers must be copied out first) is caught by its output. */
    memset(m->vals[i], 0xA5, m->vsize);
    return 0;
}

static __u32 bpf_get_prandom_u32(void) {
    return sim_rand;
}

/* The restart fold's two hook entry points (restart.c) are not part of the
 * accounting: they are identity stand-ins here, and restart_harness_test.go
 * drives the real ones. */
static inline void ior_restart_on_enter(__u32 tid, __u64 now) {
    (void)tid;
    (void)now;
}

static inline int ior_restart_on_exit(__u32 tid, __s64 ret, int emits) {
    (void)tid;
    (void)ret;
    return emits;
}

%s

static void print_aggregate(__u32 id) {
    struct syscall_aggregate *a = bpf_map_lookup_elem(&syscall_aggregate_map, &id);
    if (!a) {
        printf("none\n");
        return;
    }
    printf("count=%%llu errors=%%llu total=%%llu min=%%llu max=%%llu hist=%%llu,%%llu,%%llu,%%llu,%%llu,%%llu,%%llu,%%llu\n",
           a->count, a->errors, a->total_duration_ns, a->min_duration_ns, a->max_duration_ns,
           a->duration_histogram[0], a->duration_histogram[1], a->duration_histogram[2],
           a->duration_histogram[3], a->duration_histogram[4], a->duration_histogram[5],
           a->duration_histogram[6], a->duration_histogram[7]);
}

int main(void) {
    char cmd[16];
    unsigned long long a, b, c, d;
    long long ret;
    while (scanf("%%15s", cmd) == 1) {
        if (!strcmp(cmd, "rate") && scanf("%%llu %%llu", &a, &b) == 2) {
            /* The BPF map is an array that stores rate + 1 (0 = not configured). */
            __u32 k = a, v = b + 1;
            bpf_map_update_elem(&syscall_sampling_rate_map, &k, &v, BPF_ANY);
            printf("ok\n");
        } else if (!strcmp(cmd, "cap") && scanf("%%llu", &a) == 1) {
            syscall_enter_state_map.cap = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "fail") && scanf("%%llu", &a) == 1) {
            syscall_enter_state_map.fail = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "rand") && scanf("%%llu", &a) == 1) {
            sim_rand = a;
            printf("ok\n");
        } else if (!strcmp(cmd, "enter") && scanf("%%llu %%llu %%llu", &a, &b, &c) == 3) {
            printf("emit=%%d\n", ior_on_syscall_enter(a, b, c));
        } else if (!strcmp(cmd, "entersf") && scanf("%%llu %%llu %%llu", &a, &b, &c) == 3) {
            printf("emit=%%d\n", ior_on_syscall_enter_stateful(a, b, c));
        } else if (!strcmp(cmd, "exit") && scanf("%%llu %%llu %%lld %%llu", &a, &b, &ret, &d) == 4) {
            printf("emit=%%d\n", ior_on_syscall_exit(a, b, ret, d));
        } else if (!strcmp(cmd, "exitf") && scanf("%%llu %%llu %%lld %%llu", &a, &b, &ret, &d) == 4) {
            /* The path handlers' exit: the out pointers start as garbage, so a
             * stateless or foreign-entry exit must write the 0 itself. */
            __u64 p1 = 0xdeadbeef;
            int emit = ior_on_syscall_exit_take_filename(a, b, ret, d, &p1);
            printf("emit=%%d p1=%%llu\n", emit, p1);
        } else if (!strcmp(cmd, "exitf2") && scanf("%%llu %%llu %%lld %%llu", &a, &b, &ret, &d) == 4) {
            __u64 p1 = 0xdeadbeef, p2 = 0xfeedface;
            int emit = ior_on_syscall_exit_take_filenames(a, b, ret, d, &p1, &p2);
            printf("emit=%%d p1=%%llu p2=%%llu\n", emit, p1, p2);
        } else if (!strcmp(cmd, "stash") && scanf("%%llu %%llu %%llu", &a, &b, &c) == 3) {
            ior_stash_pending_filename(a, b);
            ior_stash_pending_filename2(a, c);
            printf("ok\n");
        } else if (!strcmp(cmd, "exectid") && scanf("%%llu %%llu %%llu", &a, &b, &c) == 3) {
            ior_on_exec_tid_change(a, b, c);
            printf("ok\n");
        } else if (!strcmp(cmd, "agg") && scanf("%%llu", &a) == 1) {
            print_aggregate(a);
        } else if (!strcmp(cmd, "state") && scanf("%%llu", &a) == 1) {
            __u32 k = a;
            struct syscall_enter_state *s = bpf_map_lookup_elem(&syscall_enter_state_map, &k);
            if (s)
                printf("state id=%%u emit=%%u\n", s->enter_trace_id, s->emit_event);
            else
                printf("nostate\n");
        } else {
            printf("bad command %%s\n", cmd);
            return 1;
        }
    }
    return 0;
}
`

// accountingStep is one harness command and the line it must print.
type accountingStep struct {
	cmd  string
	want string
}

type accountingScenario struct {
	name  string
	steps []accountingStep
}

const (
	accAggNone = "none"
	accEmit0   = "emit=0"
	accEmit1   = "emit=1"
	accOK      = "ok"
)

// accountingScenarios use trace IDs 100 (rate 0), 200 (rate 1, also the
// default of an unconfigured ID) and 300 (rate 4). A duration of 5000ns lands
// in histogram bucket 1 (1us..10us), 50000ns in bucket 2.
var accountingScenarios = []accountingScenario{
	{name: "partition by rate", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK},
		{"enter 1 200 1000", accEmit1}, {"exit 1 200 0 6000", accEmit1}, {"agg 200", accAggNone},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -2 6000", accEmit0},
		{"agg 100", "count=1 errors=1 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"rand 0", accOK}, {"enter 1 300 1000", accEmit1}, {"exit 1 300 0 6000", accEmit1}, {"agg 300", accAggNone},
		{"rand 1", accOK}, {"enter 1 300 1000", accEmit0}, {"exit 1 300 0 6000", accEmit0},
		{"agg 300", "count=1 errors=0 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"state 1", "nostate"},
	}},
	// A signal-interrupted call exits with a kernel restart code that user
	// space never sees (the call is restarted or becomes -EINTR). It is
	// aggregated as a call, with its latency, but never as an error; a real
	// errno such as -EINTR (-4) and the neighbours of the restart codes
	// (-511, -515, -517) still are.
	{name: "restart codes are not errors", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -512 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -513 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -514 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -516 6000", accEmit0},
		{"agg 100", "count=4 errors=0 total=20000 min=5000 max=5000 hist=0,4,0,0,0,0,0,0"},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -4 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -511 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -515 6000", accEmit0},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 -517 6000", accEmit0},
		{"agg 100", "count=8 errors=4 total=40000 min=5000 max=5000 hist=0,8,0,0,0,0,0,0"},
	}},
	// A clone/fork child's first return has no enter state: never counted,
	// and emitted only where a rate-1 enter would have been.
	{name: "stateless exit follows the rate", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK},
		{"exit 7 100 0 5000", accEmit0}, {"exit 7 300 0 5000", accEmit0}, {"exit 7 200 0 5000", accEmit1},
		{"agg 100", accAggNone}, {"agg 300", accAggNone}, {"agg 200", accAggNone},
	}},
	// A leftover entry of another syscall is dropped and the exit treated
	// as stateless, not paired with the foreign state.
	{name: "mismatched exit is stateless", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 200 1000", accEmit1}, {"exit 1 100 0 6000", accEmit0},
		{"state 1", "nostate"}, {"agg 100", accAggNone}, {"agg 200", accAggNone},
	}},
	// Task 2s2: at rate 1 an ordinary enter writes no state (its exit is the
	// stateless emit, the same as a lost entry), while the stateful hook of
	// the pending-filename handlers keeps the entry at every rate; the other
	// rates always keep it, since they carry the sampling decision.
	{name: "rate 1 elides the enter state", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK}, {"rand 0", accOK},
		{"enter 1 200 1000", accEmit1}, {"state 1", "nostate"},
		{"exit 1 200 0 6000", accEmit1}, {"state 1", "nostate"}, {"agg 200", accAggNone},
		{"enter 1 100 1000", accEmit0}, {"state 1", "state id=100 emit=0"},
		{"exit 1 100 0 6000", accEmit0}, {"state 1", "nostate"},
		{"enter 1 300 1000", accEmit1}, {"state 1", "state id=300 emit=1"},
		{"exit 1 300 0 6000", accEmit1}, {"state 1", "nostate"},
		{"agg 100", "count=1 errors=0 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"agg 300", accAggNone},
	}},
	{name: "stateful enter keeps the rate-1 state", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 200 1000", accEmit1}, {"state 1", "state id=200 emit=1"},
		{"exit 1 200 0 6000", accEmit1}, {"state 1", "nostate"}, {"agg 200", accAggNone},
		{"entersf 1 100 1000", accEmit0}, {"state 1", "state id=100 emit=0"},
		{"exit 1 100 0 6000", accEmit0}, {"state 1", "nostate"},
	}},
	// Enter-state map full: a new tid's write fails. Rate 1 still emits the
	// pair; other rates count the invocation once, untimed, at enter.
	{name: "full enter-state map", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK}, {"cap 1", accOK}, {"rand 0", accOK},
		{"entersf 1 200 1000", accEmit1},
		{"entersf 2 200 1000", accEmit1}, {"exit 2 200 0 6000", accEmit1}, {"agg 200", accAggNone},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 6000", accEmit0},
		{"agg 100", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"enter 2 300 1000", accEmit0}, {"exit 2 300 0 6000", accEmit0},
		{"agg 300", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"enter 2 100 1000", accEmit0},
		{"agg 100", "count=2 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
	}},
	// A failed replacement must not leave the tid's older entry behind: its
	// exit would otherwise aggregate the call a second time.
	{name: "failed replacement drops the old entry", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 1000", accEmit0}, {"state 1", "state id=100 emit=0"},
		{"fail 1", accOK}, {"enter 1 100 2000", accEmit0}, {"state 1", "nostate"},
		{"fail 0", accOK}, {"exit 1 100 0 9000", accEmit0},
		{"agg 100", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
	}},
	// Untimed counts must not seed or pin the minimum; the first timed
	// sample does, later ones only lower it.
	{name: "untimed then timed seeds min", steps: []accountingStep{
		{"rate 100 0", accOK}, {"cap 1", accOK},
		{"entersf 1 200 0", accEmit1},
		{"enter 2 100 0", accEmit0}, {"exit 2 100 0 0", accEmit0},
		{"cap 64", accOK},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 51000", accEmit0},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 6000", accEmit0},
		{"enter 2 100 1000", accEmit0}, {"exit 2 100 0 81000", accEmit0},
		{"agg 100", "count=4 errors=0 total=135000 min=5000 max=80000 hist=0,1,2,0,0,0,0,0"},
	}},
	// Equal enter/exit readings (coarse clocksource) or a start ahead of now
	// must still record a non-zero duration: userspace reads min or max of 0
	// with histogram samples as a first sample still being written.
	{name: "zero-length sample records 1ns", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 5000", accEmit0}, {"exit 1 100 0 5000", accEmit0},
		{"enter 1 100 9000", accEmit0}, {"exit 1 100 0 8000", accEmit0},
		{"agg 100", "count=2 errors=0 total=2 min=1 max=1 hist=2,0,0,0,0,0,0,0"},
	}},
	// A non-leader execve enters under the caller's tid (5) and returns
	// under the leader's (1): sched_process_exec moves the entry, so the exit
	// pairs with its own start time and sampling decision, overwriting
	// whatever the dead leader left behind, and nothing stays under 5.
	{name: "non-leader exec moves the enter state", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 200 0", accEmit1},
		{"enter 5 100 1000", accEmit0}, {"exectid 5 1 1", accOK},
		{"state 5", "nostate"}, {"state 1", "state id=100 emit=0"},
		{"exit 1 100 0 6000", accEmit0}, {"state 1", "nostate"},
		{"agg 100", "count=1 errors=0 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
		{"entersf 6 200 1000", accEmit1}, {"exectid 6 1 1", accOK},
		{"exit 1 200 0 6000", accEmit1}, {"agg 200", accAggNone},
	}},
	// An exec that keeps its tid, or one with no in-flight entry, moves
	// nothing.
	{name: "exec without a tid change moves nothing", steps: []accountingStep{
		{"entersf 5 200 1000", accEmit1}, {"exectid 5 5 1", accOK}, {"state 5", "state id=200 emit=1"},
		{"exectid 7 1 1", accOK}, {"state 1", "nostate"}, {"state 7", "nostate"},
	}},
	// On a full map the old entry's slot is freed before the insert, so the
	// move still lands.
	{name: "exec move on a full map", steps: []accountingStep{
		{"cap 2", accOK},
		{"entersf 9 200 1000", accEmit1}, {"entersf 5 200 1000", accEmit1}, {"exectid 5 1 1", accOK},
		{"state 1", "state id=200 emit=1"}, {"state 5", "nostate"},
	}},
	// The move cannot land: a failed insert falls back like a lost enter
	// state (untimed count unless rate 1); an out-of-scope new tid (its exit
	// is filtered) counts a not-emitted invocation here, and leaves an
	// emitted one to userspace.
	{name: "exec move fallbacks count once", steps: []accountingStep{
		{"rate 100 0", accOK}, {"rate 300 4", accOK}, {"rand 0", accOK},
		{"enter 5 100 1000", accEmit0}, {"exectid 5 1 0", accOK},
		{"state 5", "nostate"}, {"state 1", "nostate"},
		{"agg 100", "count=1 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"enter 5 300 1000", accEmit1}, {"exectid 5 1 0", accOK}, {"agg 300", accAggNone},
		{"enter 5 100 1000", accEmit0},
		{"fail 1", accOK}, {"exectid 5 1 1", accOK}, {"fail 0", accOK},
		{"state 5", "nostate"}, {"state 1", "nostate"},
		{"agg 100", "count=2 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		{"exit 1 100 0 6000", accEmit0},
		{"agg 100", "count=2 errors=0 total=0 min=0 max=0 hist=0,0,0,0,0,0,0,0"},
		// At rate 1 a failed insert counts nothing: the stateless exit is
		// emitted and pairs with the emitted enter in userspace.
		{"entersf 5 200 1000", accEmit1},
		{"fail 1", accOK}, {"exectid 5 1 1", accOK}, {"fail 0", accOK},
		{"state 5", "nostate"}, {"state 1", "nostate"}, {"agg 200", accAggNone},
		{"exit 1 200 0 6000", accEmit1}, {"agg 200", accAggNone},
	}},
	// Task 0t2: the path handlers' exit hook returns the stashed pointers out
	// of its own single enter-state lookup. They come back only for an entry
	// of the same syscall; a missing or foreign entry yields 0 (the harness
	// presets the outputs to garbage), the pointers are read before the entry
	// is deleted (the harness poisons deleted entries), and the one-slot
	// variant never reports the second slot.
	{name: "exit hook returns the stashed pointers", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK},
		{"exitf2 1 200 0 6000", "emit=1 p1=4096 p2=8192"}, {"state 1", "nostate"},
		{"entersf 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK},
		{"exitf 1 200 0 6000", "emit=1 p1=4096"}, {"state 1", "nostate"},
		{"entersf 1 200 1000", accEmit1}, {"stash 1 0 8192", accOK},
		{"exitf2 1 200 0 6000", "emit=1 p1=0 p2=8192"},
	}},
	{name: "exit hook takes each pointer once", steps: []accountingStep{
		{"entersf 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK},
		{"exitf2 1 200 0 6000", "emit=1 p1=4096 p2=8192"},
		{"exitf2 1 200 0 6000", "emit=1 p1=0 p2=0"}, {"exitf 1 200 0 6000", "emit=1 p1=0"},
	}},
	{name: "exit hook without an entry returns no pointers", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"exitf2 1 200 0 6000", "emit=1 p1=0 p2=0"}, {"exitf 1 200 0 6000", "emit=1 p1=0"},
		{"exitf2 1 100 0 6000", "emit=0 p1=0 p2=0"}, {"agg 100", accAggNone},
	}},
	{name: "exit hook ignores a foreign entry's pointers", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK},
		{"exitf2 1 100 0 6000", "emit=0 p1=0 p2=0"}, {"state 1", "nostate"}, {"agg 100", accAggNone},
		{"entersf 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK},
		{"exitf 1 100 0 6000", "emit=0 p1=0"}, {"state 1", "nostate"},
		// The foreign entry was dropped, not paired: the next exit is stateless.
		{"exitf2 1 200 0 6000", "emit=1 p1=0 p2=0"},
	}},
	// A not-emitted syscall (rate 0) still gets its aggregate count from the
	// same hook that hands the pointers back; the handler then returns before
	// using them.
	{name: "exit hook keeps the accounting", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"entersf 1 100 1000", accEmit0}, {"stash 1 4096 8192", accOK},
		{"exitf2 1 100 -2 6000", "emit=0 p1=4096 p2=8192"}, {"state 1", "nostate"},
		{"agg 100", "count=1 errors=1 total=5000 min=5000 max=5000 hist=0,1,0,0,0,0,0,0"},
	}},
	// A non-stateful rate-1 enter writes no entry (task 2s2), so there is
	// nothing to stash into and nothing to take.
	{name: "no pointers without a rate-1 entry", steps: []accountingStep{
		{"enter 1 200 1000", accEmit1}, {"stash 1 4096 8192", accOK}, {"state 1", "nostate"},
		{"exitf2 1 200 0 6000", "emit=1 p1=0 p2=0"},
	}},
	{name: "timed then untimed keeps min", steps: []accountingStep{
		{"rate 100 0", accOK},
		{"enter 1 100 1000", accEmit0}, {"exit 1 100 0 51000", accEmit0},
		{"cap 1", accOK}, {"entersf 3 200 0", accEmit1}, {"enter 2 100 0", accEmit0},
		{"agg 100", "count=2 errors=0 total=50000 min=50000 max=50000 hist=0,0,1,0,0,0,0,0"},
	}},
}

func TestSyscallAccountingScenarios(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	binary := compileAccountingHarness(t, filterC, mapsH)
	for _, sc := range accountingScenarios {
		t.Run(sc.name, func(t *testing.T) {
			for _, problem := range runAccountingScenario(t, binary, sc) {
				t.Error(problem)
			}
		})
	}
}

// TestSyscallAccountingScenariosCatchRegressions compiles plausible
// regressions of filter.c and requires at least one scenario to fail on each.
// accountingMutations are plausible regressions of filter.c as {anchor,
// replacement} pairs; each anchor occurs exactly once in the source.
func accountingMutations() map[string][2]string {
	return map[string][2]string{
		"enter ignores a failed write": {
			"        return ior_on_enter_state_lost(enter_trace_id, rate);\n    }",
			"    }",
		},
		"rate 1 writes the enter state anyway": {
			"if (rate == 1 && !keep_state)",
			"if (0)",
		},
		"stateful hook elides the rate-1 state": {
			"return ior_on_syscall_enter_impl(tid, enter_trace_id, now, 1);",
			"return ior_on_syscall_enter_impl(tid, enter_trace_id, now, 0);",
		},
		"elision ignores the rate": {
			"if (rate == 1 && !keep_state)",
			"if (!keep_state)",
		},
		"delete skipped for every error": {
			"if (err != -IOR_E2BIG)",
			"if (0)",
		},
		"failed replacement keeps the old entry": {
			"            bpf_map_delete_elem(&syscall_enter_state_map, &tid);\n",
			"            (void)tid;\n",
		},
		"pending pointer not taken": {
			"*pending_filename = state->pending_filename;",
			"*pending_filename = 0;",
		},
		"second pending pointer not taken": {
			"*pending_filename2 = state->pending_filename2;",
			"*pending_filename2 = 0;",
		},
		"foreign entry leaks its pending pointer": {
			"    if (state->enter_trace_id != enter_trace_id) {\n        bpf_map_delete_elem(&syscall_enter_state_map, &tid);",
			"    if (state->enter_trace_id != enter_trace_id) {\n        if (pending_filename)\n            *pending_filename = state->pending_filename;\n        bpf_map_delete_elem(&syscall_enter_state_map, &tid);",
		},
		"stateless exit leaves the pointers unset": {
			"    if (pending_filename)\n        *pending_filename = 0;\n    if (pending_filename2)\n        *pending_filename2 = 0;\n",
			"",
		},
		"pending pointer read after the delete": {
			"    bpf_map_delete_elem(&syscall_enter_state_map, &tid);\n    return emit_event != 0;",
			"    bpf_map_delete_elem(&syscall_enter_state_map, &tid);\n    if (pending_filename)\n        *pending_filename = state->pending_filename;\n    return emit_event != 0;",
		},
		"stateless exit always emits": {
			"if (!state)\n        return ior_stateless_exit_emits(enter_trace_id);",
			"if (!state)\n        return 1;",
		},
		"lost state emits at every rate": {
			"if (rate == 1)\n        return 1;\n    ior_count_untimed_syscall(",
			"if (rate != 0)\n        return 1;\n    ior_count_untimed_syscall(",
		},
		"mismatched exit uses the foreign state": {
			"if (state->enter_trace_id != enter_trace_id) {",
			"if (0) {",
		},
		"untimed fresh row counts twice": {
			"fresh.count = 1;\n    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);\n}\n\n// ior_sampling_rate",
			"fresh.count = 2;\n    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);\n}\n\n// ior_sampling_rate",
		},
		"untimed count touches the histogram": {
			"        existing->count += 1;\n        return;\n    }\n\n    fresh.count = 1;\n    bpf_map_update_elem",
			"        existing->count += 1;\n        existing->duration_histogram[0] += 1;\n        return;\n    }\n\n    fresh.count = 1;\n    bpf_map_update_elem",
		},
		"zero duration not clamped": {
			"duration = now > state->start_ns ? now - state->start_ns : 1;",
			"duration = now > state->start_ns ? now - state->start_ns : 0;",
		},
		"exec move skipped": {
			"    if (old_tid == new_tid)\n        return;",
			"    if (1)\n        return;",
		},
		"exec move keeps the old entry": {
			"    moved = *state;\n    bpf_map_delete_elem(&syscall_enter_state_map, &old_tid);",
			"    moved = *state;",
		},
		"exec move inserts before deleting": {
			"    bpf_map_delete_elem(&syscall_enter_state_map, &old_tid);\n\n    if (!in_scope) {",
			"    if (in_scope && bpf_map_update_elem(&syscall_enter_state_map, &new_tid, &moved, BPF_ANY))\n        return;\n    bpf_map_delete_elem(&syscall_enter_state_map, &old_tid);\n    if (in_scope)\n        return;\n\n    if (!in_scope) {",
		},
		"out-of-scope exec move not counted": {
			"        if (!moved.emit_event)\n            ior_count_untimed_syscall(moved.enter_trace_id);",
			"        (void)moved;",
		},
		"failed exec move not counted": {
			"        ior_on_enter_state_lost(moved.enter_trace_id, ior_sampling_rate(moved.enter_trace_id));",
			"        (void)moved;",
		},
		"restart codes counted as errors": {
			"    return ret >= -IOR_MAX_ERRNO && ret < 0 && !ior_is_restart_ret(ret);",
			"    return ret >= -IOR_MAX_ERRNO && ret < 0;",
		},
		"timed check looks at count": {
			"    if (agg->max_duration_ns)\n        return 1;",
			"    if (agg->count)\n        return 1;",
		},
	}
}

func TestSyscallAccountingScenariosCatchRegressions(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	mutations := accountingMutations()
	for name, m := range mutations {
		t.Run(name, func(t *testing.T) {
			if strings.Count(filterC, m[0]) != 1 {
				t.Fatalf("mutation anchor %q must occur exactly once in filter.c", m[0])
			}
			binary := compileAccountingHarness(t, strings.Replace(filterC, m[0], m[1], 1), mapsH)
			for _, sc := range accountingScenarios {
				if len(runAccountingScenario(t, binary, sc)) > 0 {
					return
				}
			}
			t.Fatal("every scenario passed on the mutated source")
		})
	}
}

// TestSyscallAggregateStoreOrder pins what the single-threaded harness cannot
// observe: ior_update_syscall_aggregate decides the min seeding before it
// bumps the histogram, and stores count last behind a compiler barrier, so a
// torn userspace read shows the histogram ahead of count, never behind
// (internal/syscall_aggregate_consumer.go relies on that).
func TestSyscallAggregateStoreOrder(t *testing.T) {
	filterC, mapsH := readAccountingSources(t)
	if problem := aggregateStoreOrderProblem(filterC); problem != "" {
		t.Fatal(problem)
	}
	// Storing count last only helps because userspace copies it first: it
	// must stay the first field of the struct (see maps.h).
	if problem := countFirstFieldProblem(mapsH); problem != "" {
		t.Fatal(problem)
	}
	moved := strings.Replace(mapsH, "    __u64 count;\n    __u64 errors;\n", "    __u64 errors;\n    __u64 count;\n", 1)
	if moved == mapsH || countFirstFieldProblem(moved) == "" {
		t.Error("count-first check accepted a struct with count moved down")
	}
	mutations := map[string][2]string{
		"count stored first": {
			"        existing->total_duration_ns += duration_ns;\n",
			"        existing->count += 1;\n        existing->total_duration_ns += duration_ns;\n",
		},
		"min decided after the histogram bump": {
			"        existing->duration_histogram[bucket_idx] += 1;\n",
			"        existing->duration_histogram[bucket_idx] += 1;\n        if (!ior_aggregate_has_timed_samples(existing)) existing->min_duration_ns = duration_ns;\n",
		},
		"no compiler barrier": {
			"        asm volatile(\"\" ::: \"memory\");\n",
			"",
		},
	}
	for name, m := range mutations {
		if strings.Count(filterC, m[0]) != 1 {
			t.Fatalf("%s: anchor %q must occur exactly once", name, m[0])
		}
		if aggregateStoreOrderProblem(strings.Replace(filterC, m[0], m[1], 1)) == "" {
			t.Errorf("%s: store-order check accepted the regression", name)
		}
	}
}

// countFirstFieldProblem reports when count is not the first member of struct
// syscall_aggregate in maps.h, or returns "".
func countFirstFieldProblem(mapsH string) string {
	m := regexp.MustCompile(`struct syscall_aggregate \{\s*([^;]*);`).FindStringSubmatch(stripCComments(mapsH))
	if m == nil {
		return "struct syscall_aggregate not found in maps.h"
	}
	if strings.Join(strings.Fields(m[1]), " ") != "__u64 count" {
		return fmt.Sprintf("first field of struct syscall_aggregate is %q, want __u64 count", m[1])
	}
	return ""
}

// aggregateStoreOrderProblem describes a store-order violation in the
// existing-row branch of ior_update_syscall_aggregate, or returns "".
func aggregateStoreOrderProblem(filterC string) string {
	fn := extractCFunction(stripCComments(filterC), "ior_update_syscall_aggregate")
	start := strings.Index(fn, "if (existing) {")
	end := strings.Index(fn, "fresh.count = 1;")
	if fn == "" || start < 0 || end < start {
		return "cannot isolate the existing-row branch of ior_update_syscall_aggregate"
	}
	branch := fn[start:end]
	lines := strings.Split(branch, "\n")
	var stores []string
	for _, line := range lines {
		if strings.Contains(line, "existing->") || strings.Contains(line, "asm volatile") {
			stores = append(stores, strings.TrimSpace(line))
		}
	}
	if len(stores) < 3 || stores[len(stores)-1] != "existing->count += 1;" ||
		stores[len(stores)-2] != `asm volatile("" ::: "memory");` {
		return fmt.Sprintf("count must be the last store, right behind a compiler barrier: %q", stores)
	}
	if strings.Count(branch, "existing->count") != 1 {
		return "count must be stored exactly once"
	}
	seed := strings.Index(branch, "ior_aggregate_has_timed_samples(existing)")
	hist := strings.Index(branch, "existing->duration_histogram[bucket_idx] += 1;")
	if seed < 0 || hist < 0 || seed > hist || strings.Count(branch, "ior_aggregate_has_timed_samples") != 1 {
		return "the min seeding decision must precede the histogram bump"
	}
	return ""
}

func readAccountingSources(t *testing.T) (string, string) {
	t.Helper()
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	mapsH, err := readCSource("maps.h")
	if err != nil {
		t.Fatalf("read maps.h: %v", err)
	}
	return filterC, mapsH
}

var cDefineRE = regexp.MustCompile(`(?m)^#define IOR_(HISTOGRAM_BUCKETS|MAX_ERRNO|E2BIG|ERESTARTSYS|ERESTARTNOINTR|ERESTARTNOHAND|ERESTART_RESTARTBLOCK) .*$`)

// accountingHarnessSource assembles the harness from the defines and
// functions of filter.c and the two state structs of maps.h.
func accountingHarnessSource(filterC, mapsH string) (string, error) {
	defines := strings.Join(cDefineRE.FindAllString(filterC, -1), "\n")
	// Comments may hold braces that would derail extractCFunction.
	code := stripCComments(filterC)
	var structs []string
	for _, name := range []string{"syscall_enter_state", "syscall_aggregate"} {
		re := regexp.MustCompile(`(?s)struct ` + name + ` \{.*?\n\};`)
		s := re.FindString(mapsH)
		if s == "" {
			return "", fmt.Errorf("struct %s not found in maps.h", name)
		}
		structs = append(structs, s)
	}
	var funcs []string
	for _, name := range accountingFunctions {
		fn := extractCFunction(code, name)
		if fn == "" {
			return "", fmt.Errorf("function %s not found in filter.c", name)
		}
		funcs = append(funcs, fn)
	}
	return fmt.Sprintf(accountingHarnessTemplate, defines, strings.Join(structs, "\n\n"),
		strings.Join(funcs, "\n\n")), nil
}

// extractCFunction returns the full definition of the static inline function
// name: from its signature to the brace closing its body.
func extractCFunction(source, name string) string {
	re := regexp.MustCompile(`(?m)^static __always_inline [^\n(]*\b` + name + `\(`)
	loc := re.FindStringIndex(source)
	if loc == nil {
		return ""
	}
	open := strings.IndexByte(source[loc[1]:], '{')
	if open < 0 {
		return ""
	}
	depth := 0
	for i := loc[1] + open; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[loc[0] : i+1]
			}
		}
	}
	return ""
}

func compileAccountingHarness(t *testing.T, filterC, mapsH string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no host C compiler (cc) available")
	}
	src, err := accountingHarnessSource(filterC, mapsH)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "accounting_harness.c")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "accounting_harness")
	out, err := exec.Command(cc, "-O2", "-Wall", "-Werror", "-o", binary, srcPath).CombinedOutput()
	if err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runAccountingScenario runs sc in a fresh harness process and returns one
// message per step whose output differs from the expectation.
func runAccountingScenario(t *testing.T, binary string, sc accountingScenario) []string {
	t.Helper()
	cmds := make([]string, len(sc.steps))
	for i, step := range sc.steps {
		cmds[i] = step.cmd
	}
	cmd := exec.Command(binary)
	cmd.Stdin = strings.NewReader(strings.Join(cmds, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		return []string{fmt.Sprintf("%s: harness failed: %v\n%s", sc.name, err, out)}
	}
	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var problems []string
	for i, step := range sc.steps {
		line := "<missing>"
		if i < len(got) {
			line = got[i]
		}
		if line != step.want {
			problems = append(problems, fmt.Sprintf("%s: step %d %q printed %q, want %q", sc.name, i, step.cmd, line, step.want))
		}
	}
	return problems
}
