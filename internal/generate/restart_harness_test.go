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

// The restart fold's kernel side (internal/c/restart.c, tasks 103 and t13)
// decides whether userspace may fold an interrupted syscall and its
// continuation into one row: it must announce the continuation (the RESUME
// record) exactly when the kernel carries the call on - by re-executing it,
// or for -516 through restart_syscall - never for a program's own retry or
// next call after EINTR, and stamped with the announced enter's own time. As
// with the syscall accounting (enterstate_fallback_test.go), these
// tests cut the real functions out of restart.c, compile them with the host C
// compiler against a simulated map and ring buffer, and drive them through
// the signal sequences that matter. Each scenario is also run against mutated
// sources, so the suite is shown to catch the regressions it exists for.

// restartFilterFunction is the one filter.c function restart.c calls that the
// harness takes from the real source too: what counts as a restart code.
const restartFilterFunction = "ior_is_restart_ret"

// restartFunctions are the restart.c functions the harness compiles, in
// dependency order.
var restartFunctions = []string{
	"ior_restart_slot",
	"ior_restart_code",
	"ior_restart_depth",
	"ior_restart_entry",
	"ior_restart_emit",
	"ior_restart_on_exit",
	"ior_restart_on_enter",
	"ior_restart_survives_handler",
	"ior_restart_on_handler",
	"ior_restart_forget",
	"ior_restart_on_deliver",
	"ior_restart_on_sigreturn",
}

// restartHarnessTemplate simulates what restart.c uses of BPF: the
// direct-mapped pending map, the ring buffer (one record at a time; "drop 1"
// makes every reserve fail, as a full buffer does), the current task and the
// clock. Commands name the acting tid first; each prints one line: the records
// the step emitted ("handler sa_restart=N", "resume", "lost" for a failed
// reserve, "-" for none), or the slot state for "slot".
//
// "deliver" and "sigreturn" go through the two SEC programs themselves
// (handle_signal_deliver with a simulated tracepoint context,
// handle_restart_sigreturn), so the scenarios also cover which context field
// feeds which argument and that the acting task is the current tid, not its
// tgid (the simulated tgid is 77, a tid no scenario uses).
//
// Time: every "enter" passes a fresh timestamp (sim_enter_now) as the hook's
// now, the way a generated handler passes its single clock read, and the
// simulated clock helper returns a different value (SIM_CLOCK). A RESUME
// record must carry the former - userspace matches it to the enter record by
// that time - and a HANDLER record, which has no enter to match, the latter;
// anything else prints the offending stamp instead of the record's name.
const restartHarnessTemplate = `#include <stdio.h>
#include <string.h>

typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define SEC(name)
#define SIM_CLOCK 1001ULL

%s
%s

static __u64 restart_pending_map[IOR_RESTART_SLOTS];
static int event_map;
static __u32 sim_tid;
static int sim_drop;
static __u64 sim_enter_now = 5000;
static struct syscall_restart_event sim_record;
static char sim_out[128];

static void *bpf_map_lookup_elem(void *map, const void *key) {
    __u32 idx = *(const __u32 *)key;
    return idx < IOR_RESTART_SLOTS ? &((__u64 *)map)[idx] : NULL;
}

static void *bpf_ringbuf_reserve(void *map, __u64 size, __u64 flags) {
    (void)map;
    (void)flags;
    if (size != sizeof(sim_record) || sim_drop)
        return NULL;
    memset(&sim_record, 0xA5, sizeof(sim_record));
    return &sim_record;
}

static void bpf_ringbuf_submit(void *data, __u64 flags) {
    struct syscall_restart_event *ev = data;
    (void)flags;
    if (ev->event_type != SYSCALL_RESTART_EVENT || ev->trace_id != 0 || ev->tid != sim_tid || ev->pid != 77)
        snprintf(sim_out, sizeof(sim_out), "malformed record");
    else if (ev->phase == RESTART_PHASE_RESUME && ev->time != sim_enter_now)
        snprintf(sim_out, sizeof(sim_out), "resume stamped %%llu, not the enter's %%llu", ev->time, sim_enter_now);
    else if (ev->phase == RESTART_PHASE_HANDLER && ev->time != SIM_CLOCK)
        snprintf(sim_out, sizeof(sim_out), "handler stamped %%llu, not the clock's %%llu", ev->time, SIM_CLOCK);
    else if (ev->phase == RESTART_PHASE_RESUME && ev->sa_restart == 0)
        snprintf(sim_out, sizeof(sim_out), "resume");
    else if (ev->phase == RESTART_PHASE_HANDLER)
        snprintf(sim_out, sizeof(sim_out), "handler sa_restart=%%u", ev->sa_restart);
    else
        snprintf(sim_out, sizeof(sim_out), "unknown phase %%u", ev->phase);
}

static __u64 bpf_get_current_pid_tgid(void) {
    return ((__u64)77 << 32) | sim_tid;
}

static __u64 bpf_ktime_get_boot_ns(void) {
    return SIM_CLOCK;
}

/* unused: one mutation removes its only caller. */
static __attribute__((unused)) void ior_count_ringbuf_drop(void) {
    snprintf(sim_out, sizeof(sim_out), "lost");
}

%s

static void print_slot(__u32 tid) {
    __u64 entry = restart_pending_map[tid & (IOR_RESTART_SLOTS - 1)];
    if (!entry)
        printf("free\n");
    else
        printf("tid=%%u code=%%u decided=%%d depth=%%u\n", (__u32)entry, ior_restart_code(entry),
               (entry & IOR_RESTART_DECIDED) != 0, ior_restart_depth(entry));
}

int main(void) {
    char cmd[16];
    unsigned long long tid, a, b;
    long long ret;
    while (scanf("%%15s %%llu", cmd, &tid) == 2) {
        sim_tid = tid;
        snprintf(sim_out, sizeof(sim_out), "-");
        if (!strcmp(cmd, "drop")) {
            sim_drop = tid;
        } else if (!strcmp(cmd, "exit") && scanf("%%lld %%llu", &ret, &a) == 2) {
            snprintf(sim_out, sizeof(sim_out), "emit=%%d", ior_restart_on_exit(tid, ret, a));
        } else if (!strcmp(cmd, "enter")) {
            ior_restart_on_enter(tid, ++sim_enter_now);
        } else if (!strcmp(cmd, "deliver") && scanf("%%llu %%llu", &a, &b) == 2) {
            struct trace_event_raw_signal_deliver___ior sig = {.sa_handler = a, .sa_flags = b};
            handle_signal_deliver(&sig);
        } else if (!strcmp(cmd, "sigreturn")) {
            handle_restart_sigreturn(NULL);
        } else if (!strcmp(cmd, "forget")) {
            ior_restart_forget(tid);
        } else if (!strcmp(cmd, "slot")) {
            print_slot(tid);
            continue;
        } else {
            printf("bad command %%s\n", cmd);
            return 1;
        }
        printf("%%s\n", sim_out);
    }
    return 0;
}
`

// restartStep is one harness command and the line it must print.
type restartStep struct {
	cmd  string
	want string
}

type restartScenario struct {
	name  string
	steps []restartStep
}

const (
	rsNone   = "-"
	rsResume = "resume"
	rsFree   = "free"
	rsEmit1  = "emit=1"
	rsEmit0  = "emit=0"
	// A user handler address, and the sa_flags of a handler with and without
	// SA_RESTART (0x10000000; the rest is SA_SIGINFO|SA_ONSTACK|SA_RESTORER).
	rsHandler   = "4720992"
	rsRestart   = "469762052"
	rsNoRestart = "201326596"
)

// restartScenarios follow tid 9 (and 4105, which shares its slot) through the
// kernel's signal paths. "deliver T handler flags": handler 0 is SIG_DFL, 1 is
// SIG_IGN.
var restartScenarios = []restartScenario{
	// No handler: the first enter after the interrupted exit is the
	// continuation, for each of the four codes, and it is announced once.
	{name: "no handler restarts every code", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"slot 9", "tid=9 code=512 decided=0 depth=0"},
		{"enter 9", rsResume}, {"slot 9", rsFree}, {"enter 9", rsNone},
		{"exit 9 -513 1", rsEmit1}, {"enter 9", rsResume},
		{"exit 9 -514 1", rsEmit1}, {"slot 9", "tid=9 code=514 decided=0 depth=0"}, {"enter 9", rsResume},
		{"exit 9 -516 1", rsEmit1}, {"slot 9", "tid=9 code=516 decided=0 depth=0"},
		{"enter 9", rsResume}, {"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	// Task t13. A sleep stopped and continued (SIGSTOP and SIGCONT are
	// delivered with SIG_DFL) is resumed by restart_syscall, the task's first
	// enter, and so is each further hop: restart_syscall's own -516 exit makes
	// the task pending again.
	{name: "a stopped -516 call is announced at every hop", steps: []restartStep{
		{"exit 9 -516 1", rsEmit1}, {"deliver 9 0 0", rsNone}, {"deliver 9 0 0", rsNone},
		{"slot 9", "tid=9 code=516 decided=0 depth=0"}, {"enter 9", rsResume},
		{"exit 9 -516 1", rsEmit1}, {"deliver 9 0 0", rsNone}, {"enter 9", rsResume},
		{"exit 9 0 1", rsEmit1}, {"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	// Task t13, the defect. A handler delivered to a -516 call gives the
	// program EINTR, with or without SA_RESTART: the handler is reported and
	// the task forgotten at once, so the task's next traced enter - the
	// restart_syscall of a later, silent call that was stopped - is not
	// announced, whether the handler returns or leaves by siglongjmp.
	{name: "a handler ends a -516 call", steps: []restartStep{
		{"exit 9 -516 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsRestart, "handler sa_restart=1"},
		{"slot 9", rsFree}, {"sigreturn 9", rsNone}, {"deliver 9 0 0", rsNone}, {"enter 9", rsNone},
		{"exit 9 -516 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsNoRestart, "handler sa_restart=0"},
		{"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	// The same when the HANDLER record is lost to a full ring buffer: the
	// state is not lossy, the later restart_syscall is still not announced.
	// And a handler the signal probe did not see is caught at its
	// rt_sigreturn, which a pending task cannot reach otherwise.
	{name: "a -516 call is forgotten without its handler record", steps: []restartStep{
		{"exit 9 -516 1", rsEmit1}, {"drop 1", rsNone},
		{"deliver 9 " + rsHandler + " " + rsNoRestart, "lost"}, {"slot 9", rsFree},
		{"drop 0", rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsNone},
		{"exit 9 -516 1", rsEmit1}, {"sigreturn 9", rsNone}, {"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	// SIGSTOP/SIGCONT and ignored signals are delivered with SIG_DFL or
	// SIG_IGN: no handler runs, the call restarts.
	{name: "default and ignored actions decide nothing", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1},
		{"deliver 9 0 0", rsNone}, {"deliver 9 1 " + rsRestart, rsNone},
		{"slot 9", "tid=9 code=512 decided=0 depth=0"}, {"enter 9", rsResume},
	}},
	// The negative control: a handler without SA_RESTART on -512, and any
	// handler on -514, gives the program EINTR. Its retry is its own call: no
	// RESUME, however the handler returns.
	{name: "EINTR is never announced", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsNoRestart, "handler sa_restart=0"},
		{"slot 9", rsFree}, {"enter 9", rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsNone},
		{"exit 9 -514 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsRestart, "handler sa_restart=1"},
		{"slot 9", rsFree}, {"sigreturn 9", rsNone}, {"enter 9", rsNone},
		{"exit 9 -514 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsNoRestart, "handler sa_restart=0"},
		{"sigreturn 9", rsNone}, {"enter 9", rsNone},
	}},
	// A handler the call survives: its own syscalls are not the re-execution;
	// the first enter after its rt_sigreturn is.
	{name: "restart after the handler returns", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsRestart, "handler sa_restart=1"},
		{"slot 9", "tid=9 code=512 decided=1 depth=1"},
		{"enter 9", rsNone}, {"enter 9", rsNone}, {"sigreturn 9", rsNone},
		{"slot 9", "tid=9 code=512 decided=1 depth=0"}, {"enter 9", rsResume}, {"slot 9", rsFree},
		{"exit 9 -513 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsNoRestart, "handler sa_restart=0"},
		{"enter 9", rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsResume},
	}},
	// Only the first handler decides and is reported. Later ones - nested, or
	// delivered between the first one's return and the re-execution, with or
	// without SA_RESTART - only postpone it.
	{name: "later handlers only postpone", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsRestart, "handler sa_restart=1"},
		{"deliver 9 " + rsHandler + " " + rsNoRestart, rsNone}, {"slot 9", "tid=9 code=512 decided=1 depth=2"},
		{"sigreturn 9", rsNone}, {"enter 9", rsNone}, {"sigreturn 9", rsNone},
		{"deliver 9 " + rsHandler + " " + rsNoRestart, rsNone}, {"slot 9", "tid=9 code=512 decided=1 depth=1"},
		{"enter 9", rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsResume},
	}},
	// A handler that never returns (siglongjmp) leaves its depth open: no
	// later enter is announced.
	{name: "a handler that never returns", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"deliver 9 " + rsHandler + " " + rsRestart, "handler sa_restart=1"},
		{"enter 9", rsNone}, {"enter 9", rsNone}, {"enter 9", rsNone},
		{"slot 9", "tid=9 code=512 decided=1 depth=1"},
	}},
	// Only an emitted exit with -512/-513/-514/-516 makes a task pending. An
	// exit that is not emitted, -515 (ENOIOCTLCMD, no restart code) and an
	// ordinary errno do not, and the first two drop a leftover entry.
	{name: "what makes a task pending", steps: []restartStep{
		{"exit 9 -512 0", rsEmit0}, {"slot 9", rsFree}, {"enter 9", rsNone},
		{"exit 9 -516 0", rsEmit0}, {"slot 9", rsFree}, {"enter 9", rsNone},
		{"exit 9 -515 1", rsEmit1}, {"slot 9", rsFree},
		{"exit 9 -4 1", rsEmit1}, {"slot 9", rsFree}, {"exit 9 0 1", rsEmit1}, {"slot 9", rsFree},
		{"exit 9 -511 1", rsEmit1}, {"slot 9", rsFree}, {"exit 9 -517 1", rsEmit1}, {"slot 9", rsFree},
		{"exit 9 -512 1", rsEmit1}, {"exit 9 -516 0", rsEmit0}, {"slot 9", rsFree},
		{"exit 9 -516 1", rsEmit1}, {"exit 9 -515 1", rsEmit1}, {"slot 9", rsFree},
		{"exit 9 -512 1", rsEmit1}, {"exit 9 -513 0", rsEmit0}, {"slot 9", rsFree},
		{"exit 9 -516 1", rsEmit1}, {"exit 9 -512 1", rsEmit1}, {"slot 9", "tid=9 code=512 decided=0 depth=0"},
	}},
	// A signal, an rt_sigreturn or an exit of a task that is not pending
	// changes nothing, and neither does another task's.
	{name: "other tasks are untouched", steps: []restartStep{
		{"deliver 9 " + rsHandler + " " + rsRestart, rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsNone},
		{"exit 9 -512 1", rsEmit1},
		{"deliver 10 " + rsHandler + " " + rsNoRestart, rsNone}, {"sigreturn 10", rsNone},
		{"enter 10", rsNone}, {"forget 10", rsNone}, {"exit 10 -516 0", rsEmit0},
		{"slot 9", "tid=9 code=512 decided=0 depth=0"}, {"enter 9", rsResume},
	}},
	// Tids 9 and 4105 share a slot: the later interrupted exit evicts the
	// earlier, which is then never announced; the evicted task's own signal
	// path must not disturb the owner.
	{name: "colliding tids", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"exit 4105 -514 1", rsEmit1},
		{"slot 9", "tid=4105 code=514 decided=0 depth=0"},
		{"enter 9", rsNone}, {"deliver 9 " + rsHandler + " " + rsNoRestart, rsNone},
		{"sigreturn 9", rsNone}, {"forget 9", rsNone}, {"exit 9 -516 0", rsEmit0},
		{"slot 4105", "tid=4105 code=514 decided=0 depth=0"}, {"enter 4105", rsResume},
	}},
	// An exiting task takes its pending state with it; an rt_sigreturn with no
	// handler open means the bookkeeping lost track and gives up.
	{name: "forget and stray sigreturn", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"forget 9", rsNone}, {"slot 9", rsFree}, {"enter 9", rsNone},
		{"exit 9 -512 1", rsEmit1}, {"sigreturn 9", rsNone}, {"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	// A full ring buffer loses the record and counts it, but the state moves
	// on: a lost HANDLER still postpones the restart, a lost EINTR verdict
	// still cancels it, and a lost RESUME is not sent again for a later enter.
	{name: "a lost control record still advances the state", steps: []restartStep{
		{"exit 9 -512 1", rsEmit1}, {"drop 1", rsNone},
		{"deliver 9 " + rsHandler + " " + rsRestart, "lost"}, {"slot 9", "tid=9 code=512 decided=1 depth=1"},
		{"drop 0", rsNone}, {"sigreturn 9", rsNone}, {"enter 9", rsResume},
		{"exit 9 -512 1", rsEmit1}, {"drop 1", rsNone},
		{"deliver 9 " + rsHandler + " " + rsNoRestart, "lost"}, {"slot 9", rsFree},
		{"drop 0", rsNone}, {"enter 9", rsNone},
		{"exit 9 -512 1", rsEmit1}, {"drop 1", rsNone}, {"enter 9", "lost"},
		{"drop 0", rsNone}, {"slot 9", rsFree}, {"enter 9", rsNone},
	}},
	restartDepthScenario(),
}

// restartMaxDepth is the deepest handler nesting the 8-bit depth field of a
// restart_pending_map word can count (IOR_RESTART_DEPTH_MASK).
const restartMaxDepth = 255

// restartDepthScenario drives the handler depth to both ends of its counter.
// 255 nested handlers are counted and unwound exactly, and the re-execution
// is announced after the last return. A 256th does not fit: the task must be
// forgotten, because an increment would carry out of the depth field, leave
// depth 0 behind, and the next syscall the innermost handler makes would be
// announced as the re-execution.
func restartDepthScenario() restartScenario {
	deliver := restartStep{"deliver 9 " + rsHandler + " " + rsNoRestart, rsNone}
	nest := func(steps []restartStep) []restartStep {
		// -513 survives a handler with or without SA_RESTART.
		steps = append(steps, restartStep{"exit 9 -513 1", rsEmit1},
			restartStep{deliver.cmd, "handler sa_restart=0"})
		for depth := 2; depth <= restartMaxDepth; depth++ {
			steps = append(steps, deliver)
		}
		return append(steps, restartStep{"slot 9", fmt.Sprintf("tid=9 code=513 decided=1 depth=%d", restartMaxDepth)},
			restartStep{"enter 9", rsNone})
	}
	steps := nest(nil)
	for depth := restartMaxDepth; depth > 0; depth-- {
		steps = append(steps, restartStep{"sigreturn 9", rsNone})
	}
	steps = append(steps, restartStep{"slot 9", "tid=9 code=513 decided=1 depth=0"}, restartStep{"enter 9", rsResume})
	steps = nest(steps)
	steps = append(steps, deliver, restartStep{"slot 9", rsFree}, restartStep{"enter 9", rsNone},
		restartStep{"sigreturn 9", rsNone}, restartStep{"enter 9", rsNone})
	return restartScenario{name: "handler depth at its limits", steps: steps}
}

// restartMutations are plausible regressions of restart.c as {anchor,
// replacement} pairs; each anchor occurs exactly once in the source.
var restartMutations = map[string][2]string{
	"SA_RESTART ignored for -512": {
		"    return code == IOR_ERESTARTSYS && sa_restart;",
		"    return code == IOR_ERESTARTSYS;",
	},
	"-514 survives a handler": {
		"    if (code == IOR_ERESTARTNOINTR)\n        return 1;",
		"    if (code == IOR_ERESTARTNOINTR || code == IOR_ERESTARTNOHAND)\n        return 1;",
	},
	"-513 needs SA_RESTART": {
		"    if (code == IOR_ERESTARTNOINTR)\n        return 1;",
		"    if (code == IOR_ERESTARTNOINTR)\n        return sa_restart;",
	},
	"EINTR keeps the task pending": {
		"        *slot = entry | IOR_RESTART_DECIDED | IOR_RESTART_DEPTH_ONE;\n    else\n        *slot = 0;",
		"        *slot = entry | IOR_RESTART_DECIDED | IOR_RESTART_DEPTH_ONE;",
	},
	"handler syscalls announced": {
		"    if (ior_restart_depth(entry))\n        return;\n    *slot = 0;",
		"    *slot = 0;",
	},
	"enter does not consume": {
		"        return;\n    *slot = 0;\n    ior_restart_emit(tid, now, RESTART_PHASE_RESUME, 0);",
		"        return;\n    ior_restart_emit(tid, now, RESTART_PHASE_RESUME, 0);",
	},
	"enter ignores the owner": {
		"    entry = *slot;\n    if ((__u32)entry != tid)\n        return;\n    if (ior_restart_depth(entry))",
		"    entry = *slot;\n    if (!entry)\n        return;\n    if (ior_restart_depth(entry))",
	},
	"SIG_IGN counted as a handler": {
		"    if (sa_handler <= IOR_SIG_IGN)\n        return;",
		"    if (!sa_handler)\n        return;",
	},
	"later handler decides again": {
		"    if (entry & IOR_RESTART_DECIDED) {",
		"    if (0) {",
	},
	"later handler not counted": {
		"            *slot = entry + IOR_RESTART_DEPTH_ONE;",
		"            *slot = entry;",
	},
	"sigreturn does not close": {
		"        *slot = entry - IOR_RESTART_DEPTH_ONE;",
		"        *slot = entry;",
	},
	"stray sigreturn tolerated": {
		"    if (!ior_restart_depth(entry))\n        *slot = 0;\n    else\n",
		"    if (ior_restart_depth(entry))\n",
	},
	"unemitted exit becomes pending": {
		"    if (emits && ior_is_restart_ret(ret))",
		"    if (ior_is_restart_ret(ret))",
	},
	"-515 becomes pending": {
		"    if (emits && ior_is_restart_ret(ret))",
		"    if (emits)",
	},
	// Task t13: restart.c as it was before, when -516 was left to the syscall
	// stream. Nothing announces restart_syscall then, and nothing reports the
	// handler that ended the call.
	"-516 is not pending": {
		"    if (emits && ior_is_restart_ret(ret))",
		"    if (emits && ret >= -IOR_ERESTARTNOHAND)",
	},
	"-516 survives an SA_RESTART handler": {
		"    return code == IOR_ERESTARTSYS && sa_restart;",
		"    return (code == IOR_ERESTARTSYS || code == IOR_ERESTART_RESTARTBLOCK) && sa_restart;",
	},
	// The word's layout: -516 is code 5 and needs the third bit, and the
	// decided bit must lie above it.
	"code field too narrow for -516": {
		"#define IOR_RESTART_CODE_MASK 0x7ULL",
		"#define IOR_RESTART_CODE_MASK 0x3ULL",
	},
	"decided bit inside the code field": {
		"#define IOR_RESTART_DECIDED (1ULL << 35)",
		"#define IOR_RESTART_DECIDED (1ULL << 34)",
	},
	"stale entry survives another exit": {
		"    else if ((__u32)*slot == tid)\n        *slot = 0;\n    return emits;",
		"    return emits;",
	},
	"exit clears a foreign slot": {
		"    else if ((__u32)*slot == tid)\n        *slot = 0;\n    return emits;",
		"    else\n        *slot = 0;\n    return emits;",
	},
	"exit changes the verdict": {
		"        *slot = ior_restart_entry(tid, (__u32)-ret);\n    else",
		"        *slot = ior_restart_entry(tid, (__u32)-ret), emits = 0;\n    else",
	},
	"forget keeps the entry": {
		"    if (slot && (__u32)*slot == tid)\n        *slot = 0;",
		"    (void)slot;",
	},
	"lost handler record forgets the state": {
		"    if (!ev) {\n        ior_count_ringbuf_drop();\n        return;\n    }",
		"    if (!ev) {\n        ior_count_ringbuf_drop();\n        restart_pending_map[tid & (IOR_RESTART_SLOTS - 1)] = ior_restart_entry(tid, 512);\n        return;\n    }",
	},
	"drop not counted": {
		"    if (!ev) {\n        ior_count_ringbuf_drop();\n        return;\n    }",
		"    if (!ev)\n        return;",
	},
	"phase swapped": {
		"    ior_restart_emit(tid, bpf_ktime_get_boot_ns(), RESTART_PHASE_HANDLER, sa_restart);",
		"    ior_restart_emit(tid, bpf_ktime_get_boot_ns(), RESTART_PHASE_RESUME, sa_restart);",
	},
	// The depth field saturates: without the check the 256th handler carries
	// into the bit above it and the entry reads depth 0.
	"depth overflow carries": {
		"        if (ior_restart_depth(entry) == IOR_RESTART_DEPTH_MASK)",
		"        if (0)",
	},
	// RESUME must carry the enter's own timestamp, not a clock read of its own
	// and not a constant: userspace matches the two records by it.
	"resume stamped by its own clock read": {
		"    ior_restart_emit(tid, now, RESTART_PHASE_RESUME, 0);",
		"    ior_restart_emit(tid, bpf_ktime_get_boot_ns(), RESTART_PHASE_RESUME, 0);",
	},
	"emit ignores the caller's time": {
		"    ev->time = now;",
		"    ev->time = bpf_ktime_get_boot_ns();",
	},
	// The SEC programs: which context field is which argument, and whose
	// state they touch.
	"deliver swaps handler and flags": {
		"    ior_restart_on_deliver((__u32)bpf_get_current_pid_tgid(), sa_handler, sa_flags);",
		"    ior_restart_on_deliver((__u32)bpf_get_current_pid_tgid(), sa_flags, sa_handler);",
	},
	"deliver reads the flags from the handler field": {
		"    __u64 sa_flags = ctx->sa_flags;",
		"    __u64 sa_flags = ctx->sa_handler;",
	},
	"deliver judges the tgid": {
		"    ior_restart_on_deliver((__u32)bpf_get_current_pid_tgid(), sa_handler, sa_flags);",
		"    ior_restart_on_deliver((__u32)(bpf_get_current_pid_tgid() >> 32), sa_handler, sa_flags);",
	},
	"sigreturn closes the tgid's handler": {
		"    ior_restart_on_sigreturn((__u32)bpf_get_current_pid_tgid());",
		"    ior_restart_on_sigreturn((__u32)(bpf_get_current_pid_tgid() >> 32));",
	},
}

func TestRestartFoldScenarios(t *testing.T) {
	binary := compileRestartHarness(t, readRestartSources(t))
	for _, sc := range restartScenarios {
		t.Run(sc.name, func(t *testing.T) {
			for _, problem := range runRestartScenario(t, binary, sc) {
				t.Error(problem)
			}
		})
	}
}

// TestRestartFoldScenariosCatchRegressions compiles plausible regressions of
// restart.c and requires at least one scenario to fail on each.
func TestRestartFoldScenariosCatchRegressions(t *testing.T) {
	sources := readRestartSources(t)
	for name, m := range restartMutations {
		t.Run(name, func(t *testing.T) {
			if strings.Count(sources.restartC, m[0]) != 1 {
				t.Fatalf("mutation anchor %q must occur exactly once in restart.c", m[0])
			}
			mutated := sources
			mutated.restartC = strings.Replace(sources.restartC, m[0], m[1], 1)
			binary := compileRestartHarness(t, mutated)
			for _, sc := range restartScenarios {
				if len(runRestartScenario(t, binary, sc)) > 0 {
					return
				}
			}
			t.Fatal("no scenario caught the regression")
		})
	}
}

// TestRestartHooksAreWiredIntoEverySyscallHook pins the call sites in
// filter.c and exec.c that the harness cannot see: both enter hooks consult
// the pending state before anything else, all three exit hooks pass their
// verdict through it, and the exit probe forgets a dying task.
func TestRestartHooksAreWiredIntoEverySyscallHook(t *testing.T) {
	filterC, err := readCSource("filter.c")
	if err != nil {
		t.Fatalf("read filter.c: %v", err)
	}
	code := stripCComments(filterC)
	for _, hook := range []string{"ior_on_syscall_enter", "ior_on_syscall_enter_stateful"} {
		body := extractCFunction(code, hook)
		call := strings.Index(body, "ior_restart_on_enter(tid, now);")
		impl := strings.Index(body, "ior_on_syscall_enter_impl(")
		if call < 0 || impl < 0 || call > impl {
			t.Errorf("%s must call ior_restart_on_enter(tid, now) before ior_on_syscall_enter_impl:\n%s", hook, body)
		}
	}
	for _, hook := range []string{"ior_on_syscall_exit", "ior_on_syscall_exit_take_filename", "ior_on_syscall_exit_take_filenames"} {
		body := strings.Join(strings.Fields(extractCFunction(code, hook)), " ")
		if !strings.Contains(body, "return ior_restart_on_exit(tid, ret, ior_on_syscall_exit_impl(") {
			t.Errorf("%s must return ior_restart_on_exit(tid, ret, ior_on_syscall_exit_impl(...)):\n%s", hook, body)
		}
	}
	execC, err := readCSource("exec.c")
	if err != nil {
		t.Fatalf("read exec.c: %v", err)
	}
	exit := regexp.MustCompile(`(?s)int handle_sched_process_exit\(.*?\n\}\n`).FindString(stripCComments(execC))
	forget := strings.Index(exit, "ior_restart_forget((__u32)bpf_get_current_pid_tgid());")
	scope := strings.Index(exit, "ior_process_exit_in_scope(")
	if forget < 0 || scope < 0 || forget > scope {
		t.Errorf("handle_sched_process_exit must forget the task's pending restart before its scope check:\n%s", exit)
	}
}

// TestRestartSlotCountMatchesTheMap: the slot index is the tid masked with
// IOR_RESTART_SLOTS - 1, so the constant must be a power of two equal to
// restart_pending_map's max_entries; a larger mask would index past the map
// and never find a slot.
func TestRestartSlotCountMatchesTheMap(t *testing.T) {
	sources := readRestartSources(t)
	slots := regexp.MustCompile(`(?m)^#define IOR_RESTART_SLOTS (\d+)$`).FindStringSubmatch(sources.restartC)
	entries := regexp.MustCompile(`(?s)__uint\(max_entries, (\d+)\);\s*__type\(key, __u32\);\s*__type\(value, __u64\);\s*\} restart_pending_map`).
		FindStringSubmatch(sources.mapsH)
	if slots == nil || entries == nil {
		t.Fatalf("IOR_RESTART_SLOTS (%v) or restart_pending_map's max_entries (%v) not found", slots, entries)
	}
	var n uint
	if _, err := fmt.Sscan(slots[1], &n); err != nil || n == 0 || n&(n-1) != 0 {
		t.Fatalf("IOR_RESTART_SLOTS = %s, want a power of two", slots[1])
	}
	if slots[1] != entries[1] {
		t.Fatalf("IOR_RESTART_SLOTS = %s but restart_pending_map has %s entries", slots[1], entries[1])
	}
}

// restartSources are the C files the harness is cut from.
type restartSources struct {
	restartC, filterC, typesH, mapsH string
}

func readRestartSources(t *testing.T) restartSources {
	t.Helper()
	var sources restartSources
	for name, dst := range map[string]*string{"restart.c": &sources.restartC, "filter.c": &sources.filterC,
		"types.h": &sources.typesH, "maps.h": &sources.mapsH} {
		text, err := readCSource(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		*dst = text
	}
	return sources
}

// The two SEC programs and the tracepoint context flavor the signal program
// reads, cut out whole. The patterns pin each program's section (the
// tracepoint it is loaded for) and signature along the way; the flavor's CO-RE
// attribute means nothing to the host compiler and is removed.
var (
	restartSignalCtxRE     = regexp.MustCompile(`(?s)struct trace_event_raw_signal_deliver___ior \{.*?\n\} __attribute__\(\(preserve_access_index\)\);`)
	restartSignalProgramRE = regexp.MustCompile(`(?s)SEC\("tracepoint/signal/signal_deliver"\)\nint handle_signal_deliver\(void \*raw_ctx\) \{.*?\n\}`)
	restartSigretProgramRE = regexp.MustCompile(`(?s)SEC\("tracepoint/syscalls/sys_enter_rt_sigreturn"\)\nint handle_restart_sigreturn\(void \*ctx\) \{.*?\n\}`)
)

var (
	restartDefineRE     = regexp.MustCompile(`(?m)^#define IOR_(RESTART_[A-Z_]+|SA_RESTART|SIG_IGN) .*$`)
	restartCodeDefineRE = regexp.MustCompile(`(?m)^#define IOR_(ERESTARTSYS|ERESTARTNOINTR|ERESTARTNOHAND|ERESTART_RESTARTBLOCK) .*$`)
	restartTypeDefineRE = regexp.MustCompile(`(?m)^#define (SYSCALL_RESTART_EVENT|RESTART_PHASE_[A-Z]+) .*$`)
	restartEventRE      = regexp.MustCompile(`(?s)struct syscall_restart_event \{.*?\n\};`)
)

// restartHarnessSource assembles the harness from the defines, functions and
// SEC programs of restart.c, the restart codes of filter.c with the function
// that recognises them, and the record of types.h.
func restartHarnessSource(sources restartSources) (string, error) {
	defines := strings.Join(restartCodeDefineRE.FindAllString(sources.filterC, -1), "\n") + "\n" +
		strings.Join(restartTypeDefineRE.FindAllString(sources.typesH, -1), "\n") + "\n" +
		strings.Join(restartDefineRE.FindAllString(sources.restartC, -1), "\n")
	record := restartEventRE.FindString(sources.typesH)
	if record == "" {
		return "", fmt.Errorf("struct syscall_restart_event not found in types.h")
	}
	// Comments may hold braces that would derail extractCFunction.
	code := stripCComments(sources.restartC)
	functions := []string{extractCFunction(stripCComments(sources.filterC), restartFilterFunction)}
	if functions[0] == "" {
		return "", fmt.Errorf("function %s not found in filter.c", restartFilterFunction)
	}
	for _, name := range restartFunctions {
		fn := extractCFunction(code, name)
		if fn == "" {
			return "", fmt.Errorf("function %s not found in restart.c", name)
		}
		functions = append(functions, fn)
	}
	programs, err := restartPrograms(code)
	if err != nil {
		return "", err
	}
	functions = append(functions, programs...)
	return fmt.Sprintf(restartHarnessTemplate, defines, record, strings.Join(functions, "\n\n")), nil
}

// restartPrograms returns the signal context flavor and the two SEC programs
// of restart.c (comments stripped), ready for the host compiler.
func restartPrograms(code string) ([]string, error) {
	flavor := restartSignalCtxRE.FindString(code)
	deliver := restartSignalProgramRE.FindString(code)
	sigreturn := restartSigretProgramRE.FindString(code)
	if flavor == "" || deliver == "" || sigreturn == "" {
		return nil, fmt.Errorf("restart.c: context flavor (%d bytes), handle_signal_deliver (%d) or "+
			"handle_restart_sigreturn (%d) not found in the expected shape", len(flavor), len(deliver), len(sigreturn))
	}
	flavor = strings.Replace(flavor, " __attribute__((preserve_access_index))", "", 1)
	return []string{flavor, deliver, sigreturn}, nil
}

func compileRestartHarness(t *testing.T, sources restartSources) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no host C compiler (cc) available")
	}
	src, err := restartHarnessSource(sources)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "restart_harness.c")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}
	binary := filepath.Join(dir, "restart_harness")
	out, err := exec.Command(cc, "-O2", "-Wall", "-Werror", "-o", binary, srcPath).CombinedOutput()
	if err != nil {
		t.Fatalf("compile harness: %v\n%s", err, out)
	}
	return binary
}

// runRestartScenario runs sc in a fresh harness process and returns one
// message per step whose output differs from the expectation.
func runRestartScenario(t *testing.T, binary string, sc restartScenario) []string {
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
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(sc.steps) {
		return []string{fmt.Sprintf("%s: %d output lines for %d steps:\n%s", sc.name, len(lines), len(sc.steps), out)}
	}
	var problems []string
	for i, step := range sc.steps {
		if lines[i] != step.want {
			problems = append(problems, fmt.Sprintf("%s: step %d %q printed %q, want %q", sc.name, i, step.cmd, lines[i], step.want))
		}
	}
	return problems
}
