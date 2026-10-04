//+build ignore

// Raw tracepoint syscall dispatch: PROTOTYPE of task 703 (included by
// ior.bpf.c after the generated handlers, whose trace ID constants it uses).
// The design and the measurements are in docs/raw-tracepoint-design.md.
//
// Today every traced syscall has two classic tracepoint programs
// (syscalls:sys_enter_<name>, sys_exit_<name>). A classic syscall tracepoint
// runs perf_syscall_enter/exit first, which copies the syscall's arguments
// into a perf trace buffer before the program runs; the raw tracepoints
// raw_syscalls:sys_enter/sys_exit skip that and hand the program the task's
// struct pt_regs and the syscall number (or return value) instead. One raw
// pair sees every syscall, so it has to dispatch on the number itself.
//
// Three backend variants are compiled in, for read and write only, so that
// they can be measured against each other and against the classic handlers:
//
//   - tail calls (ior_raw_sys_enter_tail/ior_raw_sys_exit_tail): a
//     BPF_MAP_TYPE_PROG_ARRAY indexed by the syscall number holds one handler
//     program per traced syscall; an empty slot is an untraced syscall, so
//     "attach" and "detach" are a map update and a map delete.
//   - one program with a switch (ior_raw_sys_enter_switch/..._exit_switch):
//     an ARRAY indexed by the syscall number says whether the syscall is
//     traced (an inlined lookup), and a switch runs the inlined handler body.
//   - fentry/fexit on __x64_sys_{read,write} (ior_fentry_*/ior_fexit_*,
//     task g23): one trampoline per traced syscall and side; no
//     dispatcher. Untraced cost is still ~classic while userspace keeps
//     the classic handle_restart_sigreturn probe (that arms
//     perf_syscall_enter host-wide); see docs/raw-tracepoint-design.md.
//
// Every program here is in a "?" section: libbpf does not load it unless
// userspace switches its autoload on, which only IOR_RAW_SYSCALLS does
// (internal/rawsyscall_proto.go). A run without that variable loads exactly
// the programs it loaded before this file existed; only the three small maps
// below are created in addition.
//
// The handler bodies are the generated handle_sys_enter_read/write and
// handle_sys_exit_read/write ones (same filter, same enter and exit hooks,
// same records and trace IDs), with two differences:
//
//   - the arguments come from struct pt_regs instead of the tracepoint
//     record: x86_64 only here (di is the first argument; the build defines
//     __TARGET_ARCH_amd64, which bpf_tracing.h's PT_REGS_PARM*_SYSCALL do not
//     recognise, so the register is named directly). A raw tracepoint's
//     regs is an untyped u64, so a register is read either through
//     bpf_rdonly_cast (a direct load; the kfunc is Linux 6.2+, see
//     fileident.c) or with a probe read (a helper call; every kernel). The
//     first is used where the kernel has the kfunc unless
//     IOR_RAW_PROBE_REGS asks for the second, which is what el8 would run;
//   - a 32-bit (compat) syscall is skipped explicitly: the classic syscall
//     tracepoints never report one (x86 sets
//     ARCH_TRACE_IGNORE_COMPAT_SYSCALLS), but the raw ones see it with its
//     32-bit number, which is some other syscall's 64-bit number.

// IOR_RAW_SYSCALL_SLOTS bounds the syscall numbers the dispatch maps cover:
// x86_64's table ends near 470. A larger number (an x32 syscall, which has
// bit 30 set, or the -1 that rt_sigreturn leaves in orig_ax) is untraced.
#define IOR_RAW_SYSCALL_SLOTS 512

// x86_64 syscall numbers of the two prototype syscalls, and of rt_sigreturn.
#define IOR_RAW_NR_READ 0
#define IOR_RAW_NR_WRITE 1
#define IOR_RAW_NR_RT_SIGRETURN 15

// IOR_TS_COMPAT is x86's thread_info.status bit of a task inside a 32-bit
// syscall (arch/x86/include/asm/thread_info.h, what in_ia32_syscall tests).
#define IOR_TS_COMPAT 0x0002

// ior_raw_enter_progs and ior_raw_exit_progs are the tail-call tables of the
// first variant, indexed by syscall number; userspace stores the handler
// programs' fds in the slots of the traced syscalls.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, IOR_RAW_SYSCALL_SLOTS);
    __type(key, __u32);
    __type(value, __u32);
} ior_raw_enter_progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, IOR_RAW_SYSCALL_SLOTS);
    __type(key, __u32);
    __type(value, __u32);
} ior_raw_exit_progs SEC(".maps");

// ior_raw_traced is the switch variant's enable table, indexed by syscall
// number: non-zero means traced.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, IOR_RAW_SYSCALL_SLOTS);
    __type(key, __u32);
    __type(value, __u32);
} ior_raw_traced SEC(".maps");

// IOR_RAW_PROBE_REGS forces the probe-read register access (1) where the
// kernel would allow the direct one (0). Userspace sets it from
// IOR_RAW_SYSCALLS's "-probe" variants, to measure what a kernel without
// the kfunc pays.
const volatile u32 IOR_RAW_PROBE_REGS = 0;

// The raw tracepoints' arguments, TP_PROTO(struct pt_regs *regs, long id) and
// TP_PROTO(struct pt_regs *regs, long ret). Declared as plain structs and
// cast from void *ctx, like ior_task_rename_args in exec.c: reaching them
// through vmlinux.h's struct bpf_raw_tracepoint_args would add a CO-RE
// relocation on the context, which the 4.18/5.14 verifiers reject.
struct ior_raw_sys_enter_args {
    struct pt_regs *regs;
    long id;
};

struct ior_raw_sys_exit_args {
    struct pt_regs *regs;
    long ret;
};

// ior_raw_in_compat_syscall reports whether the current task is inside a
// 32-bit syscall. It reads the BTF-typed task (a direct load, no helper
// call); that needs Linux 5.11, which is fine for a prototype that only runs
// where it is asked for. Production code needs a probe-read fallback for
// el8 (see the design document). A kernel without the status field (not
// x86) reports no compat syscall.
static __always_inline int ior_raw_in_compat_syscall(void) {
    struct task_struct *task;

    if (!bpf_core_field_exists(struct thread_info, status))
        return 0;
    task = bpf_get_current_task_btf();
    return (task->thread_info.status & IOR_TS_COMPAT) != 0;
}

// ior_raw_direct_regs reports whether registers are read by direct load.
// The terms are constants after libbpf's relocations, so the verifier
// prunes the branch a run does not take.
static __always_inline int ior_raw_direct_regs(void) {
    return !IOR_RAW_PROBE_REGS && bpf_ksym_exists(bpf_rdonly_cast) &&
           bpf_core_type_id_kernel(struct pt_regs) != 0;
}

// ior_raw_typed_regs types the raw tracepoint's regs for direct loads (an
// untrusted, read-only BTF pointer: a faulting load reads 0).
static __always_inline struct pt_regs *ior_raw_typed_regs(struct pt_regs *regs) {
    return bpf_rdonly_cast(regs, bpf_core_type_id_kernel(struct pt_regs));
}

// ior_raw_arg0 returns the first syscall argument (x86_64: di).
static __always_inline __u64 ior_raw_arg0(struct pt_regs *regs) {
    if (ior_raw_direct_regs())
        return ior_raw_typed_regs(regs)->di;
    return BPF_CORE_READ(regs, di);
}

// ior_raw_exit_nr returns the number of the syscall a sys_exit belongs to:
// orig_ax, what syscall_get_nr reads on x86_64. The raw sys_exit does not
// pass it, and unlike the classic one it also fires for a syscall that
// cleared orig_ax (rt_sigreturn sets it to -1), which then is no slot.
static __always_inline __u64 ior_raw_exit_nr(struct pt_regs *regs) {
    if (ior_raw_direct_regs())
        return ior_raw_typed_regs(regs)->orig_ax;
    return BPF_CORE_READ(regs, orig_ax);
}

// ior_raw_enter_fd is the body of the generated fd-kind enter handlers
// (handle_sys_enter_read/write) with the descriptor taken from pt_regs.
static __always_inline int ior_raw_enter_fd(struct pt_regs *regs, __u32 enter_id) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;
    if (ior_raw_in_compat_syscall())
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    if (!ior_on_syscall_enter(tid, enter_id, now))
        return 0;

    struct fd_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct fd_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    ev->event_type = ENTER_FD_EVENT;
    ev->trace_id = enter_id;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = now;
    ev->fd = (__s32)ior_raw_arg0(regs);
    ev->file_ident = ior_file_ident(ev->fd);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ior_raw_exit_ret is the body of the generated ret-kind exit handlers
// (handle_sys_exit_read/write); ret is the raw tracepoint's own argument.
static __always_inline int ior_raw_exit_ret(__u32 enter_id, __u32 exit_id, __u32 ret_type, __s64 ret) {
    __u32 pid, tid;
    if (filter(&pid, &tid))
        return 0;
    if (ior_raw_in_compat_syscall())
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    if (!ior_on_syscall_exit(tid, enter_id, ret, now))
        return 0;

    struct ret_event *ev = bpf_ringbuf_reserve(&event_map, sizeof(struct ret_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    ev->event_type = EXIT_RET_EVENT;
    ev->trace_id = exit_id;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = now;
    ev->ret = ret;
    ev->ret_type = ret_type;
    ev->file_ident = 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// ior_raw_enter_always is what every sys_enter dispatcher does for every
// syscall, traced or not: the restart fold's handler-depth count at
// rt_sigreturn (handle_restart_sigreturn in restart.c). With a raw-
// dispatcher mode on (tailcall/switch), userspace does not attach that
// classic sys_enter_rt_sigreturn program: any classic syscall tracepoint
// keeps perf_syscall_enter, the argument capture the raw pair exists to
// avoid, running for every syscall on the host (it is one callback on the
// same raw tracepoint, which looks the syscall up in its enable bitmap
// only after it was called). fentry has no dispatcher, so userspace keeps
// the classic hand probe instead (task g23).
static __always_inline void ior_raw_enter_always(__u64 nr) {
    if (nr == IOR_RAW_NR_RT_SIGRETURN && !ior_raw_in_compat_syscall())
        ior_restart_on_sigreturn((__u32)bpf_get_current_pid_tgid());
}

// --- Variant 1: tail calls -------------------------------------------------

// The dispatchers are the only programs attached. A tail call into an empty
// slot falls through, so an untraced syscall costs the raw tracepoint, the
// bounds check and the failed tail call (plus orig_ax's probe read at exit).
SEC("?raw_tracepoint/sys_enter")
int ior_raw_sys_enter_tail(void *ctx) {
    struct ior_raw_sys_enter_args *args = ctx;
    __u64 nr = (__u64)args->id;

    ior_raw_enter_always(nr);
    if (nr >= IOR_RAW_SYSCALL_SLOTS)
        return 0;
    bpf_tail_call(ctx, &ior_raw_enter_progs, (__u32)nr);
    return 0;
}

SEC("?raw_tracepoint/sys_exit")
int ior_raw_sys_exit_tail(void *ctx) {
    struct ior_raw_sys_exit_args *args = ctx;
    __u64 nr = ior_raw_exit_nr(args->regs);

    if (nr >= IOR_RAW_SYSCALL_SLOTS)
        return 0;
    bpf_tail_call(ctx, &ior_raw_exit_progs, (__u32)nr);
    return 0;
}

// The tail-call targets: one program per syscall and side, as today, but of
// the raw tracepoint type (a tail call needs the caller's type). They are
// never attached themselves; userspace puts them into the tables.
SEC("?raw_tracepoint/sys_enter")
int ior_raw_enter_read(void *ctx) {
    struct ior_raw_sys_enter_args *args = ctx;
    return ior_raw_enter_fd(args->regs, SYS_ENTER_READ);
}

SEC("?raw_tracepoint/sys_enter")
int ior_raw_enter_write(void *ctx) {
    struct ior_raw_sys_enter_args *args = ctx;
    return ior_raw_enter_fd(args->regs, SYS_ENTER_WRITE);
}

SEC("?raw_tracepoint/sys_exit")
int ior_raw_exit_read(void *ctx) {
    struct ior_raw_sys_exit_args *args = ctx;
    return ior_raw_exit_ret(SYS_ENTER_READ, SYS_EXIT_READ, READ_CLASSIFIED, args->ret);
}

SEC("?raw_tracepoint/sys_exit")
int ior_raw_exit_write(void *ctx) {
    struct ior_raw_sys_exit_args *args = ctx;
    return ior_raw_exit_ret(SYS_ENTER_WRITE, SYS_EXIT_WRITE, WRITE_CLASSIFIED, args->ret);
}

// --- Variant 2: one program, enable table and switch -----------------------

// ior_raw_is_traced asks the enable table; an array lookup is inlined.
static __always_inline int ior_raw_is_traced(__u64 nr) {
    __u32 key = (__u32)nr;
    __u32 *traced;

    if (nr >= IOR_RAW_SYSCALL_SLOTS)
        return 0;
    traced = bpf_map_lookup_elem(&ior_raw_traced, &key);
    return traced && *traced;
}

SEC("?raw_tracepoint/sys_enter")
int ior_raw_sys_enter_switch(void *ctx) {
    struct ior_raw_sys_enter_args *args = ctx;
    __u64 nr = (__u64)args->id;

    ior_raw_enter_always(nr);
    if (!ior_raw_is_traced(nr))
        return 0;
    switch (nr) {
    case IOR_RAW_NR_READ:
        return ior_raw_enter_fd(args->regs, SYS_ENTER_READ);
    case IOR_RAW_NR_WRITE:
        return ior_raw_enter_fd(args->regs, SYS_ENTER_WRITE);
    }
    return 0;
}

SEC("?raw_tracepoint/sys_exit")
int ior_raw_sys_exit_switch(void *ctx) {
    struct ior_raw_sys_exit_args *args = ctx;
    __u64 nr = ior_raw_exit_nr(args->regs);

    if (!ior_raw_is_traced(nr))
        return 0;
    switch (nr) {
    case IOR_RAW_NR_READ:
        return ior_raw_exit_ret(SYS_ENTER_READ, SYS_EXIT_READ, READ_CLASSIFIED, args->ret);
    case IOR_RAW_NR_WRITE:
        return ior_raw_exit_ret(SYS_ENTER_WRITE, SYS_EXIT_WRITE, WRITE_CLASSIFIED, args->ret);
    }
    return 0;
}

// --- Variant 3: fentry/fexit on the syscall wrappers (task g23) ------------
//
// One trampoline per traced syscall and side, attached to
// __x64_sys_{read,write}. No dispatcher (unlike the raw variants), so
// there is no per-syscall dispatcher tax; untraced cost is still ~classic
// while the classic handle_restart_sigreturn probe stays attached.
// Skips stay per-program, and compat syscalls never reach these hooks.
// BPF_PROG expands the typed args from the trampoline's ctx; bpf_tracing.h
// is included here so the classic handlers (which do not need it) stay
// unchanged. The programs stay in "?" sections like the raw ones.

#include <bpf/bpf_tracing.h>

SEC("?fentry/__x64_sys_read")
int BPF_PROG(ior_fentry_read, struct pt_regs *regs)
{
    return ior_raw_enter_fd(regs, SYS_ENTER_READ);
}

SEC("?fexit/__x64_sys_read")
int BPF_PROG(ior_fexit_read, struct pt_regs *regs, long ret)
{
    return ior_raw_exit_ret(SYS_ENTER_READ, SYS_EXIT_READ, READ_CLASSIFIED, ret);
}

SEC("?fentry/__x64_sys_write")
int BPF_PROG(ior_fentry_write, struct pt_regs *regs)
{
    return ior_raw_enter_fd(regs, SYS_ENTER_WRITE);
}

SEC("?fexit/__x64_sys_write")
int BPF_PROG(ior_fexit_write, struct pt_regs *regs, long ret)
{
    return ior_raw_exit_ret(SYS_ENTER_WRITE, SYS_EXIT_WRITE, WRITE_CLASSIFIED, ret);
}
