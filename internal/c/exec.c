//+build ignore

/**
 * exec.c holds the hand-written tracepoint handlers that are not syscall
 * tracepoints: sched_process_exec, sched_process_exit, task_newtask and
 * task_rename.
 *
 * Why sched_process_exec exists: the comm shown for a syscall used to come from an
 * asynchronous /proc/<tid>/comm read (internal/eventloop_comm.go). A task that
 * forks and then execve()s keeps its tid across the exec, so a lookup that
 * landed in the post-fork/pre-exec window cached the *old* program name for
 * that tid and nothing ever invalidated it. The earliest post-exec syscalls -
 * notably the dynamic loader's access("/etc/ld.so.preload") - were therefore
 * labelled with the pre-exec comm, which made the comm column contradict the
 * kernel-side -comm filter that had (correctly) matched the post-exec name.
 *
 * sched_process_exec fires from bprm_execve() after begin_new_exec() has
 * already installed the new program's name in task->comm, and strictly before
 * the new program issues its first syscall. Emitting the exact kernel comm
 * here, into the same ring buffer as the syscall events, gives userspace an
 * ordered "this tid is now called X" record: the BPF ring buffer hands records
 * to the consumer in reservation order and the event loop processes them in a
 * single goroutine, so the update is always applied before any post-exec
 * syscall event of that task is turned into a row.
 *
 * Cost: one small (48-byte) record per successful execve, versus the
 * alternative of stamping bpf_get_current_comm() onto every single syscall
 * event, which would add 16 bytes to every ring-buffer record on a path where
 * ring-buffer pressure is already a tracked concern (ringbuf_drop_map).
 *
 * A non-leader exec also changes the task's tid (de_thread() hands it the
 * leader's), and the execve it is still inside entered under the old one.
 * The handler therefore moves the in-flight enter state to the new tid
 * (ior_on_exec_tid_change in filter.c) and reports the old tid in the record,
 * so userspace can re-key its parked execve enter the same way. The move runs
 * for out-of-scope tasks too (except ior itself): under -tid the traced
 * thread's exec lands on the filtered leader tid, and its entry must still be
 * reclaimed. For every exec that keeps its tid the move returns after one
 * compare.
 *
 * -tid <non-leader> is the one case where the exec'ing task is in scope before
 * the exec but not after it: filter() accepted the caller's tid, while the
 * record's tid is the leader's, which TID_FILTER rejects. The record is still
 * emitted for it (ior_exec_record_scope below), flagged exit_untraced, because
 * it is userspace's only notice that the process's FD_CLOEXEC descriptors are
 * gone and that the execve it parked under the caller's tid has succeeded.
 * The execve's own exit returns under the filtered leader tid and never
 * arrives, so userspace completes the parked enter from this record instead.
 * If this record is lost to ring-buffer backpressure, nothing completes it:
 * unlike the in-scope case there is no exit for userspace to adopt the enter
 * from, so that execve row (and, at a sampling rate N, its count) is lost,
 * visible only as a ringbuf_drop_map drop.
 *
 * -tid tracing of that thread ends at such an exec. TID_FILTER is a
 * load-time constant, and following the task onto the leader tid would need
 * a map lookup in filter() on every event of every task the tid filter
 * rejects; the renumbered thread is therefore not traced any further (see
 * the -tid notes in AGENTS.md).
 */

// Emission scope of a sched_process_exec record.
enum ior_exec_scope {
    IOR_EXEC_OUT_OF_SCOPE = 0,
    // filter() accepts the post-exec task: the execve's exit is traced too.
    IOR_EXEC_IN_SCOPE,
    // Only the pre-exec caller was traced (-tid <non-leader>): emit, but flag
    // the record exit_untraced.
    IOR_EXEC_CALLER_TRACED,
};

// ior_exec_record_scope classifies an exec for emission. in_scope is
// filter()'s verdict on the post-exec task, pid its tgid and old_tid the
// caller's pre-exec tid. ior itself was already excluded by the caller.
//
// The caller-traced case mirrors ior_process_exit_in_scope's bypass for the
// sched_process_exit record, with a narrower key: it is not "some thread of
// the traced process" but the traced thread itself, identified exactly by
// old_tid == TID_FILTER (tid reuse aside, the same ambiguity filter() has).
// PID_FILTER still applies, so -pid P -tid T never emits for a T outside P.
static __always_inline enum ior_exec_scope
ior_exec_record_scope(int in_scope, __u32 pid, __u32 old_tid) {
    if (in_scope)
        return IOR_EXEC_IN_SCOPE;
    if (-1 == TID_FILTER || old_tid != TID_FILTER)
        return IOR_EXEC_OUT_OF_SCOPE;
    if (-1 != PID_FILTER && pid != PID_FILTER)
        return IOR_EXEC_OUT_OF_SCOPE;
    return IOR_EXEC_CALLER_TRACED;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Zero-initialised: filter() leaves tid unwritten on its early ior-self
    // return.
    __u32 pid = 0, tid = 0;
    struct process_exec_event *ev;
    int in_scope = !filter(&pid, &tid);
    enum ior_exec_scope scope;

    if (pid == IOR_PID_FILTER)
        return 0;
    ior_on_exec_tid_change((__u32)ctx->old_pid, tid, in_scope);
    scope = ior_exec_record_scope(in_scope, pid, (__u32)ctx->old_pid);
    if (scope == IOR_EXEC_OUT_OF_SCOPE)
        return 0;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct process_exec_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    ev->event_type = PROCESS_EXEC_EVENT;
    // Not a syscall tracepoint: there is no enter/exit trace id to report.
    ev->trace_id = 0;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_boot_ns();
    // bpf_get_current_comm writes all sizeof(ev->comm) bytes (NUL-padded), so
    // the field needs no memset first; see "String fields in ring-buffer
    // records" in filter.c.
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->old_tid = (__u32)ctx->old_pid;
    ev->exit_untraced = scope == IOR_EXEC_CALLER_TRACED ? 1 : 0;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// Why sched_process_exit exists: the userspace fdTracker keys its fd table by
// (tgid, fd), because a descriptor number is only meaningful inside the
// process that owns it. Close and close_range evict a process's own entries,
// but nothing in the syscall stream reports that a *process* went away, so
// every descriptor a dead process left behind would sit in the table until LRU
// eviction got around to it - pure garbage for any fd number that process ever
// held, and memory that only grows with process churn.
//
// sched:sched_process_exit fires per exiting *task* (thread) and carries the
// task in context, so this handler emits a small control record with the tgid,
// the tid and a group_dead flag (internal/eventloop_processexit.go consumes
// it). Per-task firing is exactly right for the tid-keyed userspace state (comm
// cache, parked enters, pending handles), but the fd table belongs to the
// whole thread group: a thread dying while its siblings live must not evict
// the process's descriptors. Doing so used to push every later syscall on
// them through the /proc/<pid>/fd fallback, which renames the same descriptor
// (pipe:0:3:4 becomes pipe:[73538387]), returns nothing for an fd closed in
// the meantime, and can even attribute a reused fd number to the wrong file
// when userspace lags. group_dead tells userspace when the last thread of the
// group is gone, so it evicts the fd table only then. The flag is also the
// process-lifetime signal later consumers (e.g. the stats engine's PID-reuse
// handling) can forward.
//
// Cost: one 32-byte record per task exit, comparable to the per-exec record
// above, on the same ring buffer.

// trace_event_raw_sched_process_exit___ior is a CO-RE "flavor" of the kernel's
// struct trace_event_raw_sched_process_exit, reduced to the one field this
// program reads. libbpf matches it to the kernel type by name (everything from
// "___" on is dropped); preserve_access_index turns the field access into a
// relocation instead of a fixed offset, so group_dead's real offset comes from
// the running kernel's BTF and the leading members need not be repeated here.
struct trace_event_raw_sched_process_exit___ior {
    bool group_dead;
} __attribute__((preserve_access_index));

// ior_exit_group_dead reports whether the exiting task was the last live
// member of its thread group, i.e. whether the process as a whole is dead.
//
// Newer kernels expose exactly this as the tracepoint's own group_dead field,
// which do_exit() computed with atomic_dec_and_test(&tsk->signal->live). The
// field access below is a CO-RE relocation against the running kernel's
// trace_event_raw_sched_process_exit: on a kernel without the field,
// bpf_core_field_exists() resolves to the constant 0, the verifier prunes the
// branch as dead code, and libbpf's poisoned relocation for ctx->group_dead is
// never executed.
//
// The relocation goes through the local flavor type declared above rather
// than through vmlinux.h's struct trace_event_raw_sched_process_exit. That
// vmlinux.h is dumped from the BUILD host's kernel (Magefile.go), and kernels
// predating the group_dead change (RHEL/Rocky 8 and 9) define
// sched_process_exit from the shared sched_process_template, so their
// vmlinux.h has no such struct at all and naming it here made the object fail
// to compile there. libbpf matches the flavor to the target kernel's type by
// name (the ___ior suffix is ignored) at load time, so the runtime behaviour
// is unchanged. On a kernel whose BTF lacks the type entirely, libbpf resolves
// the field-exists relocation to 0 rather than failing the load.
//
// Older kernels fall back to reading task->signal->live directly. do_exit()
// decrements live before it fires the tracepoint and nothing can increment it
// again once the group is exiting, so live == 0 here means every thread has
// passed that point: the process is dead. The last thread to decrement always
// reads its own decrement, so at least one exit record of a group carries
// group_dead = 1. Two threads exiting concurrently can both observe 0 and
// both report it (the earlier thread fires its tracepoint after the later
// one's decrement). Userspace eviction is idempotent and the group-dead
// counter drops the duplicate (see isDuplicateGroupDead). A failed read (NULL
// signal) reports 0 rather than guessing: the fd entries then linger until LRU
// trimming, the same outcome as a record lost to ring-buffer backpressure.
//
// Verification status: the field path is exercised end to end by the
// integration scenario thread-exit-keeps-fd (integrationtests) on the 7.2
// development host, whose tracepoint has group_dead. The signal->live
// fallback compiles to valid CO-RE relocations but has not been run on a
// kernel lacking the field; its correctness rests on the do_exit() ordering
// argued above.
static __always_inline __u32
ior_exit_group_dead(void *raw_ctx) {
    struct trace_event_raw_sched_process_exit___ior *ctx = raw_ctx;
    struct task_struct *task;
    struct signal_struct *signal;

    if (bpf_core_field_exists(ctx->group_dead))
        return ctx->group_dead ? 1 : 0;

    task = (struct task_struct *)bpf_get_current_task();
    signal = BPF_CORE_READ(task, signal);
    if (!signal)
        return 0;
    return BPF_CORE_READ(signal, live.counter) == 0 ? 1 : 0;
}

// ior_process_exit_in_scope decides whether an exit record is emitted and
// fills *group_dead for the records that are. It is filter() with one
// exception: a group-dead exit of the traced process bypasses the TID_FILTER
// dimension, while ior itself stays excluded.
//
// Why the exception: under -tid, filter() only admits the traced thread, but
// the thread that ends the group - the only record userspace evicts the
// process's fd entries on - is usually another one. Without the bypass a
// -tid run would never evict its process's descriptors at all, a regression
// against the old evict-on-every-exit behaviour that did fire for the traced
// thread.
//
// The bypass is scoped to TID_FILTER_TGID, the traced thread's process, which
// userspace resolves at setup (PID_FILTER when -pid is also given, else
// /proc/<tid>/status; see tidFilterTgid in internal/bpfsetup.go). An unscoped
// bypass would emit a record for every process death on the system under
// -tid without -pid. When the tgid is unresolved (-1) no pid matches, so
// there is no bypass at all. group_dead is only read once the pid matched,
// so exits of unrelated processes cost no extra reads.
static __always_inline int
ior_process_exit_in_scope(void *ctx,
                          __u32 *pid, __u32 *tid, __u32 *group_dead) {
    if (!filter(pid, tid)) {
        *group_dead = ior_exit_group_dead(ctx);
        return 1;
    }
    // No tid filter means the rejection was a pid one (or ior itself): no
    // bypass. Otherwise only the traced thread's own process qualifies; that
    // also excludes ior, whose tgid is never the traced one.
    if (-1 == TID_FILTER || *pid != TID_FILTER_TGID)
        return 0;
    *group_dead = ior_exit_group_dead(ctx);
    return *group_dead;
}

// IOR_EXIT_TID_INHERITED is the exit_flags bit of a process_exit_event whose
// task is a thread-group leader killed by another thread's execve (see
// ior_exit_tid_inherited); every other record carries 0 there, exactly like
// the always-zero reserved word it replaced, so an older object or a consumer
// that ignores the field reads "the tid is gone".
#define IOR_EXIT_TID_INHERITED 0x1U

// signal_struct___ior_exec and signal_struct___ior_exit are CO-RE flavors of
// struct signal_struct naming the one member ior_exit_tid_inherited reads,
// under its two kernel spellings: group_exec_task (Linux 5.16+) and
// group_exit_task (older kernels, RHEL/Rocky 8 and 9 included). Both point at
// the thread running de_thread() for an execve while it kills its siblings.
// Flavors, not vmlinux.h's struct, because vmlinux.h is dumped from the build
// host's kernel and carries only one of the two names.
struct signal_struct___ior_exec {
    struct task_struct *group_exec_task;
} __attribute__((preserve_access_index));

struct signal_struct___ior_exit {
    struct task_struct *group_exit_task;
} __attribute__((preserve_access_index));

// ior_exit_tid_inherited returns IOR_EXIT_TID_INHERITED when the exiting
// current task is its thread-group leader (pid == tid) and another thread of
// the group is exec'ing (signal->group_exec_task set and not the current
// task), else 0.
//
// Why: when a non-leader thread calls execve, de_thread() kills every other
// thread, the leader included. The leader runs do_exit() and fires
// sched_process_exit (tid == tgid, group_dead 0, since the exec'ing thread is
// still live), but then the exec'ing thread takes over the leader's tid and
// start time (exchange_tids) and continues as the new program. Under
// `-tid <leader>` the BPF tid filter keeps tracing that program, a
// PIDFD_THREAD pidfd and /proc/<tid> follow it too (observed on 7.2 with
// bpftrace: the old leader's record shows group_exec_task = the exec'ing
// thread, and the pidfd stays unreadable across the exec), so userspace must
// not treat this record as the traced tid's end (endTraceOnTargetThreadExit).
//
// A non-leader killed by the same de_thread() is really gone (its tid is not
// inherited), so it gets no flag. The leader exiting on its own just as
// another thread starts an exec is still flagged, and rightly: de_thread()
// waits for the leader to become a zombie and takes its tid all the same. If
// the exec'ing thread is killed instead (a fatal signal during de_thread()),
// the whole group dies; userspace then ends on the group-dead record.
//
// Verification status: the group_exec_task path is exercised by the
// integration test TestHeadlessTidLeaderRunSurvivesANonLeaderExec on the 7.2
// development host; the group_exit_task path compiles to a valid CO-RE
// relocation but has not been run on an old kernel.
static __always_inline __u32
ior_exit_tid_inherited(__u32 pid, __u32 tid) {
    struct task_struct *task;
    struct task_struct *exec_task = NULL;
    struct signal_struct___ior_exec *sig_exec;
    struct signal_struct___ior_exit *sig_exit;

    if (pid != tid)
        return 0;
    task = (struct task_struct *)bpf_get_current_task();
    sig_exec = (struct signal_struct___ior_exec *)BPF_CORE_READ(task, signal);
    if (!sig_exec)
        return 0;
    if (bpf_core_field_exists(sig_exec->group_exec_task)) {
        exec_task = BPF_CORE_READ(sig_exec, group_exec_task);
    } else {
        sig_exit = (struct signal_struct___ior_exit *)sig_exec;
        if (bpf_core_field_exists(sig_exit->group_exit_task))
            exec_task = BPF_CORE_READ(sig_exit, group_exit_task);
    }
    if (!exec_task || exec_task == task)
        return 0;
    return IOR_EXIT_TID_INHERITED;
}

SEC("tracepoint/sched/sched_process_exit")
// ctx is void *: the tracepoint's context struct has a different name (and
// layout) per kernel generation and the handler only needs its address.
int handle_sched_process_exit(void *ctx) {
    // Zero-initialised: filter() leaves tid unwritten on its early ior-self
    // return, and the verifier cannot prove the bypass never reaches the
    // ev->tid store on that path.
    __u32 pid = 0, tid = 0, group_dead = 0;
    struct process_exit_event *ev;

    if (!ior_process_exit_in_scope(ctx, &pid, &tid, &group_dead))
        return 0;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct process_exit_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    ev->event_type = PROCESS_EXIT_EVENT;
    // Not a syscall tracepoint: there is no enter/exit trace id to report.
    ev->trace_id = 0;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_boot_ns();
    ev->group_dead = group_dead;
    // Always written (0 or the flag), so no stale ring-buffer bytes reach
    // userspace through the former tail pad.
    ev->exit_flags = ior_exit_tid_inherited(pid, tid);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// Why task_newtask exists: a task that has never issued a traced syscall has no
// name in userspace's tid->comm cache, and the only way to learn it there was
// an asynchronous /proc/<tid>/comm read. That read loses the race against every
// short-lived task: a thread that has already exited by the time a lookup
// worker gets to it has no /proc entry any more, so every row it produced
// carried an empty comm, and the first rows of a thread that lives a few
// milliseconds were empty too, until the lookup landed. Under -comm it was
// worse than cosmetic: an empty comm matches no ordinary -comm pattern at the
// exit-side comm check, so such rows were dropped, silently (and before task
// dr2 the enter of a non-open/exec syscall was dropped outright).
//
// task:task_newtask fires from copy_process() once the child has its pid and
// its inherited comm, and before the child is first woken (wake_up_new_task),
// so it precedes every syscall the child can make. Emitting the child's comm
// into the same ring buffer as the syscall events gives userspace an ordered
// "this new tid is called X" record, exactly like sched_process_exec does for
// a rename: the ring buffer delivers records in reservation order and the event
// loop has a single consumer goroutine, so the cache is seeded before the
// child's first syscall becomes a row (handleTaskNewtaskEvent).
//
// The name is the creator's, inherited by the child at fork time, so it can
// be out of date by the child's first syscall: a fork()ed process that then
// execve()s is renamed by the sched_process_exec record, and a thread that
// renames itself (prctl(PR_SET_NAME)/pthread_setname_np: tokio, Java, Chrome
// and Bun worker pools do so as their first act) is reported by the task_rename
// record below. That record can still be missing (lost under ring-buffer
// backpressure, or its probe failed to attach), so userspace treats the seed as
// provisional and re-reads /proc once (setCachedProvisional).
//
// The record also carries the raw clone_flags and the creator's tgid, the inputs
// userspace needs to tell a thread from a process and to model the fd table the
// child inherits: a fork()ed child starts with a copy of the creator's
// descriptor table (handleTaskNewtaskEvent copies the tracked entries), while
// CLONE_FILES shares it (one table, two tgids: the child's table operations
// show up under the child's tgid but change the creator's table too).
//
// One record is emitted for a child that is OUT of scope: the CLONE_FILES
// process child of an in-scope creator (IOR_NEWTASK_CHILD_OUT_OF_SCOPE in
// scope_flags). Under -pid/-tid such a child's syscalls are filtered out, yet
// whatever it closes or opens changes the descriptor table its in-scope creator
// keeps using, so the creator's tracked names would go stale without anyone
// noticing; the record lets userspace stop trusting that table. It is the only
// record an out-of-scope task produces.
//
// Cost: one 56-byte record per created task, the same order as the per-exec and
// per-exit records, on the same ring buffer.

// IOR_CLONE_THREAD is CLONE_THREAD from include/uapi/linux/sched.h: the new
// task joins the creator's thread group instead of founding its own.
#define IOR_CLONE_THREAD 0x00010000ULL

// IOR_CLONE_FILES is CLONE_FILES: the new task shares the creator's descriptor
// table instead of receiving a copy of it.
#define IOR_CLONE_FILES 0x00000400ULL

// IOR_NEWTASK_CHILD_OUT_OF_SCOPE is the scope_flags bit of a record whose child
// is not in scope (see above); every other record carries 0 there, exactly like
// the always-zero reserved word it replaced, so an older object or a consumer
// that ignores the field reads "child in scope".
#define IOR_NEWTASK_CHILD_OUT_OF_SCOPE 0x1U

// ior_task_in_scope is filter() applied to an explicitly named task rather than
// to the current one. The task_newtask handler runs in the parent's context, so
// filter() itself would judge the parent, but what decides whether the child's
// syscalls are traced is the child's own tgid and tid: a fork() child of a -pid
// target has a different tgid and is out of scope, a new thread of a -pid target
// is in scope. The task_rename handler judges the renamed task the same way
// (it can run in a sibling thread's context). ior itself stays excluded - by the
// task's tgid, so its own threads produce no records, while a subprocess it
// spawns (a new tgid) is judged like any other process.
static __always_inline int
ior_task_in_scope(__u32 child_pid, __u32 child_tid) {
    if (child_pid == IOR_PID_FILTER)
        return 0;
    if (-1 != PID_FILTER && child_pid != PID_FILTER)
        return 0;
    if (-1 != TID_FILTER && child_tid != TID_FILTER)
        return 0;
    return 1;
}

// trace_event_raw_task_newtask___ior is a CO-RE "flavor" of the kernel's
// struct trace_event_raw_task_newtask, reduced to the two scalars this program
// reads; libbpf matches it to the kernel type by name (the ___ior suffix is
// ignored) and relocates the field offsets from the running kernel's BTF. Same
// reasoning as trace_event_raw_sched_process_exit___ior above: naming the
// vmlinux.h struct directly ties the build to the build host's kernel headers,
// and a host whose vmlinux.h lacks the struct could not compile the object.
// The context arrives as void * and is cast here, so the handler's signature
// does not depend on the vmlinux.h type either.
struct trace_event_raw_task_newtask___ior {
    int pid;
    unsigned long clone_flags;
} __attribute__((preserve_access_index));

SEC("tracepoint/task/task_newtask")
int handle_task_newtask(void *raw_ctx) {
    struct trace_event_raw_task_newtask___ior *ctx = raw_ctx;
    struct task_newtask_event *ev;
    __u64 clone_flags = ctx->clone_flags;
    __u32 child_tid = (__u32)ctx->pid;
    // The creator's tgid: this handler runs in the context of the task that
    // called clone, so the current task is the creator.
    __u64 creator_id = bpf_get_current_pid_tgid();
    __u32 creator_pid = (__u32)(creator_id >> 32);
    __u32 creator_tid = (__u32)creator_id;
    // The child's tgid: the creator's for a new thread, its own tid for a new
    // process. Derived rather than read from the child's task_struct so the
    // handler does not depend on when copy_process() assigns p->tgid relative to
    // the tracepoint.
    __u32 child_pid = (clone_flags & IOR_CLONE_THREAD)
        ? creator_pid
        : child_tid;

    __u32 scope_flags = 0;

    if (!ior_task_in_scope(child_pid, child_tid)) {
        // Out of scope: silent, except for a CLONE_FILES process child of an
        // in-scope creator, whose hidden table writes hit the creator's table.
        // A new thread (CLONE_THREAD) is excluded: it is not a separate
        // process, and a hidden sibling thread is the -tid limitation
        // documented in AGENTS.md, not something this record can fix.
        if (!(clone_flags & IOR_CLONE_FILES) || (clone_flags & IOR_CLONE_THREAD))
            return 0;
        if (!ior_task_in_scope(creator_pid, creator_tid))
            return 0;
        scope_flags = IOR_NEWTASK_CHILD_OUT_OF_SCOPE;
    }

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct task_newtask_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    ev->event_type = TASK_NEWTASK_EVENT;
    // Not a syscall tracepoint: there is no enter/exit trace id to report.
    ev->trace_id = 0;
    ev->pid = child_pid;
    ev->tid = child_tid;
    ev->time = bpf_ktime_get_boot_ns();
    // The child's name at creation is the creator's, and this handler runs in
    // the creator's context, so bpf_get_current_comm() reports it - the same
    // helper the exec handler uses, and it writes all sizeof(ev->comm) bytes
    // (NUL-padded), so the field needs no memset first; see "String fields in
    // ring-buffer records" in filter.c.
    //
    // The tracepoint's own comm field is deliberately not used. Copying the
    // char[16] out of the context compiles to context pointer arithmetic
    // followed by a dereference (r2 = ctx; r2 += <CO-RE offset>; *(u32 *)(r2 +
    // 4)), which the verifiers of the 4.18 and 5.14 kernels (RHEL/Rocky 8 and 9)
    // reject as "dereference of modified ctx ptr" - and one rejected program
    // fails the load of the whole object, so ior would not start at all. The
    // scalar fields above are plain fixed-offset loads and pass. Nor would a
    // raw copy be guaranteed clean: the tracepoint memcpy()s task->comm, which
    // older kernels write with strlcpy(), leaving whatever bytes followed the
    // terminator. bpf_get_current_comm() pads with NULs. Userspace cuts at the
    // first NUL (types.StringValue) either way.
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));
    ev->clone_flags = clone_flags;
    // The process whose descriptor table a non-thread, non-CLONE_FILES child
    // starts as a copy of (handleTaskNewtaskEvent), or shares for CLONE_FILES.
    // Ring-buffer memory is not zeroed, so scope_flags must always be written.
    ev->creator_pid = creator_pid;
    ev->scope_flags = scope_flags;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

// Why task_rename exists: nothing else reports a task renaming itself. A thread
// calls prctl(PR_SET_NAME) or pthread_setname_np() (which writes
// /proc/self/task/<tid>/comm), and the kernel changes task->comm without any
// syscall record, exec record or open payload telling userspace; the tid->comm
// cache then kept serving the old name for the rest of the thread's life (until
// an open event's payload comm happened to heal it). The visible damage was a
// wrong label on every later row and, under -comm, an inverted filter:
// -comm <new name> dropped the renamed thread's rows while -comm <old name> kept
// admitting them, and an openat dropped at the enter-side gate (no cached name
// match) could not heal the cache either.
//
// task:task_rename fires from __set_task_comm() for every change of task->comm:
// prctl, a /proc/<tid>/comm write (also by a sibling thread) and the exec's own
// rename in begin_new_exec (which merely repeats the sched_process_exec record's
// name). Emitting it as a control record into the syscall ring buffer gives
// userspace an ordered "this tid is now called X" notice, like the exec record:
// the buffer hands records out in reservation order to the single event-loop
// goroutine, so the rename is applied after the renaming task's earlier rows and
// before its later ones (handleTaskRenameEvent).
//
// It is attached as a RAW tracepoint (SEC raw_tracepoint, args = the
// TP_PROTO of the tracepoint: the task and the new name). The classic
// tracepoint's context carries the same name in a char[16] member, but, exactly
// as for task_newtask above, copying a context array compiles to ctx pointer
// arithmetic that the 4.18/5.14 verifiers reject - and one rejected program
// fails the load of the whole object. A raw tracepoint's args are plain u64
// loads at constant offsets. The name cannot be taken from the current task
// instead (bpf_get_current_comm): the tracepoint fires before the kernel stores
// the new name, and the renamed task need not be the current one.
//
// The renamed task is scoped like filter() but is named explicitly
// (ior_task_in_scope), because a /proc/<tid>/comm write renames a *sibling*
// thread: only the thread-group check in the kernel (same_thread_group) ties it
// to the writer, so the record's tgid is read from the renamed task itself.
//
// Cost: one 40-byte record per rename. Renames are rare (worker pools rename each
// thread once at start; exec renames once per exec), so this is far below the
// per-exec and per-newtask records in volume.

// ior_task_rename_args are the arguments of the task_rename raw tracepoint,
// TP_PROTO(struct task_struct *task, const char *comm). Declared as a struct
// rather than indexed ad hoc so each handler line names what it reads.
struct ior_task_rename_args {
    struct task_struct *task;
    const char *comm;
};

SEC("raw_tracepoint/task_rename")
// ctx is void *, cast straight to the argument struct: reaching the arguments
// through vmlinux.h's struct bpf_raw_tracepoint_args::args would add a CO-RE
// relocation (vmlinux.h types carry preserve_access_index) and so ctx pointer
// arithmetic, exactly what the plain loads at offsets 0 and 8 avoid.
int handle_task_rename(void *ctx) {
    struct ior_task_rename_args *args = ctx;
    struct task_struct *task = args->task;
    struct task_rename_event *ev;
    __u32 pid = (__u32)BPF_CORE_READ(task, tgid);
    __u32 tid = (__u32)BPF_CORE_READ(task, pid);

    if (!ior_task_in_scope(pid, tid))
        return 0;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct task_rename_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return 0;
    }

    // The name is read from the kernel buffer the tracepoint was handed
    // (a stack array of the caller for prctl and /proc writes, the basename of
    // the executable for exec); it is NUL-terminated by the helper on success.
    // A failed read leaves no usable name, so the record is dropped rather than
    // sent with an unterminated one; see "String fields in ring-buffer records"
    // in filter.c.
    if (bpf_probe_read_kernel_str(ev->comm, sizeof(ev->comm), args->comm) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }

    ev->event_type = TASK_RENAME_EVENT;
    // Not a syscall tracepoint: there is no enter/exit trace id to report.
    ev->trace_id = 0;
    ev->pid = pid;
    ev->tid = tid;
    ev->time = bpf_ktime_get_boot_ns();

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
