//+build ignore

/**
 * exec.c holds the hand-written tracepoint handlers that are not syscall
 * tracepoints: sched_process_exec, sched_process_exit and task_newtask.
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
    // Zero the explicit tail pad so no stale ring-buffer bytes reach userspace.
    ev->reserved = 0;

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
// worse than cosmetic: the enter-side gate recycles a non-open/exec enter whose
// tid has no cached comm yet, so such rows were dropped, silently.
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
// The name is the parent's: a fork()ed process that then execve()s is renamed
// by the sched_process_exec record; a bare thread keeps it until
// prctl(PR_SET_NAME)/pthread_setname_np, which no tracepoint reports (a
// pre-existing limitation of the comm cache, unchanged here).
//
// The record also carries the raw clone_flags, the input later consumers need
// to tell a thread from a process and to model the fd table the child inherits
// or shares (CLONE_FILES).
//
// Cost: one 48-byte record per created task, the same order as the per-exec and
// per-exit records, on the same ring buffer.

// IOR_CLONE_THREAD is CLONE_THREAD from include/uapi/linux/sched.h: the new
// task joins the creator's thread group instead of founding its own.
#define IOR_CLONE_THREAD 0x00010000ULL

// ior_newtask_in_scope is filter() applied to the *child*. The handler runs in
// the parent's context, so filter() itself would judge the parent, but what
// decides whether the child's syscalls are traced is the child's own tgid and
// tid: a fork() child of a -pid target has a different tgid and is out of scope,
// a new thread of a -pid target is in scope. ior itself stays excluded - by the
// child's tgid, so its own threads produce no records, while a subprocess it
// spawns (a new tgid) is judged like any other process.
static __always_inline int
ior_newtask_in_scope(__u32 child_pid, __u32 child_tid) {
    if (child_pid == IOR_PID_FILTER)
        return 0;
    if (-1 != PID_FILTER && child_pid != PID_FILTER)
        return 0;
    if (-1 != TID_FILTER && child_tid != TID_FILTER)
        return 0;
    return 1;
}

SEC("tracepoint/task/task_newtask")
int handle_task_newtask(struct trace_event_raw_task_newtask *ctx) {
    struct task_newtask_event *ev;
    __u64 clone_flags = ctx->clone_flags;
    __u32 child_tid = (__u32)ctx->pid;
    // The child's tgid: the creator's for a new thread, its own tid for a new
    // process. Derived rather than read from the child's task_struct so the
    // handler does not depend on when copy_process() assigns p->tgid relative to
    // the tracepoint.
    __u32 child_pid = (clone_flags & IOR_CLONE_THREAD)
        ? (__u32)(bpf_get_current_pid_tgid() >> 32)
        : child_tid;

    if (!ior_newtask_in_scope(child_pid, child_tid))
        return 0;

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
    // The tracepoint's own comm field is the child's name at creation. It is
    // copied whole (16 bytes, NUL-padded by the kernel), so the field needs no
    // memset first; see "String fields in ring-buffer records" in filter.c.
    __builtin_memcpy(ev->comm, ctx->comm, sizeof(ev->comm));
    ev->clone_flags = clone_flags;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
