//+build ignore

/**
 * exec.c holds the hand-written sched tracepoint handlers that are not
 * syscall tracepoints: sched_process_exec and sched_process_exit.
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
 * Cost: one small (40-byte) record per successful execve, versus the
 * alternative of stamping bpf_get_current_comm() onto every single syscall
 * event, which would add 16 bytes to every ring-buffer record on a path where
 * ring-buffer pressure is already a tracked concern (ringbuf_drop_map).
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u32 pid, tid;
    struct process_exec_event *ev;

    if (filter(&pid, &tid))
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
// Older kernels fall back to reading task->signal->live directly. do_exit()
// decrements live before it fires the tracepoint and nothing can increment it
// again once the group is exiting, so live == 0 here means every thread has
// passed that point: the process is dead. The last thread to decrement always
// reads its own decrement, so at least one exit record of a group carries
// group_dead = 1. Two threads exiting concurrently can both observe 0 and
// both report it; userspace eviction is idempotent, so the duplicate is
// harmless. A failed read (NULL signal) reports 0 rather than guessing - the
// fd entries then linger until LRU trimming, the same outcome as a record lost
// to ring-buffer backpressure.
//
// Verification status: the field path is exercised end to end by the
// integration scenario thread-exit-keeps-fd (integrationtests) on the 7.2
// development host, whose tracepoint has group_dead. The signal->live
// fallback compiles to valid CO-RE relocations but has not been run on a
// kernel lacking the field; its correctness rests on the do_exit() ordering
// argued above.
static __always_inline __u32
ior_exit_group_dead(struct trace_event_raw_sched_process_exit *ctx) {
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
// exception: a group-dead exit bypasses the TID_FILTER dimension, while still
// honouring PID_FILTER and the exclusion of ior itself.
//
// Why the exception: under -tid, filter() only admits the traced thread, but
// the thread that ends the group - the only record userspace evicts the
// process's fd entries on - is usually another one. Without the bypass a
// -tid run would never evict its process's descriptors at all, a regression
// against the old evict-on-every-exit behaviour that did fire for the traced
// thread. The price, only under -tid without -pid, is one record per process
// death system-wide; userspace eviction of a pid it never tracked is O(1),
// and dropping the dying thread's tid-keyed state is correct for any tid.
// group_dead is only read once the pid dimension has passed, so -pid runs pay
// no extra cost for the exits of unrelated processes.
static __always_inline int
ior_process_exit_in_scope(struct trace_event_raw_sched_process_exit *ctx,
                          __u32 *pid, __u32 *tid, __u32 *group_dead) {
    if (!filter(pid, tid)) {
        *group_dead = ior_exit_group_dead(ctx);
        return 1;
    }
    // Rejected by the pid dimension (or ior itself): no bypass. filter() only
    // consults TID_FILTER after both pid checks passed, so with no TID_FILTER
    // the rejection was necessarily a pid one.
    if (*pid == IOR_PID_FILTER || -1 == TID_FILTER)
        return 0;
    if (-1 != PID_FILTER && *pid != PID_FILTER)
        return 0;
    *group_dead = ior_exit_group_dead(ctx);
    return *group_dead;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_sched_process_exit(struct trace_event_raw_sched_process_exit *ctx) {
    __u32 pid, tid, group_dead;
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
