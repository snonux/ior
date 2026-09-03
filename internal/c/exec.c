//+build ignore

/**
 * exec.c holds the hand-written sched:sched_process_exec handler.
 *
 * Why this exists: the comm shown for a syscall used to come from an
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
    __builtin_memset(&(ev->comm), 0, sizeof(ev->comm));
    bpf_get_current_comm(&ev->comm, sizeof(ev->comm));

    bpf_ringbuf_submit(ev, 0);
    return 0;
}
