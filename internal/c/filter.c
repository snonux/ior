//+build ignore

#define ACCEPT 0
#define FILTER 1
#define IOR_HISTOGRAM_BUCKETS 8
#define IOR_MAX_PID_NS_LEVEL 32
#define IOR_MAX_ERRNO 4095

static __always_inline int ior_is_errno_ret(__s64 ret) {
    return ret >= -IOR_MAX_ERRNO && ret < 0;
}

// Return the current thread group's PID as seen in its active PID namespace.
// bpf_get_current_pid_tgid() reports the kernel's host TGID, while syscall PID
// arguments are interpreted in the caller's namespace. Follow the signal
// struct's TGID pid (the backing object used by the kernel's task_tgid()) to
// its innermost namespace number so kcmp can prove a self comparison while the
// caller is still alive at sys_enter.
static __always_inline __u32 ior_current_namespace_tgid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct signal_struct *signal;
    struct pid *tgid_pid;
    __u32 level;
    __s32 tgid;

    signal = BPF_CORE_READ(task, signal);
    if (!signal)
        return 0;
    tgid_pid = BPF_CORE_READ(signal, pids[PIDTYPE_TGID]);
    if (!tgid_pid)
        return 0;
    level = BPF_CORE_READ(tgid_pid, level);
    if (level > IOR_MAX_PID_NS_LEVEL)
        return 0;
    if (bpf_core_read(&tgid, sizeof(tgid), &tgid_pid->numbers[level].nr))
        return 0;
    return tgid > 0 ? (__u32)tgid : 0;
}

static __always_inline int ior_kcmp_pid_is_current(__s32 pid1) {
    if (pid1 <= 0)
        return 0;
    return (__u32)pid1 == ior_current_namespace_tgid();
}

// ior_count_ringbuf_drop records one event lost to a full event_map ring
// buffer. Every generated tracepoint handler calls it on the
// bpf_ringbuf_reserve() NULL path, which is the only place ior loses events
// kernel-side; userspace reports the summed value in the run statistics and
// as a live TUI warning, so backpressure is no longer invisible.
//
// ringbuf_drop_map is a single-slot PERCPU_ARRAY, so the lookup yields this
// CPU's private counter and the increment needs no atomic. The map is
// pre-allocated by the kernel: the lookup can only fail if the map is missing,
// in which case dropping the count is the correct, verifier-safe fallback.
static __always_inline void ior_count_ringbuf_drop(void) {
    __u32 key = 0;
    __u64 *drops = bpf_map_lookup_elem(&ringbuf_drop_map, &key);

    if (drops)
        *drops += 1;
}

static __always_inline __u32 ior_histogram_bucket_index(__u64 duration_ns) {
    if (duration_ns < 1000)
        return 0;
    if (duration_ns < 10000)
        return 1;
    if (duration_ns < 100000)
        return 2;
    if (duration_ns < 1000000)
        return 3;
    if (duration_ns < 10000000)
        return 4;
    if (duration_ns < 100000000)
        return 5;
    if (duration_ns < 1000000000)
        return 6;
    return 7;
}

static __always_inline void ior_update_syscall_aggregate(__u32 enter_trace_id, __u64 duration_ns, __s64 ret) {
    __u32 bucket_idx;
    struct syscall_aggregate *existing;
    struct syscall_aggregate fresh = {};

    existing = bpf_map_lookup_elem(&syscall_aggregate_map, &enter_trace_id);
    bucket_idx = ior_histogram_bucket_index(duration_ns);
    if (bucket_idx >= IOR_HISTOGRAM_BUCKETS)
        bucket_idx = IOR_HISTOGRAM_BUCKETS - 1;

    if (existing) {
        existing->count += 1;
        existing->total_duration_ns += duration_ns;
        if (ior_is_errno_ret(ret))
            existing->errors += 1;
        if (existing->count == 1 || duration_ns < existing->min_duration_ns)
            existing->min_duration_ns = duration_ns;
        if (duration_ns > existing->max_duration_ns)
            existing->max_duration_ns = duration_ns;
        existing->duration_histogram[bucket_idx] += 1;
        return;
    }

    fresh.count = 1;
    fresh.total_duration_ns = duration_ns;
    fresh.min_duration_ns = duration_ns;
    fresh.max_duration_ns = duration_ns;
    if (ior_is_errno_ret(ret))
        fresh.errors = 1;
    fresh.duration_histogram[bucket_idx] = 1;
    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);
}

static __always_inline int ior_should_emit_trace(__u32 enter_trace_id) {
    __u32 default_rate = 1;
    __u32 *configured = bpf_map_lookup_elem(&syscall_sampling_rate_map, &enter_trace_id);
    __u32 rate = configured ? *configured : default_rate;

    // A zero rate means aggregate-only mode for this syscall.
    if (rate == 0)
        return 0;
    if (rate == 1)
        return 1;
    return (bpf_get_prandom_u32() % rate) == 0;
}

// The per-syscall hooks below take the handler's timestamp instead of reading
// the clock themselves. Each generated handler calls bpf_ktime_get_boot_ns()
// exactly once and uses that one value both here and for ev->time, so a traced
// syscall costs two clock helper calls (one per side) instead of four, and the
// kernel-side duration (syscall_aggregate_map) and the userspace duration
// (exit ev->time - enter ev->time) are derived from the same two instants.
static __always_inline int ior_on_syscall_enter(__u32 tid, __u32 enter_trace_id, __u64 now) {
    struct syscall_enter_state state = {};

    state.start_ns = now;
    state.enter_trace_id = enter_trace_id;
    state.emit_event = ior_should_emit_trace(enter_trace_id) ? 1 : 0;
    bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY);
    return state.emit_event != 0;
}

// ior_on_noreturn_syscall_enter is the enter hook for noreturn syscalls
// (exit, exit_group, rt_sigreturn). Unlike ior_on_syscall_enter it deliberately
// does NOT write a per-tid entry into syscall_enter_state_map. A noreturn
// syscall never returns to the syscall site (exit/exit_group terminate;
// rt_sigreturn restores the pre-signal context), so its sys_exit tracepoint
// never fires and the matching
// exit handler is suppressed by the generator (see internal/generate/codegen.go
// isNoreturnSyscall). With no exit handler, nothing would ever look up or
// bpf_map_delete_elem that enter-state entry, so recording it would only leave
// stale per-tid entries crowding the bounded (32768) map on hosts churning many
// distinct tids. We still honor the sampling decision so the enter null_event is
// emitted (or dropped) exactly as a normal syscall's enter would be, but without
// the dead, unreclaimable map write.
static __always_inline int ior_on_noreturn_syscall_enter(__u32 enter_trace_id) {
    return ior_should_emit_trace(enter_trace_id);
}

static __always_inline int ior_on_syscall_exit(__u32 tid, __u32 enter_trace_id, __s64 ret, __u64 now) {
    __u64 duration = 0;
    __u8 emit_event = 1;
    struct syscall_enter_state *state;

    state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);
    if (!state)
        return 1;

    if (now >= state->start_ns)
        duration = now - state->start_ns;

    emit_event = state->emit_event;

    // Aggregate-vs-emit partitioning: this map counts exactly the syscalls
    // that userspace will NOT see as ring-buffer events, so the kernel
    // aggregate and the per-event stream are disjoint and their sum is the
    // true invocation count:
    //   rate 0 (aggregate-only): nothing is emitted, everything lands here.
    //   rate 1 (trace all):      everything is emitted, nothing lands here
    //                            (the aggregate map stays empty for it).
    //   rate N (1-in-N):         the ~1/N emitted pairs are counted user-side
    //                            by the stats engine, the other (N-1)/N land
    //                            here and are merged in by the aggregate
    //                            drainer — no double counting, no scaling
    //                            estimate.
    // Counting emitted events here as well would double-count every traced
    // syscall once the drainer ingests rows for sampled trace IDs.
    //
    // Pairing uses the explicit enter_trace_id passed by the generated exit
    // handler, avoiding any numeric adjacency assumption between
    // kernel-assigned enter and exit tracepoint IDs.
    if (!emit_event && state->enter_trace_id == enter_trace_id)
        ior_update_syscall_aggregate(state->enter_trace_id, duration, ret);

    bpf_map_delete_elem(&syscall_enter_state_map, &tid);
    return emit_event != 0;
}

// Recovering an open filename whose sys_enter read faulted.
//
// bpf_probe_read_user_str() is a *nofault* read: it runs with page faults
// disabled, so it cannot bring in a user page that is not resident and returns
// -EFAULT instead, leaving no name in the destination buffer. For open-family
// syscalls that is not a rare corner case. The path string usually lives in
// freshly mapped, never-touched memory - the classic case is the very first
// openat a program makes through a library it has only just mmap'ed, where the
// string sits in the library's .rodata and nothing has faulted that page in
// yet. Measured on this tree, ~2% of system-wide openat events and ~15% of the
// openats of short-lived fork/exec workloads lost their filename that way. The
// row then printed "E:name", the descriptor was registered under the empty
// string so every later read/write/close on it lost its path too, and -path
// could not match a name that was never captured.
//
// Retrying at sys_enter cannot help (the page is still not resident and the
// read still cannot fault), but by sys_exit the kernel itself has copied the
// path in through getname(), so the page is resident and the identical read
// succeeds. The three helpers below implement exactly that: the enter handler
// stashes the user pointer on failure, the exit handler takes it back and
// re-reads the string into a control record that userspace splices into the
// still-pending enter event before the pair is completed.
//
// Open handlers and named descriptor creators (memfd_create/fsopen) do this.
// In both cases a lost name propagates past the row itself into the fd table.
// The control event keeps its original open-oriented name for wire/runtime
// compatibility, but the recovery mechanism itself is intentionally shared.

// ior_stash_pending_filename records filename_ptr on this tid's in-flight
// syscall state so the matching exit handler can retry the read. Called only
// on the read-failure path, so the extra map lookup stays off the hot path.
static __always_inline void ior_stash_pending_filename(__u32 tid, __u64 filename_ptr) {
    struct syscall_enter_state *state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);

    if (state)
        state->pending_filename = filename_ptr;
}

// ior_take_pending_filename returns the pointer stashed by the matching enter
// handler, or 0 when there is nothing to recover. It must be called BEFORE
// ior_on_syscall_exit, which deletes the per-tid entry. The enter_trace_id
// check makes a stale entry from a different syscall unusable rather than
// letting it graft a foreign path onto this pair.
static __always_inline __u64 ior_take_pending_filename(__u32 tid, __u32 enter_trace_id) {
    struct syscall_enter_state *state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);

    if (!state || state->enter_trace_id != enter_trace_id)
        return 0;
    return state->pending_filename;
}

// String fields in ring-buffer records.
//
// bpf_ringbuf_reserve() hands out memory that is not zeroed: until a handler
// writes them, the bytes of a record are whatever an earlier record of the same
// ring buffer left there. (That is not a verifier concern - ring-buffer memory
// is not stack memory, so the verifier does not track whether it has been
// initialized.) The generated handlers used to clear every string field with a
// full-buffer __builtin_memset before reading it - 256 bytes per path, 512 for
// the two names of a rename, i.e. 32 or 64 stores on every event - so that a
// record carried nothing but the captured string and zeros.
//
// Userspace never reads past a string's first NUL: every consumer goes through
// types.StringValue, and the *_status field, not the bytes, says whether the
// read succeeded. So a string field only has to be terminated. A successful
// bpf_probe_read_user_str() writes the NUL itself (it also truncates an
// over-long string to size - 1 bytes plus NUL); on every other path - a NULL
// pointer, a failed read, or a kind that does not capture that string - the
// generated code writes the first byte (writeStringTerminator in
// internal/generate/bpfhandler.go). It does so even after a failed read, where
// the helper zero-fills the destination as well, so the empty result does not
// depend on that helper detail. bpf_get_current_comm() always writes all of
// comm (NUL-padded), so comm needs no initialization at all.
//
// Decision: the bytes after the terminator stay stale. They can only come from
// earlier records of this same ring buffer, whose whole data area ior - its
// only reader - already has mapped read-only, so they expose nothing ior could
// not read anyway. They must still never reach output: the decoders copy
// them into pooled Go structs, and everything that turns a string field into
// text has to stop at the NUL. That includes the generated String() methods -
// fmt's %v of an event - which the uncached-comm warning renders into a
// searchable, exportable TUI stream row; they rendered whole arrays until the
// task 79 review and now go through types.StringValue as well
// (writeStringMethod in internal/generate/typesgo.go). Only the test-only
// Equals() still compares whole arrays. The generator tests pin the BPF shape
// (internal/generate/stringterminator_test.go) and userspace tests pin that
// garbage after the NUL cannot change a row or a warning
// (internal/eventloop_stringtail_test.go, internal/types/stringtail_test.go).

// ior_emit_open_name_fixup re-reads the identifying string at sys_exit and publishes it
// as a compact OPEN_NAME_FIXUP_EVENT control record. It is reserved and
// submitted before the exit event of the same syscall, and the ring buffer
// preserves that order, so the single userspace consumer always applies the
// fix while the enter event is still pending and unpaired.
//
// A still-failing read is discarded rather than submitted. A successful read
// of an empty C string returns 1 and is deliberately submitted: that control
// record proves the original non-NULL pathname was a valid empty string.
static __always_inline void ior_emit_open_name_fixup(__u32 tid, __u32 enter_trace_id,
                                                     __u64 filename_ptr) {
    struct open_name_fixup_event *ev;

    if (!filename_ptr)
        return;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct open_name_fixup_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return;
    }

    ev->event_type = OPEN_NAME_FIXUP_EVENT;
    ev->trace_id = enter_trace_id;
    ev->tid = tid;
    // No memset: a submitted record always holds a successful read, which is
    // NUL-terminated (see "String fields in ring-buffer records" above).
    if (bpf_probe_read_user_str(ev->filename, sizeof(ev->filename), (void *)filename_ptr) < 0) {
        bpf_ringbuf_discard(ev, 0);
        return;
    }

    bpf_ringbuf_submit(ev, 0);
}

// filter() decides whether the current task's syscall is in scope. Today this is
// a single-TGID gate (PID_FILTER, with -1 meaning trace-all) plus an optional
// TID_FILTER. ior does NOT follow forks: a traced process's children run under a
// different TGID and are excluded here, which also means their syscalls miss the
// aggregate-count path downstream. A planned opt-in process-tree-following mode
// would extend this gate to also accept descendant TGIDs from a BPF-maintained
// set seeded with the root PID and updated via sched_process_fork/exit — see
// docs/follow-forks-plan.md for the full design.
static __always_inline int filter(__u32 *pid, __u32 *tid) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    *pid = pid_tgid >> 32;

    // Ignore ior userland process itself
    if (*pid == IOR_PID_FILTER) {
        return FILTER;
    }
    
    *tid = pid_tgid & 0xFFFFFFFF;
    if (-1 == PID_FILTER || *pid == PID_FILTER) {
        if (-1 == TID_FILTER || *tid == TID_FILTER) {
            return ACCEPT;
        }
    }

    return FILTER;
}
