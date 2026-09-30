//+build ignore

#define ACCEPT 0
#define FILTER 1
#define IOR_HISTOGRAM_BUCKETS 8
#define IOR_MAX_PID_NS_LEVEL 32
#define IOR_MAX_ERRNO 4095
// E2BIG as returned by a BPF hash map update when the map is full; vmlinux.h
// carries no errno macros.
#define IOR_E2BIG 7

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

// ior_aggregate_has_timed_samples reports whether agg already holds at least
// one invocation with a measured duration. A row can carry untimed counts
// (ior_count_untimed_syscall below), whose invocations have no duration and so
// must never seed min_duration_ns; and on a PERCPU_HASH the slots of the other
// CPUs start zeroed. Either way "count == 1" no longer identifies the first
// timed sample, the histogram does: every timed update bumps exactly one
// bucket. max_duration_ns is non-zero for every settled timed row, because
// ior_on_syscall_exit clamps durations to at least 1ns, so the hot path costs
// one compare; the bucket scan only runs for fresh or untimed-only rows (and
// guards a row whose max store has not landed yet).
static __always_inline int ior_aggregate_has_timed_samples(const struct syscall_aggregate *agg) {
    if (agg->max_duration_ns)
        return 1;
    for (int i = 0; i < IOR_HISTOGRAM_BUCKETS; i++) {
        if (agg->duration_histogram[i])
            return 1;
    }
    return 0;
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
        // Store order matters. Userspace reads this CPU's slot while it may
        // be half-updated, and derives the untimed part of count as count
        // minus the histogram total (internal/syscall_aggregate_consumer.go).
        // The kernel copies a slot to userspace in ascending address order,
        // and count is the first field of struct syscall_aggregate (maps.h),
        // so count is read first; storing it last means a torn read can only
        // show the other fields ahead of count, never count ahead of them.
        // Userspace handles "histogram ahead" exactly (a timed invocation in
        // flight). "Count ahead" would look like an untimed invocation and
        // be booked as one for good (its latency still arrives with a later
        // row); it cannot happen on x86, whose stores are not reordered. The
        // empty asm is a compiler barrier that keeps clang from sinking the
        // other stores below the count store; weakly ordered CPUs would need
        // a real barrier. The min seeding decision must come first, before
        // this very sample bumps the histogram that
        // ior_aggregate_has_timed_samples inspects.
        if (!ior_aggregate_has_timed_samples(existing) || duration_ns < existing->min_duration_ns)
            existing->min_duration_ns = duration_ns;
        existing->total_duration_ns += duration_ns;
        existing->duration_histogram[bucket_idx] += 1;
        if (duration_ns > existing->max_duration_ns)
            existing->max_duration_ns = duration_ns;
        if (ior_is_errno_ret(ret))
            existing->errors += 1;
        asm volatile("" ::: "memory");
        existing->count += 1;
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

// ior_count_untimed_syscall counts one invocation of enter_trace_id into
// syscall_aggregate_map without a duration or a return value: only count
// moves. It is the fallback for an enter whose syscall_enter_state_map write
// failed (see ior_on_syscall_enter), where neither the start time nor the
// sampling decision survives until sys_exit. The row's latency fields and
// histogram keep describing the timed invocations only, so userspace sees
// count > sum(histogram) and must not take min/max from a row without
// histogram samples (rawSyscallAggregate.add in
// internal/syscall_aggregate_consumer.go). Errors of untimed invocations are
// unknown and not counted.
static __always_inline void ior_count_untimed_syscall(__u32 enter_trace_id) {
    struct syscall_aggregate *existing;
    struct syscall_aggregate fresh = {};

    existing = bpf_map_lookup_elem(&syscall_aggregate_map, &enter_trace_id);
    if (existing) {
        existing->count += 1;
        return;
    }

    fresh.count = 1;
    bpf_map_update_elem(&syscall_aggregate_map, &enter_trace_id, &fresh, BPF_ANY);
}

// ior_sampling_rate returns the configured sampling rate of enter_trace_id:
// 0 = aggregate-only, 1 = emit every event (also the default for a syscall
// userspace did not configure), N = emit 1-in-N.
static __always_inline __u32 ior_sampling_rate(__u32 enter_trace_id) {
    __u32 *configured = bpf_map_lookup_elem(&syscall_sampling_rate_map, &enter_trace_id);

    return configured ? *configured : 1;
}

static __always_inline int ior_sample_rate_emits(__u32 rate) {
    // A zero rate means aggregate-only mode for this syscall.
    if (rate == 0)
        return 0;
    if (rate == 1)
        return 1;
    return (bpf_get_prandom_u32() % rate) == 0;
}

static __always_inline int ior_should_emit_trace(__u32 enter_trace_id) {
    return ior_sample_rate_emits(ior_sampling_rate(enter_trace_id));
}

// Enter state and its two fallbacks.
//
// The aggregate map and the ring-buffer stream must partition the invocations
// exactly (see ior_on_syscall_exit), and the per-tid syscall_enter_state_map
// entry is what carries the sampling decision from sys_enter to sys_exit. Two
// situations leave a sys_exit without a matching entry, and both are handled
// so that every invocation whose sys_enter ior saw is counted exactly once:
//
//   1. The enter-state write fails. syscall_enter_state_map is a bounded
//      (32768) HASH, and a host-wide trace with more threads parked inside
//      traced syscalls (futex, epoll_wait, ...) fills it. A full map only
//      rejects tids without an entry yet (replacing an entry in place uses
//      the map's spare per-CPU element); rarer failures such as -EBUSY
//      bucket-lock contention or -ENOMEM take the same path, and those can
//      hit a tid that still holds an older entry, so ior_on_syscall_enter
//      tries to delete this tid's entry before falling back (best effort, see
//      there). Whatever the cause,
//      ior_on_enter_state_lost then decides by rate alone, without the
//      per-invocation sample: at rate 1 the enter is emitted and the
//      stateless exit below emits too, so userspace pairs them as usual; at
//      any other rate an emitted enter could never be paired (its exit is
//      suppressed), so the enter is suppressed and the invocation is counted
//      right here with ior_count_untimed_syscall. Its duration and errno are
//      lost, its count is not.
//
//   2. The exit has no entry of its own: the child side of clone/clone3/
//      fork/vfork (its first return runs in a task that never entered the
//      syscall), a syscall already in flight when the tracepoints were
//      attached, or case 1 above. A stale entry left by a different syscall
//      (enter_trace_id mismatch) is the same situation. An execve by a
//      non-leader thread returns under the leader's tid (de_thread), but
//      ior_on_exec_tid_change moves its entry there before the exit runs,
//      so it normally pairs; its exit stays stateless only when there was
//      nothing to move - -tid <leader> filtered the caller's enter - or
//      when the move's insert failed.
//      ior_stateless_exit_emits emits such an exit only when the syscall's
//      rate is 1, i.e. exactly when a rate-1 enter would have been emitted,
//      and never counts it: its enter was either never seen (nothing to
//      count, as at rate 1, where userspace drops the unpaired exit) or was
//      already counted by case 1. Emitting it at rate 0/N would ship an
//      orphan exit for an aggregate-only syscall - every clone child did so
//      before - and counting it would count a clone twice.
//
// The rate is read again at sys_exit. Userspace writes the sampling map once
// before the tracepoints are attached, so it cannot change between the two.
static __always_inline int ior_on_enter_state_lost(__u32 enter_trace_id, __u32 rate) {
    if (rate == 1)
        return 1;
    ior_count_untimed_syscall(enter_trace_id);
    return 0;
}

static __always_inline int ior_stateless_exit_emits(__u32 enter_trace_id) {
    return ior_sampling_rate(enter_trace_id) == 1;
}

// The per-syscall hooks below take the handler's timestamp instead of reading
// the clock themselves. Each generated handler calls bpf_ktime_get_boot_ns()
// exactly once and uses that one value both here and for ev->time, so a traced
// syscall costs two clock helper calls (one per side) instead of four, and the
// kernel-side duration (syscall_aggregate_map) and the userspace duration
// (exit ev->time - enter ev->time) are derived from the same two instants.
static __always_inline int ior_on_syscall_enter(__u32 tid, __u32 enter_trace_id, __u64 now) {
    struct syscall_enter_state state = {};
    __u32 rate = ior_sampling_rate(enter_trace_id);
    long err;

    state.start_ns = now;
    state.enter_trace_id = enter_trace_id;
    state.emit_event = ior_sample_rate_emits(rate) ? 1 : 0;
    err = bpf_map_update_elem(&syscall_enter_state_map, &tid, &state, BPF_ANY);
    if (err) {
        // A failed replacement (-EBUSY, -ENOMEM) can leave this tid's previous
        // entry behind; its exit would then pair with the wrong start time
        // and sampling decision. Dropping it is best effort: the delete can
        // hit the same -EBUSY bucket lock, and a leftover entry then still
        // falls to the mismatch check in ior_on_syscall_exit unless it is
        // for the same syscall. -E2BIG (full map) only rejects tids without
        // an entry, so there is nothing to delete.
        if (err != -IOR_E2BIG)
            bpf_map_delete_elem(&syscall_enter_state_map, &tid);
        return ior_on_enter_state_lost(enter_trace_id, rate);
    }
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
    __u64 duration;
    __u8 emit_event = 1;
    struct syscall_enter_state *state;

    state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);
    if (!state)
        return ior_stateless_exit_emits(enter_trace_id);
    // A different syscall's leftover entry says nothing about this one: drop
    // it (the tid is back at the syscall boundary, so it is dead anyway) and
    // treat the exit as stateless. See "Enter state and its two fallbacks".
    if (state->enter_trace_id != enter_trace_id) {
        bpf_map_delete_elem(&syscall_enter_state_map, &tid);
        return ior_stateless_exit_emits(enter_trace_id);
    }

    // A completed invocation always has a duration of at least 1ns in the
    // aggregate. A coarse clocksource can return the same reading at enter
    // and exit, but a 0 duration would leave min_duration_ns/max_duration_ns
    // at 0, which userspace reserves for "first timed sample still being
    // written" (normalizeTornSlot in internal/syscall_aggregate_consumer.go)
    // and would then drop the slot's latency for the rest of the session.
    // The clamp also covers a start timestamp ahead of now.
    duration = now > state->start_ns ? now - state->start_ns : 1;

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
    // kernel-assigned enter and exit tracepoint IDs. A mismatching entry has
    // already been diverted to the stateless path above; the ID check below
    // restates that invariant right at the only aggregate write.
    if (!emit_event && state->enter_trace_id == enter_trace_id)
        ior_update_syscall_aggregate(state->enter_trace_id, duration, ret);

    bpf_map_delete_elem(&syscall_enter_state_map, &tid);
    return emit_event != 0;
}

// ior_on_exec_tid_change carries an in-flight execve's enter state across the
// tid change a non-leader exec makes. It is called from sched_process_exec
// (exec.c) with the tracepoint's old_pid (the caller's pre-exec tid) and the
// current tid.
//
// When a thread other than the group leader calls execve, de_thread() kills
// every other thread, waits for the leader to become a zombie and then
// swaps pids with it: the exec'ing task continues under the leader's tid
// (== tgid), and sys_exit_execve fires under that tid. The entry
// ior_on_syscall_enter wrote under the old tid would never be looked up
// again - it lingered until tid reuse, crowding the bounded map - and the
// exit ran down the stateless path, so the invocation lost its duration and,
// at a rate other than 1, was never counted at all.
//
// Moving the entry to the new tid lets ior_on_syscall_exit pair it as usual.
// Whatever the new tid still holds belongs to the dead leader: a zombie
// already passed its own sys_exit (which deleted its entry), and anything left
// is stale, so BPF_ANY overwrites it. The old entry is deleted before the
// insert, which frees its slot for the insert on a full map.
//
// Two cases cannot pair and fall back to counting (see "Enter state and its
// two fallbacks"):
//   - The insert fails. The exit then finds no entry and is stateless, which
//     is exactly the lost-state case 1: ior_on_enter_state_lost counts the
//     invocation untimed unless the rate is 1 (where the stateless exit is
//     emitted and pairs in userspace).
//   - The new tid is out of scope (in_scope 0, e.g. -tid traced the
//     exec'ing thread and the leader's tid is filtered): the exit handler
//     never runs. An invocation whose enter was not emitted would have been
//     counted there, so it is counted here, untimed. An emitted enter is
//     userspace's: the exec record, still emitted for the traced caller and
//     flagged exit_untraced (ior_exec_record_scope in exec.c), makes
//     userspace complete it, so it is counted exactly once - unless that
//     record's ring-buffer reserve fails: the entry is already gone here, no
//     exit arrives and there is no exit for adoptLostExecCaller to adopt
//     from, so the invocation is lost (the drop is counted in
//     ringbuf_drop_map; the parked enter ages out of userspace's LRU).
static __always_inline void ior_on_exec_tid_change(__u32 old_tid, __u32 new_tid, int in_scope) {
    struct syscall_enter_state moved;
    struct syscall_enter_state *state;

    if (old_tid == new_tid)
        return;
    state = bpf_map_lookup_elem(&syscall_enter_state_map, &old_tid);
    if (!state)
        return;
    moved = *state;
    bpf_map_delete_elem(&syscall_enter_state_map, &old_tid);

    if (!in_scope) {
        if (!moved.emit_event)
            ior_count_untimed_syscall(moved.enter_trace_id);
        return;
    }
    if (bpf_map_update_elem(&syscall_enter_state_map, &new_tid, &moved, BPF_ANY))
        ior_on_enter_state_lost(moved.enter_trace_id, ior_sampling_rate(moved.enter_trace_id));
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
//
// getcwd reuses the same three helpers for a different reason: its path is an
// OUTPUT buffer the kernel only fills during the call, so there is nothing to
// read at sys_enter (outputPathSyscalls in internal/generate/classify.go). Its
// enter handler stashes args[0] unconditionally once ior_on_syscall_enter has
// decided to emit the event; its exit handler takes the pointer the same way
// but emits the fixup only when ctx->ret > 0, because a failed getcwd wrote
// nothing into the buffer. Userspace attaches that string to the pending pair
// instead of splicing it into the (header-only) enter event
// (applyCapturedOutputPath / finishGetcwdPath, internal/eventloop_getcwd.go).

// ior_stash_pending_filename records filename_ptr on this tid's in-flight
// syscall state so the matching exit handler can read the string there. The
// open kinds call it only on the read-failure path, so the extra map lookup
// stays off their hot path; getcwd calls it on every emitted enter, since its
// output buffer can only be read at sys_exit (see above).
static __always_inline void ior_stash_pending_filename(__u32 tid, __u64 filename_ptr) {
    struct syscall_enter_state *state = bpf_map_lookup_elem(&syscall_enter_state_map, &tid);

    if (state)
        state->pending_filename = filename_ptr;
}

// ior_take_pending_filename returns the pointer stashed by the matching enter
// handler, or 0 when there is nothing to read. It must be called BEFORE
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

// ior_emit_open_name_fixup reads the identifying string at sys_exit - a second
// read of a faulted open name, or the first read of getcwd's output buffer,
// which the generated caller guards with ctx->ret > 0 - and publishes it
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
