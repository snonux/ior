//+build ignore

/**
 * restart.c proves, kernel-side, that a syscall interrupted by a signal is
 * carried on by the kernel - re-executed, or resumed through restart_syscall -
 * so userspace can fold the interrupted row and its continuation into one row
 * (tasks 103 and t13, internal/eventloop_restart.go).
 *
 * The problem. A blocked read, accept, futex wait, wait4, ... that a signal
 * interrupts exits with -ERESTARTSYS (-512), -ERESTARTNOINTR (-513) or
 * -ERESTARTNOHAND (-514); a blocked nanosleep, clock_nanosleep, poll or timed
 * futex wait with -ERESTART_RESTARTBLOCK (-516). What happens next is decided
 * on the way back to user mode (x86 arch_do_signal_or_restart / handle_signal,
 * the same on arm64):
 *
 *   - no user handler runs for it (SIGSTOP/SIGCONT, an ignored or default-
 *     ignored signal, a signal another thread took, a ptrace or freezer stop):
 *     the kernel rewinds the instruction pointer and the task re-executes the
 *     very same syscall - or, for -516, executes restart_syscall in its
 *     place, which finishes the call from the task's restart block. The
 *     program never learns the call was interrupted.
 *   - a handler runs: -513 is still restarted, -512 only when the handler was
 *     installed with SA_RESTART, -514 and -516 never; otherwise the program
 *     gets EINTR. A restarted call is re-executed when the handler returns
 *     (rt_sigreturn), after whatever syscalls the handler made.
 *
 * To the syscall tracepoints both outcomes look alike: the exit with the
 * restart code, later an enter of the same syscall. A program that got EINTR
 * and retried by itself (the Go runtime, every C retry loop) produces exactly
 * that as well, and its retry is a call of its own that must stay a row.
 *
 * -516 looked like the exception, because its continuation has a name of its
 * own: restart_syscall resumes a -516 call and nothing else, so userspace
 * used to fold on the stream alone - a -516 exit whose tid's next record is a
 * restart_syscall enter (task fs2). That holds only while the next record
 * that ARRIVES is the next thing the thread did. After a handled signal the
 * call has no restart_syscall (EINTR), and the records that would say so -
 * the handler's syscalls, its rt_sigreturn - are silent whenever they are not
 * traced, sampled out, or the handler leaves by siglongjmp. A later call of
 * the thread that is silent too and gets stopped then has its
 * restart_syscall arrive right behind the -516 exit, and was folded into a
 * call that had returned EINTR long before (task t13). So -516 takes the same
 * proof as the other three codes.
 *
 * Why userspace cannot decide it from signal records alone. signal:signal_deliver
 * fires in the task that dequeues a signal, and only there. When a process is
 * stopped, one thread dequeues SIGSTOP and every other thread blocked in a
 * syscall is interrupted and restarted without dequeuing anything; the same
 * holds for a process-directed signal a sibling thread took. So "no handler
 * ran" has no record, and treating the absence of a handler record as proof
 * would turn every record lost to ring-buffer backpressure into a wrong fold.
 *
 * So the proof is kept here, where nothing is lossy, in one word per task
 * (restart_pending_map, maps.h):
 *
 *   1. ior_restart_on_exit: a syscall exit that is EMITTED with -512, -513,
 *      -514 or -516 makes the task pending.
 *   2. handle_signal_deliver: the first user handler delivered to a pending
 *      task decides by the kernel's rules. If the program gets EINTR the task
 *      is forgotten; otherwise the restart is merely postponed and the handler
 *      nesting depth is counted (depth 1).
 *   3. handle_restart_sigreturn: every rt_sigreturn of the task closes one
 *      handler.
 *   4. ior_restart_on_enter: the first syscall enter of a pending task at
 *      depth 0 is the continuation - without a handler the task could not run
 *      a single user instruction in between, and after the last handler
 *      returned it resumes at the rewound syscall instruction. The hook emits a
 *      RESTART_PHASE_RESUME control record right before that enter's own
 *      record, and forgets the task.
 *
 * Userspace folds only on that RESUME record followed by the enter it
 * announces and that enter's exit. The HANDLER record emitted at step 2 is not
 * part of the proof; it tells userspace to keep the interrupted row while the
 * handler's own syscalls pass (and lets it release the row at once when the
 * program got EINTR).
 *
 * For -516 the four steps are the same and shorter. No handler lets the call
 * survive (step 2 always forgets the task), so a -516 entry never has a depth,
 * and step 4 fires only where the kernel set restart_syscall up: that enter
 * is the task's first one. The hook does not know which syscall it runs for,
 * so RESUME is emitted for whatever traced enter comes first, and userspace
 * takes it for the continuation only when it is a restart_syscall enter with
 * the RESUME record's time. When restart_syscall is not traced, the entry
 * waits for the task's next traced enter, whose RESUME releases the row.
 * What the record adds over the stream: a restart_syscall enter that no
 * RESUME announced - the one of a later, silent call - is not a continuation
 * of anything userspace holds, whether or not the HANDLER record that should
 * have released the row arrived (lost, or the entry evicted by a colliding
 * tid), and whether or not the row's own restart_syscall was sampled out.
 *
 * RESUME names its enter by time. The record is emitted before the enter
 * hook's sampling decision and before the handler reserves the enter's own
 * record, so the announced enter may never reach userspace: at a 1-in-N rate
 * it is sampled out N-1 times out of N, and a full ring buffer can refuse it.
 * What userspace then sees after RESUME is the task's NEXT call of that
 * syscall, whenever it comes. So ior_restart_on_enter stamps RESUME with the
 * handler's `now`, the value the handler also writes to the enter's ev->time
 * (every generated handler reads the clock once, see "The per-syscall hooks"
 * in filter.c), and userspace takes an enter for the announced one only when
 * it carries exactly that time (isAnnouncedEnter in
 * internal/eventloop_restart.go). The equal timestamps are part of the
 * record's contract, not a coincidence: stamp RESUME from another clock read
 * and nothing is folded any more.
 *
 * Emitting RESUME only for an enter that is emitted, or carrying the
 * interrupted call's sampling decision over to the re-execution, were the
 * alternatives. Both move the restart check behind or into the sampling
 * verdict on the enter path that every traced syscall pays, the second also
 * emits rows the configured rate did not select, and neither helps when the
 * ring buffer refuses the enter after RESUME went out - the time rule is
 * needed in any case, and it is sufficient, so it is the whole mechanism. The
 * price: at a rate above 1 a re-execution folds only when both of its halves
 * happen to be sampled in; otherwise the interrupted row keeps its restart
 * code.
 *
 * Lost records. The state in restart_pending_map is not lossy (userspace
 * clears it at a runtime probe change, see below, and nothing else takes an
 * entry away); the records are. A lost RESUME means no fold. A lost HANDLER makes the handler's first
 * syscall release the row (for -516: whatever record of the task comes next;
 * no RESUME follows, the task was forgotten when the handler was delivered).
 * A lost announced enter is caught by the time rule.
 * What neither catches is a loss that leaves a well-formed stream behind: the
 * re-executed exit and the next call's enter lost together (that call's exit
 * then looks like the continuation's), or the lost exit of a call interrupted
 * inside the handler (the entry here moves on to the inner call while
 * userspace still holds the outer row). For those userspace folds only when
 * it can prove that the ring-buffer drop counter has not moved since the
 * interrupted exit (restartDropWatch: the periodic drop monitor tells it
 * since when the counter has stood at its value, and it reads the counter
 * again at RESUME and at the folding exit), and keeps the fold off altogether
 * when it cannot read that counter. With that, a lost record fails towards
 * "not folded", and a fold refused after the re-executed enter was already
 * taken for it still leaves two rows, the interrupted one and the
 * re-execution; the remaining assumption is the one all of ior's record-time
 * comparisons make, that ior does not run in a time namespace with a boottime
 * offset.
 *
 * Runtime probe changes (task o03). Step 4 takes the task's first traced
 * enter for the continuation, which is true only while the continuation's own
 * enter tracepoint is attached when the kernel runs it. The TUI's probes modal
 * detaches and attaches syscall pairs while ior runs: a read that exits -512,
 * has read's probes switched off and is re-executed unseen leaves its entry
 * standing, and once the probes are on again the task's next read - a call
 * the program made itself - was announced and folded into the interrupted
 * row. The programs here cannot know that a tracepoint was off in between,
 * so userspace deals with it, whenever the probe manager attaches or detaches
 * a syscall pair at runtime (internal/eventloop_restart.go, "Runtime probe
 * changes"): it writes 0 to every slot of restart_pending_map
 * (internal/restart_pending_map.go) - after a detach has destroyed its links,
 * before an attach attaches any - and from then on folds nothing into a row
 * whose interrupted exit is not younger than that moment. Either would do for
 * the case above; the clear keeps a stale RESUME from being emitted at all,
 * and the time rule covers what the clear cannot: it races with the programs
 * on other CPUs, and a signal delivery or rt_sigreturn that read a slot before
 * the clear and writes its changed word back afterwards
 * (ior_restart_on_handler, ior_restart_on_sigreturn) keeps that one entry
 * alive. The clear also takes the entries of calls no probe change touched;
 * their rows are the ones userspace has just refused to fold, so nothing more
 * is lost by it. A slot stored after the clear belongs to a call interrupted
 * after it and is as good as any.
 *
 * Cost. The enter hook pays an inlined array lookup, one load and one compare
 * per traced syscall; the exit hook pays one range check of ret. Everything
 * else runs only for a task with an interrupted call. signal_deliver fires
 * for every delivered signal on the host and returns after the same lookup
 * and compare unless the task is pending; the extra rt_sigreturn program
 * likewise.
 *
 * Known limits: not folded although the kernel re-executed the call.
 *   - A handler that leaves through siglongjmp never closes its depth; the
 *     call is not folded (it was not re-executed either).
 *   - Two pending tasks whose tids collide in the map: the earlier is evicted.
 *   - A syscall interrupted inside a handler replaces the outer pending call.
 *   - A handler delivered in a later pass of the kernel's exit loop, after an
 *     earlier pass found no handler and already set the restart up, does not
 *     change the kernel's decision, but is judged here like a first handler:
 *     without SA_RESTART (or for -514 and -516) the restarted call is not
 *     announced. For -516 the restart_syscall that then follows the handler
 *     is a row of its own.
 *   - A -516 call whose restart_syscall is not traced, or is detached, has
 *     nothing to fold with.
 *   - A call that was interrupted before a syscall's probes - any syscall's -
 *     were last attached or detached at runtime (see "Runtime probe changes"
 *     above): its entry is cleared and userspace refuses the fold, also when
 *     the change had nothing to do with it. A family toggle changes one pair
 *     after the other, so for as long as it runs nothing is folded.
 *   - The re-executed call's enter or exit is sampled out or lost, or any
 *     record at all was dropped host-wide while the row was held (above).
 *   - The 32-bit sigreturn of compat tasks is not seen; syscall tracepoints
 *     do not fire for compat syscalls either, so such tasks are never pending.
 *
 * Known wrong folds. There are two kinds.
 *
 * Stale entries: RESUME is wrong. These need two things at once. First, the
 * entry stands at depth 0 although the kernel is not about to re-execute the
 * call: it outlived the re-execution, or there never was one. Second, the
 * first syscall enter of the task that ior traces after that is an enter of
 * the very syscall that was interrupted (the same tracepoint: a read for a
 * read, not a pread64; for a -516 entry, restart_syscall, i.e. a later call
 * of the task that was stopped in turn and is itself not recorded), and its
 * exit is recorded. RESUME then names a real enter of the right syscall, so
 * the time rule cannot object. Any other traced syscall the task makes first
 * takes the RESUME instead, and userspace releases the row. The ways an entry
 * gets into that state:
 *   - A restarting handler rewrites the saved user context so that its
 *     rt_sigreturn resumes somewhere else (a preemptive user-level thread
 *     switch).
 *   - A call is interrupted inside handler A and restarted through a nested
 *     handler B that siglongjmps back into A; A's own rt_sigreturn then
 *     closes B's depth, and the interrupted code runs on.
 *   - A handler that the signal_deliver probe does not see cuts a -516 call
 *     and leaves by siglongjmp (an rt_sigreturn would forget the task, see
 *     ior_restart_on_sigreturn). Userspace therefore holds -516 rows only
 *     when that probe attached, like the rows of the other codes.
 *   - A ptrace tracer rewrites the registers of the interrupted call so that
 *     the kernel neither restarts it nor runs a handler: at the
 *     signal-delivery stop (a gdb inferior call sets orig_ax to -1 and
 *     suppresses the signal, and the called function's first traced syscall
 *     is announced), or at the interrupted call's syscall-exit stop, which
 *     comes after the sys_exit tracepoint this file judges by (a tracer that
 *     replaces the restart code in the return register there).
 *   - Something takes the re-executed call away before its sys_enter
 *     tracepoint fires, so the re-execution has no enter here and the entry
 *     stays: a ptrace tracer that, at the re-execution's syscall-entry stop,
 *     cancels the call or turns it into a syscall ior does not trace (the
 *     stop comes before the tracepoint, and the per-syscall tracepoint goes
 *     by the number the tracer left: strace's --inject error= and retval=
 *     replace it with -1; a number changed to another traced syscall takes
 *     the RESUME and releases the row instead); a seccomp user-notification
 *     supervisor that let the first attempt through and answers the second
 *     itself (or a filter installed in between); or syscall user dispatch
 *     switched on in between (its SIGSYS handler is then also judged as if it
 *     had interrupted the call).
 *   - A kernel or driver bug lets -ERESTARTSYS escape with no signal pending:
 *     nothing restarts, the program sees errno 512 and carries on.
 *
 * A time rule that cannot tell: RESUME is right. Here the kernel did
 * re-execute the call and the entry was cleared when it should be, but the
 * enter RESUME announced was sampled out, and the time rule that keeps the
 * task's next call of that syscall out of the row has nothing to go by:
 *   - A clocksource too coarse to give two enters of one task different
 *     readings (jiffies) weakens the rule to "same syscall, same tick". A
 *     later call of the interrupted syscall that the task enters within the
 *     tick of the sampled-out re-execution, is sampled in and has its exit
 *     recorded is then folded in its place.
 *
 * No longer among them: the syscall's probes (for -516: restart_syscall's)
 * detached in the TUI between the interrupted exit and the continuation and
 * attached again later, so that the entry outlived the continuation it stood
 * for (task o03, "Runtime probe changes" above; an exit handler still running
 * on another CPU when the detach returns can store an entry a few
 * microseconds younger than the detach, which cannot announce that syscall
 * while its probes are off and is cleared, its row refused, before they are
 * attached again); a -516 call cut by a handled signal whose handler is
 * silent, followed by a silent stopped call (task t13, see the top of this
 * comment; the stream-only fold took that call's restart_syscall for the
 * continuation); a recycled tid inheriting the entry of a task that died
 * pending (ior_restart_forget drops it in sched_process_exit, and userspace
 * folds only when that probe attached); the sampled-out and
 * lost-record cases described above; and a call interrupted inside a
 * restarting handler whose interrupted exit pairs with nothing in userspace
 * (its enter was filtered out or lost) - the exit replaces the entry here,
 * and in userspace that exit record itself now releases the row the handler
 * was running for (stepHandlerRecord).
 *
 * Old kernels: the probes use only an ARRAY map, scalar context loads through
 * a CO-RE flavor (the pattern handle_task_newtask uses, see exec.c) and the
 * ring buffer the object needs anyway. Task t13 added no map, helper or
 * context access: the exit hook's pending test became ior_is_restart_ret,
 * four compares on a scalar. Verified by loading on the 7.2 development host
 * only; the RHEL/Rocky 8 and 9 verifiers were not run.
 */

// IOR_RESTART_SLOTS must equal restart_pending_map's max_entries and be a
// power of two: the slot index is the tid's low bits.
#define IOR_RESTART_SLOTS 4096

// Layout of a restart_pending_map word (ior_restart_entry). 0 is a free slot:
// no task has tid 0 and a live entry always carries a non-zero code.
//   bits  0-31  tid of the pending task
//   bits 32-34  code: 1, 2, 3, 5 for -512, -513, -514, -516 (ior_restart_code)
//   bit  35     decided: a handler was delivered and the call still restarts
//   bits 40-47  depth: user handlers delivered and not yet returned
#define IOR_RESTART_CODE_SHIFT 32
#define IOR_RESTART_CODE_MASK 0x7ULL
#define IOR_RESTART_DECIDED (1ULL << 35)
#define IOR_RESTART_DEPTH_SHIFT 40
#define IOR_RESTART_DEPTH_MASK 0xFFULL
#define IOR_RESTART_DEPTH_ONE (1ULL << IOR_RESTART_DEPTH_SHIFT)

// SA_RESTART (include/uapi/asm-generic/signal-defs.h, the same value on x86
// and arm64) and the two sa_handler values that run no user handler, SIG_DFL
// (0) and SIG_IGN (1). vmlinux.h carries no such macros.
#define IOR_SA_RESTART 0x10000000UL
#define IOR_SIG_IGN 1UL

static __always_inline __u64 *ior_restart_slot(__u32 tid) {
    __u32 idx = tid & (IOR_RESTART_SLOTS - 1);

    return bpf_map_lookup_elem(&restart_pending_map, &idx);
}

static __always_inline __u32 ior_restart_code(__u64 entry) {
    return (__u32)((entry >> IOR_RESTART_CODE_SHIFT) & IOR_RESTART_CODE_MASK) + IOR_ERESTARTSYS - 1;
}

static __always_inline __u32 ior_restart_depth(__u64 entry) {
    return (__u32)((entry >> IOR_RESTART_DEPTH_SHIFT) & IOR_RESTART_DEPTH_MASK);
}

// ior_restart_entry is the word of a task that has just exited with -code
// (512, 513, 514 or 516): pending, no handler seen yet.
static __always_inline __u64 ior_restart_entry(__u32 tid, __u32 code) {
    return (__u64)tid | ((__u64)(code - IOR_ERESTARTSYS + 1) << IOR_RESTART_CODE_SHIFT);
}

// ior_restart_emit publishes one syscall_restart_event for the current task,
// stamped with now: for RESUME the caller's enter timestamp, which is how the
// record names its enter (see "RESUME names its enter by time" above). A
// record the ring buffer cannot take is counted like every other lost record;
// the state in restart_pending_map advances regardless, so a lost HANDLER or
// RESUME record can only make userspace fold less, never wrongly.
static __always_inline void ior_restart_emit(__u32 tid, __u64 now, __u32 phase, __u32 sa_restart) {
    struct syscall_restart_event *ev;

    ev = bpf_ringbuf_reserve(&event_map, sizeof(struct syscall_restart_event), 0);
    if (!ev) {
        ior_count_ringbuf_drop();
        return;
    }

    ev->event_type = SYSCALL_RESTART_EVENT;
    // Not a syscall tracepoint event: there is no enter/exit trace id.
    ev->trace_id = 0;
    ev->time = now;
    ev->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    ev->tid = tid;
    ev->phase = phase;
    ev->sa_restart = sa_restart;

    bpf_ringbuf_submit(ev, 0);
}

// ior_restart_on_exit is called by the syscall exit hook with the hook's
// verdict (emits) and returns it unchanged. An emitted exit with a restart
// code (-512, -513, -514, -516; ior_is_restart_ret in filter.c) makes the
// task pending, replacing whatever the slot held. Every other exit in the
// range - a restart code on an exit that is not emitted (userspace holds no
// row to fold into), and -515, which is ENOIOCTLCMD and no restart code -
// drops a leftover entry of this task instead, so a stale one can never vouch
// for a later call. restart_syscall's own exit comes through here like any
// other: resumed and stopped again it carries -516 and makes the task pending
// for the next hop.
//
// Hot path: ret outside [-516, -512], i.e. practically every exit, costs the
// two compares of the first line.
static __always_inline int ior_restart_on_exit(__u32 tid, __s64 ret, int emits) {
    __u64 *slot;

    if (ret > -IOR_ERESTARTSYS || ret < -IOR_ERESTART_RESTARTBLOCK)
        return emits;
    slot = ior_restart_slot(tid);
    if (!slot)
        return emits;
    if (emits && ior_is_restart_ret(ret))
        *slot = ior_restart_entry(tid, (__u32)-ret);
    else if ((__u32)*slot == tid)
        *slot = 0;
    return emits;
}

// ior_restart_on_enter is called by the syscall enter hooks for every traced
// enter of an in-scope task, before the sampling decision. For a pending task
// with no handler open, this enter is the kernel's continuation of the
// interrupted call - its re-execution, or for -516 its restart_syscall (see
// the file comment): the RESUME record goes out ahead of the enter's own
// record, and the task is forgotten. An enter at depth > 0 is a syscall the
// signal handler makes and changes nothing.
//
// now must be the timestamp the calling handler writes to its enter record's
// ev->time. The enter may be sampled out or lost after RESUME is out, and the
// shared timestamp is the only thing that ties the two records together.
//
// Hot path: a task that is not pending returns after the slot compare.
static __always_inline void ior_restart_on_enter(__u32 tid, __u64 now) {
    __u64 *slot = ior_restart_slot(tid);
    __u64 entry;

    if (!slot)
        return;
    entry = *slot;
    if ((__u32)entry != tid)
        return;
    if (ior_restart_depth(entry))
        return;
    *slot = 0;
    ior_restart_emit(tid, now, RESTART_PHASE_RESUME, 0);
}

// ior_restart_survives_handler is the kernel's handle_signal rule for a call
// that exited with -code when a user handler runs: -ERESTARTNOINTR is always
// restarted, -ERESTARTSYS only under SA_RESTART, -ERESTARTNOHAND and
// -ERESTART_RESTARTBLOCK never (the program gets EINTR; handle_signal lists
// the two in one case). internal/eventloop_restart.go restates the rule
// (restartSurvivesHandler) for the HANDLER record.
static __always_inline int ior_restart_survives_handler(__u32 code, __u32 sa_restart) {
    if (code == IOR_ERESTARTNOINTR)
        return 1;
    return code == IOR_ERESTARTSYS && sa_restart;
}

// ior_restart_on_handler applies one delivered user handler to the pending
// task that owns slot. The first handler decides the interrupted call: the
// kernel rewrites the return value once, in the handle_signal of that first
// delivery, and later deliveries find no restart code any more. It is
// reported to userspace either way. Every later handler - nested, or
// delivered after the previous one returned but before the re-execution - only
// postpones the restart, so it only opens one more depth level. A task nested
// deeper than the counter holds is forgotten rather than miscounted.
static __always_inline void ior_restart_on_handler(__u64 *slot, __u64 entry, __u32 tid, __u32 sa_restart) {
    if (entry & IOR_RESTART_DECIDED) {
        if (ior_restart_depth(entry) == IOR_RESTART_DEPTH_MASK)
            *slot = 0;
        else
            *slot = entry + IOR_RESTART_DEPTH_ONE;
        return;
    }
    if (ior_restart_survives_handler(ior_restart_code(entry), sa_restart))
        *slot = entry | IOR_RESTART_DECIDED | IOR_RESTART_DEPTH_ONE;
    else
        *slot = 0;
    ior_restart_emit(tid, bpf_ktime_get_boot_ns(), RESTART_PHASE_HANDLER, sa_restart);
}

// ior_restart_forget drops the pending state of a task that is exiting, so a
// later task with the recycled tid does not inherit it.
static __always_inline void ior_restart_forget(__u32 tid) {
    __u64 *slot = ior_restart_slot(tid);

    if (slot && (__u32)*slot == tid)
        *slot = 0;
}

// ior_restart_on_deliver applies one signal the task tid dequeued, with the
// action the kernel is about to take: sa_handler is SIG_DFL (0), SIG_IGN (1)
// or the address of the user handler get_signal() returns to have run. Only a
// user handler matters; after a default or ignored action the kernel keeps
// dequeuing, and when nothing with a handler turns up the interrupted call is
// restarted, which the enter hook reports.
//
// Hot path: signal_deliver fires for every signal delivered on the host; a
// task that is not pending returns after the slot compare.
static __always_inline void ior_restart_on_deliver(__u32 tid, __u64 sa_handler, __u64 sa_flags) {
    __u64 *slot = ior_restart_slot(tid);
    __u64 entry;

    if (!slot)
        return;
    entry = *slot;
    if ((__u32)entry != tid)
        return;
    if (sa_handler <= IOR_SIG_IGN)
        return;
    ior_restart_on_handler(slot, entry, tid, (sa_flags & IOR_SA_RESTART) ? 1 : 0);
}

// ior_restart_on_sigreturn closes one user handler of the task tid. A pending
// task with no handler open cannot reach rt_sigreturn before its re-execution
// (it has not run in user mode since the interrupted exit), so that
// combination means the bookkeeping lost track and the task is forgotten.
static __always_inline void ior_restart_on_sigreturn(__u32 tid) {
    __u64 *slot = ior_restart_slot(tid);
    __u64 entry;

    if (!slot)
        return;
    entry = *slot;
    if ((__u32)entry != tid)
        return;
    if (!ior_restart_depth(entry))
        *slot = 0;
    else
        *slot = entry - IOR_RESTART_DEPTH_ONE;
}

// trace_event_raw_signal_deliver___ior is a CO-RE "flavor" of the kernel's
// struct trace_event_raw_signal_deliver, reduced to the two scalars this
// program reads; libbpf matches it by name (the ___ior suffix is ignored) and
// relocates the offsets from the running kernel's BTF. Same reasoning as
// trace_event_raw_task_newtask___ior in exec.c: the build must not depend on
// the build host's vmlinux.h carrying the struct, and scalar context loads at
// relocated constant offsets are what the 4.18 and 5.14 verifiers accept.
struct trace_event_raw_signal_deliver___ior {
    unsigned long sa_handler;
    unsigned long sa_flags;
} __attribute__((preserve_access_index));

// signal:signal_deliver fires in get_signal(), in the context of the task
// that dequeues the signal. The scope filter is implied: only an emitted exit
// of an in-scope task makes a task pending, and ior_restart_on_deliver
// returns for every other task.
SEC("tracepoint/signal/signal_deliver")
int handle_signal_deliver(void *raw_ctx) {
    struct trace_event_raw_signal_deliver___ior *ctx = raw_ctx;
    // Both scalars are read first, straight off the context register: the
    // only shape of context access the old verifiers accept once CO-RE has
    // patched the offsets (see handle_task_newtask in exec.c).
    __u64 sa_handler = ctx->sa_handler;
    __u64 sa_flags = ctx->sa_flags;

    ior_restart_on_deliver((__u32)bpf_get_current_pid_tgid(), sa_handler, sa_flags);
    return 0;
}

// A second program on sys_enter_rt_sigreturn, next to the generated
// handle_sys_enter_rt_sigreturn: that one only exists to report the syscall
// and is attached only when rt_sigreturn is selected for tracing, while the
// handler depth has to be counted in every session. The two do not share
// state, so their relative order on the tracepoint does not matter.
SEC("tracepoint/syscalls/sys_enter_rt_sigreturn")
int handle_restart_sigreturn(void *ctx) {
    ior_restart_on_sigreturn((__u32)bpf_get_current_pid_tgid());
    return 0;
}
