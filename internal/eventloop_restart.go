package internal

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"sync"
	"sync/atomic"

	"ior/internal/event"
	"ior/internal/types"
)

// Folding a kernel-restarted call into one row (tasks fs2, 103 and t13).
//
// A signal that interrupts a blocked syscall makes it exit with a
// kernel-internal restart code, and the kernel may then carry the call on
// without the program ever learning it was interrupted. ior used to show such
// a call as two or more rows; here the pieces are folded back into the one
// call the program made. There are two ways the kernel carries a call on.
// Each has its own continuation, and both are folded only on a proof BPF
// keeps (internal/c/restart.c).
//
// (1) restart_syscall, for -ERESTART_RESTARTBLOCK (-516; tasks fs2 and t13).
// A blocked nanosleep, clock_nanosleep, poll or timed futex wait exits with
// -516. When no handler runs (SIGSTOP/SIGCONT, a ptrace or freezer stop), the
// kernel does not re-execute the call: it re-enters the task through
// restart_syscall, which finishes the same call from the restart block (for a
// relative sleep, against the original absolute expiry). When a handler runs,
// the program gets EINTR and nothing resumes the call (x86 handle_signal
// treats -516 like -514).
//
// restart_syscall can only resume a -516, so this fold used to go by the
// syscall stream alone: a -516 row whose tid's very next record is a
// restart_syscall enter. That is a proof only while the next record that
// ARRIVES is the next thing the thread did, and after a handled signal it need
// not be (task t13). The records that would release the row - the handler's
// syscalls, its rt_sigreturn - are silent when rt_sigreturn is outside the
// trace set, sampled out, aggregate-only or detached, or when the handler
// leaves by siglongjmp. A later call of the thread that is silent too and gets
// stopped then has its restart_syscall arrive right behind the -516 exit, and
// it was folded into a call that had returned EINTR long before, with no
// record lost and nothing sampled.
//
// So this fold takes BPF's proof as well (internal/c/restart.c). An emitted
// -516 exit makes the task pending there; a user handler delivered to it
// forgets the task and is reported (HANDLER: the row is released at once, the
// call got EINTR); and the first syscall enter of a task still pending - the
// restart_syscall the kernel set up - is preceded by a RESUME record stamped
// with that enter's time. A -516 row is resumed only by a restart_syscall
// enter that RESUME announced (isAnnouncedEnter); one that comes unannounced
// is some other call's and releases the row. Nothing is concluded from a
// record that is absent: a HANDLER record that never arrived (lost to
// backpressure, or the task's BPF entry evicted by a colliding tid before the
// signal) leaves the row waiting, and then no RESUME comes for it either.
//
// Without the probes. RESUME is a proof only while BPF sees every handler
// delivered to a pending task (the signal_deliver probe: a handler it misses
// that leaves by siglongjmp would leave the task pending, and the next
// restart_syscall of the thread would be announced) and forgets a task that
// dies pending (the sched_process_exit probe). When either did not attach,
// -516 rows are not held at all (foldProvenRestarts, restartBlock): a stopped
// sleep is then the two rows it was before task fs2, the -516 row and a
// restart_syscall row. The same holds, with the probes attached, for an
// IOR_BPF_OBJECT override that predates task t13: it never announces a
// restart_syscall, so the held row is released by the tid's next record. The
// fold ran without any probe until then, so this takes it away from such runs
// on purpose. The alternatives were to keep the stream-only fold there, which
// keeps the wrong row this is about, or to hold -516 rows only while
// rt_sigreturn is traced at rate 1, so that a returning handler always leaves
// a record: that still folds a stranger after a handler that siglongjmps, and
// it makes a stopped sleep fold or not depending on whether rt_sigreturn is in
// the trace set. A run without the probes is rare - an object override older
// than the probes, or a kernel that refuses the attach, each with a startup
// warning - and two correct rows are what every refused fold degrades to.
//
// A full ring buffer can still take records out of the stream between a hold
// and its fold; the drop counter says whether that happened ("Lost records"
// below).
//
// (2) Re-execution, for -ERESTARTSYS, -ERESTARTNOINTR and -ERESTARTNOHAND
// (-512/-513/-514; task 103). The kernel rewinds the instruction pointer and
// the task issues the very same syscall again - but a sys_enter of the same
// syscall is also what a program that got EINTR and retried by itself
// produces (the Go runtime and many C loops do exactly that), and that retry
// is a call of its own. The syscall stream cannot tell the two apart, so the
// proof comes from BPF (internal/c/restart.c): it applies the kernel's
// handle_signal rules to the handlers signal:signal_deliver reports (-513 is
// always restarted, -512 when no handler runs or the handler has SA_RESTART,
// -514 only when no handler runs), follows a restarting handler to its
// rt_sigreturn, and emits a RESUME control record immediately before the
// enter that is the re-execution. That record is the only thing that
// licenses a fold here; without it (the probe did not attach, the record was
// lost to ring-buffer backpressure, the program got EINTR) the row stays as
// it was. Such rows are held only when BPF's proof is complete for the run
// (foldProvenRestarts): the two probes above, and a drop counter.
//
// RESUME names its enter by time, for both folds. BPF emits RESUME before it
// knows whether the enter itself will be recorded: the enter may be sampled
// out (1-in-N sampling suppresses it with probability (N-1)/N) or lost to a
// full ring buffer. Both records are stamped with the handler's one clock
// read, so the fold takes only an enter whose time equals the RESUME record's
// (heldRestart.resumeTime); a later call of the same syscall - a later stopped
// call's restart_syscall, for a -516 row - which is what follows RESUME when
// the continuation went unrecorded, has a later time and releases the row.
// BPF does not know which syscall an enter belongs to, so RESUME precedes the
// task's first traced enter whatever it is; the enter must also be the
// continuation's syscall (continuationEnterID), which after -516 it is
// whenever restart_syscall is traced. Carrying the interrupted call's sampling decision over to
// the re-execution in BPF instead would fold more calls at rates above 1, but
// it would put a second verdict on the enter hot path, emit rows the
// configured rate did not select, and still not cover an enter the ring
// buffer refused - the time check is needed either way, so it is the whole
// mechanism.
//
// Lost records. A fold also requires proof that the kernel dropped no record
// since the interrupted exit (restartDropWatch): with records missing, the
// stream between hold and fold is no longer the one the rules below reason
// about (the re-executed exit and the next call's enter lost together would
// let that call's exit complete the fold; a lost exit of a call interrupted
// inside the handler leaves BPF tracking the inner call while the outer row is
// still held here). The restart_syscall fold has the same hole (task p03):
// what it reasons about is the records that ARRIVED. When a stopped sleep's
// restart_syscall exit is lost together with the thread's records up to a
// later stopped call's restart_syscall enter (that call's enter, its -516
// exit, its RESUME and the enter), the kept enter is followed by an exit that
// resumes another call, and its return value and end time would be written
// into the row; with the first restart_syscall lost whole, RESUME included,
// the later call's RESUME and enter arrive in its place. The check is
// host-wide, so under ring-buffer backpressure nothing is folded - the
// direction every doubt is resolved in. A refused fold costs no row: the call
// shows as it did before it was folded at all, the interrupted row and the
// continuation's row.
//
// The two folds differ in what they do WITHOUT a drop counter (the counter
// map could not be opened, or an object override without it; ior warns at
// startup). The re-execution fold is then off altogether
// (foldProvenRestarts): it never ran unchecked. The restart_syscall fold
// predates the counter and keeps folding, on RESUME alone (restartProofLost):
// refusing would turn every stopped sleep of such a run back into two rows,
// in order to avoid a wrong row that needs a burst of five consecutive lost
// records of one stopped-and-stopped-again thread that ends exactly inside
// the later call's restart_syscall (the two shapes above) - in a run that
// cannot report any of its losses in the first place. The later call must
// itself be recorded for that: BPF announces a restart_syscall only after an
// emitted -516 exit, so the restart_syscall of a call that is not traced or
// was sampled out comes unannounced and releases the row (before task t13 two
// lost records were enough there). That is the residual, pinned by
// TestRestartSyscallFoldWithoutADropCounterIsUnchecked. A counter that exists
// but cannot be read is not that case: it refuses both folds.
//
// Sampling (task s13). A sampled-out record is not a lost one: BPF never
// reserves it, the drop counter does not move, and the check above cannot see
// it. restart_syscall is a traced syscall like any other. It has no built-in
// rate, so by default every one is emitted, but
// -syscall-sampling-syscalls restart_syscall=N or its family's rate
// (-syscall-sampling-families Process=N) samples it, per invocation, enter
// and exit together (ior_on_syscall_enter_impl in internal/c/filter.c). The
// stream-only fold then took a stranger with no record lost: a stopped call
// is recorded and held, its restart_syscall is sampled out, the thread's next
// stopped call emits nothing (sampled out, aggregate-only like a timed futex
// wait at the TUI's default rate 0, or not traced), and that call's
// restart_syscall is sampled in.
//
// So a run whose restart_syscall is not at rate 1 holds no -516 row
// (restartTracker.restartSyscallSampled, holdable). The rows of such a run
// are the unfolded ones: the -516 row at once, and restart_syscall as a row
// of its own whenever it is sampled in. Rate 0 is refused with the rest; no
// restart_syscall is emitted there, so there was nothing to fold. The rate is
// the effective one BPF applies (default < family < syscall, a family's 0
// promoted to 1 in the raw output modes), in every output mode.
//
// Since task t13 the guard is no longer what keeps the stranger out. RESUME
// is emitted before the sampling decision and names its enter by time, so a
// sampled-out restart_syscall leaves a RESUME whose time no later enter
// carries, and the later call's restart_syscall releases the row
// (TestSampledOutRestartSyscallIsNotFoldedWithoutTheGuard) - exactly how the
// re-execution fold has always dealt with a sampled-out re-execution. The
// guard is kept on top of that: it costs the folds a sampled run could make
// when both halves of a restart_syscall happen to be sampled in, which such a
// run never made, and it leaves the one case the time rule cannot tell (a
// clocksource too coarse to give two enters of a thread different readings,
// see restart.c) to the re-execution fold alone. The interrupted syscall's
// own rate needs no guard under either rule: a sampled-out interrupted call
// holds no row and is not pending in BPF (ior_restart_on_exit takes emitted
// exits only), so its restart_syscall is a row of its own.
//
// Runtime probe changes (task o03). BPF takes a task's first traced enter
// after an interrupted exit for the continuation, and that holds only while
// the continuation's own enter tracepoint is attached when the kernel runs it.
// The TUI's probes modal detaches and attaches syscall pairs while the loop
// runs. A read that exits -512, has its probes switched off, is re-executed
// unseen and returns, leaves the task pending in BPF for as long as the probes
// stay off; switched on again, the task's next read - a call the program made
// itself, minutes later - is announced, enter and exit arrive in order, and it
// was folded into the row still held here. The same went for a -516 row and
// the probes of restart_syscall.
//
// So the probe manager reports every runtime change of a syscall pair
// (probemanager.Manager.SetChangeHook, wired by watchProbeChanges): after a
// detach has destroyed its links, before an attach attaches anything and again
// when that attach is over, each time before the opposite change of that
// syscall can begin. On each report (probesChanged, on the goroutine that
// changed the probe):
//
//   - restart_pending_map is cleared (restartPendingMap.Clear), so no entry
//     made before the change announces anything after it;
//   - the boot clock is read, once before the clear and once after it, and
//     the later reading kept as the time of the latest change
//     (restartProbeWatch). From then on no row interrupted at or before that
//     time is folded or held: holdable refuses it, and a row already held is
//     released at the two steps that commit to a fold, RESUME and the
//     continuation's exit (restartAcrossProbeChange), exactly where a possible
//     lost record refuses it;
//   - the loop is woken (processRawEvents) and releases the rows it holds from
//     before the change, each as the row it was, the continuation's enter of a
//     row in restartContinuing parked again like on any release
//     (releaseRestartsBehindProbeChange). That is only promptness: such a row
//     can no longer fold, and without the wake it would wait for its tid's
//     next record, which a stopped task may not produce for a long time.
//
// The time rule is the one that carries the proof, because it does not depend
// on how far behind the ring buffer the loop is. A record of a stale entry -
// the RESUME ahead of the program's own call - is reserved after the probes
// were attached again, so after the detach's stamp was stored, and the loop
// reads the stamp when it processes that record: the row it would have folded
// was interrupted before the stamp, wherever the loop stood when the probes
// changed. A snapshot of "the rows held when the change was noticed" would not
// do: a loop still working through a backlog notices the change before it has
// even read the interrupted exit, holds the row afterwards, and folds. The
// clear of the map is the second line: with it the stale RESUME is not emitted
// in the first place, which also covers a record time and a userspace clock
// reading that cannot be compared (a time namespace with a boottime offset,
// see probesChanged).
//
// The rule is deliberately coarse. Any pair's change refuses every row
// interrupted before it, of any syscall and any task: a family toggle is a
// rare, manual act, the refused folds cost no row (the interrupted row and the
// continuation's row, as before the folds existed), and telling which rows a
// change of which syscall can have touched means knowing the attached set at
// every instant of the stream the loop has yet to read. The hand-attached
// probes (signal_deliver, sched_process_exit, the restart fold's rt_sigreturn
// program) are attached for the whole session and never report; the syscall
// probe of rt_sigreturn does, like any pair.
//
// Who listens. Only a run whose probe manager was published to a TUI
// (runTraceSetup, traceSetupHooks.probes): the probes modal is the one place
// probes change at runtime. A headless run installs no hook, takes no stamp
// and refuses nothing on this account. Installing the hook counts as a change
// itself (watchProbeChanges: stamp, clear, stamp and wake, like any report):
// the TUI is handed the probe manager before the loop exists, and a change it
// makes in between is reported to nobody.
//
// Why an attach reports as well, and twice.
//
// Before it attaches anything, because the detach's stamp can miss an entry.
// An exit handler that is still running on another CPU when the link's
// destruction returns makes its task pending with an exit stamped microseconds
// AFTER the detach's stamp and clear. (Whether that can happen is a question
// of whether the kernel waits for a grace period there; it may not while
// another perf event keeps the tracepoint registered, see
// perf_trace_event_unreg. That was not checked against the kernel's source,
// and the design does not depend on it: the report is made either way.) Its
// re-execution goes unseen like any other. While the probes are off that
// entry cannot announce a call of the same syscall, and the attach's first
// report clears it and stamps past its row before the enter tracepoint is
// back.
//
// After the attach, because the first report cannot stand for the attach
// itself: the two tracepoints are attached one after the other, enter first,
// and the first stamp is older than both. Take an attach of restart_syscall's
// probes. A traced poll is stopped and exits -516 after the first stamp - its
// row is held, its task pending - and is resumed before the enter tracepoint
// is attached: the restart_syscall goes unseen, nothing releases the row, and
// the entry stands. The thread's next recorded enter can then be the
// restart_syscall of a later stopped call whose own syscall is detached or
// outside the trace set, and it was announced and folded into the held row.
// (Seen at its enter and gone before the exit tracepoint is attached, the
// restart_syscall leaves the row with its enter taken instead, waiting for an
// exit that only a later call can deliver.) The second report's stamp is
// younger than that row and its clear takes the entry. A failed attach is
// reported twice all the same: it may have had the enter tracepoint attached
// for a moment, which is an attach and a detach in one - or, when that enter
// link could not be destroyed again, have left it attached for good: the
// enter-only (mirror) state described two paragraphs below.
//
// A detach that failed half-way and left the exit tracepoint attached, with
// the enter tracepoint gone, needs no report of its own while it lasts. A held
// call whose continuation is that syscall - a call of the syscall itself, or
// for restart_syscall a stopped call - is then continued unseen at its enter,
// and its task stays pending. But the continuation's exit is recorded, arrives
// as an exit of the tid that no RESUME announced, and releases the row (the
// Release rule below). The entry stays until the task's next traced enter,
// which cannot be one of that syscall, or until the probe is detached for
// good, which reports and clears it (an attach of a probe that still has a
// link is a no-op in the manager and reports nothing).
//
// The mirror state - the enter tracepoint left attached, the exit tracepoint
// gone - needs no report while it lasts either. The syscall emits no exit, so
// no call of it becomes pending and nothing of it is held. Only as
// restart_syscall can it be a continuation: its enter is announced and taken,
// its exit never arrives, and the row waits in restartContinuing until the
// tid's next record releases it or the next report does.
//
// What is left open. A report is made when the attach call has returned, not
// at the instant the kernel attaches, so the fresh pair produces records
// before the second stamp exists. A wrong fold through that gap needs the
// whole of the scenario above inside one attach: the first restart_syscall
// unseen before the enter tracepoint is attached, the later call's
// restart_syscall entered after that, its exit recorded once the exit
// tracepoint is attached, and the loop processing that exit before
// probesChanged has stored its first stamp - which it takes before the clear
// for that reason, so the race is against the return from the attach call and
// one clock reading. That is one thread stopped and continued twice within a
// single attach, and it is not closed: the loop would have to be told that a
// change is in flight (a begin and an end rather than points in time) and
// refuse every fold meanwhile.
//
// The decision rules (heldRestart.phase records where a held row stands):
//
//   - Hold (waiting): a pair whose exit carries -516 (a *types.RetEvent, in
//     a run whose probes make RESUME a proof and that does not sample
//     restart_syscall), or -512/-513/-514 when re-execution folding is on, is
//     parked here instead of being completed (tracepointExited). Its exit
//     handler, derived values and pair filter all wait for the outcome. At
//     most maxHeldRestarts rows are held; beyond that the row is completed at
//     once, unfolded. A row interrupted at or before the latest runtime probe
//     change is not held either ("Runtime probe changes" above).
//   - Handler: a HANDLER control record says a user handler runs for the
//     interrupted call. If the call survives it by the rules above
//     (restartSurvivesHandler, -513 and -512 with SA_RESTART; BPF applied the
//     same rule and will send RESUME only then), the row stays held while the
//     handler's own syscalls pass through as ordinary rows; otherwise (-514,
//     -516, -512 without SA_RESTART) the program gets EINTR and the row is
//     released at once. At most maxHandlerRecords records may pass (a handler
//     that leaves through siglongjmp never returns, and a lost RESUME must
//     not park the row for good).
//   - Resume: a RESUME control record announces the continuation - unless
//     records may have been lost since the interrupted exit, in which case it
//     releases the row - and the continuation's enter must be the tid's very
//     next record, stamped with the RESUME record's time: an enter of
//     restart_syscall for -516, of the same syscall for a re-execution. It is
//     taken out of the stream (no row, no raw enter filter: the decision must
//     not depend on what this run would show) and kept with the row
//     (heldRestart.continuation), not recycled: the fold can still be
//     refused, and then the continuation needs it to become a row. A
//     restart_syscall enter, or one of the same syscall, that no RESUME
//     announced releases the row and is an ordinary enter.
//   - Fold: the tid's next record is the continuation's exit, and no record
//     may have been lost since the interrupted exit (asked again: the enter
//     and the exit can be a long sleep apart). For -516 its return value
//     and time replace the held exit's (the exit keeps the original syscall's
//     trace ID); for re-execution the exit record itself replaces the held
//     one (it is the same syscall's exit, of whatever kind). The kept enter
//     is recycled now. A fold that ends in a restart code again is held
//     again, and its next hop asks about lost records from that exit on. A
//     name fixup the re-executed enter triggers is applied to the kept enter
//     and consumed.
//   - Release: any record of the held tid that is not the next step above
//     (any enter, another exit, a control record such as the task's exit, a
//     fresh task with the recycled tid, a restart record that does not fit
//     the phase) first completes the held row unchanged, then is processed
//     normally. So does a RESUME record or a
//     continuation's exit that arrives after the kernel may have dropped
//     records (see "Lost records" above) or for a row interrupted before the
//     syscall probes last changed, and an exit of the tid with a
//     restart code while its handler runs, paired or not: BPF tracks the
//     latest interrupted call of a task, so the row it could announce a
//     re-execution for is no longer this one (stepHandlerRecord). A paired
//     one is then held in the row's place (when there is room, holdRestart).
//     At the end of the run every held row is completed too
//     (releaseAllHeldRestarts), and at a runtime probe change every row
//     interrupted before it (releaseRestartsBehindProbeChange). No held row
//     is lost: it is either folded or emitted as it was.
//   - One release is not triggered by a record of the held tid, because there
//     is none: a non-leader thread that execs continues under the leader's
//     tid, gets no exit record under its old one, and is never heard of under
//     that tid again. Its exec record names the old tid (OldTid), and that
//     releases the row held there (releaseExecCallerRestart) - the execve
//     itself when it was interrupted with -513 and re-executed, or the call
//     whose restarting handler exec'd instead of returning. When the exec
//     record is lost, the successful execve's exit under the leader tid is
//     what is left, and it releases the same row (adoptLostExecCaller, which
//     finds a re-executed execve by reexecutingExecCaller; task r13).
//   - A release never costs the continuation its row either. When the
//     continuation's enter was already taken (restartContinuing), the release
//     parks it again as the tid's pending enter, through the path every enter
//     takes (syscallEntered: comm seeding, the raw enter filter, the exec
//     snapshot), after the held row is completed and before the releasing
//     record is processed. A refused or interrupted fold is therefore exactly
//     the two rows ior showed before it folded anything: the releasing record
//     finds the stream as if the fold had never been attempted, and the
//     continuation's exit - the releasing record itself when the fold was
//     refused over lost records, or a later one - pairs with its own enter,
//     runs its exit handler (fd tracking for an accept or an open) and is
//     counted.
//   - Except when the releasing record says the task is gone (reportsTaskGone,
//     task r13): its sched_process_exit record, or a task_newtask record that
//     hands the tid to a new task. The continuation's call was cut short and
//     never returns, so its enter is recycled instead of parked - what
//     handleProcessExitEvent does with any enter of a task that died inside a
//     syscall. Parked, it was a dead task's enter under a tid that is free or
//     already someone else's.
//
// How the folded row looks: the original enter (name, arguments, requested
// sleep, enter time, gap to the previous row) with the final return value
// and exit time. Its latency is the whole wall-clock span from the
// interrupted enter to the final exit, stopped time and handler time
// included: that is how long the program was inside the call ("asked to
// sleep 2s, the call took 2.0s"), and a relative sleep resumed by
// restart_syscall still ends at the original deadline, so a short stop does
// not lengthen it at all. The sum of the separate pieces would hide the stop
// and is not a time the kernel or the program knows. The restart code is
// gone from the folded row (ret is what the call finally returned); a row
// still showing one was not provably continued: the program got EINTR, the
// proof was lost or unavailable, the continuation was sampled out (or, for
// -516, restart_syscall is sampled at all or not traced), or the trace ended
// first.
//
// Counting: numSyscalls counts the call once (at its first exit; the
// continuation's exit is not counted again), the pair filter and every
// consumer (stats engine, Parquet, CSV, flamegraph) see one row. Kernel-side
// aggregates (aggregate-only syscalls, sampled-out invocations) are counted
// by BPF per invocation and are not folded.
//
// Output order: rows are emitted when the call completes, as always. A held
// row is delayed until its tid's next record; for a folded call that is its
// real completion, and for a row released unchanged (the handled-signal
// case) it is the HANDLER record, emitted as the handler is delivered,
// typically microseconds later. Rows of other tids emitted meanwhile may therefore
// precede it although they exited later, and so do the rows of a restarting
// handler's own syscalls: they complete before the call they interrupted.
// Those rows measure their gap from the interrupted exit, and the folded row
// keeps the gap it had at its first enter (heldRestart.gapBase).
//
// One held row has no such bound: a -516 row that no handler ends, in a run
// where restart_syscall emits nothing because it is outside the attached
// trace set (-trace-syscalls without it, or its probes switched off in the
// TUI). It can never fold, yet it is held like any other: holdable goes by
// the probes and the sampling rate, and the loop is not told which syscalls
// are attached. No record marks the resumption then, so the row waits for
// whatever the thread's next record is - the RESUME ahead of its next traced
// enter (the BPF entry waits for that enter, restart.c), its exit record, or
// the end of the run. For a thread that goes on sleeping that is as long as
// the rest of the stopped call takes (2.5 s in a live run), and for one that
// makes no further traced call it is the thread's exit. The row is right (ret
// -516, the latency up to the stop); only the time it appears at and its
// place in the output are off. Not holding -516 rows while restart_syscall is
// not attached would end the delay, and is left open (task u13): the loop
// would have to know the attached set, which the TUI's probes modal changes
// while the loop runs, so a row held under one set can be released under
// another.
type restartTracker struct {
	held map[uint32]*heldRestart // keyed by tid
	// restartBlock and reexec are set by trace setup (foldProvenRestarts)
	// before the loop starts. restartBlock: the signal_deliver and
	// sched_process_exit probes attached, so a RESUME record of BPF means
	// what it says and -516 rows are worth holding. reexec: that, and the
	// drop counter is readable, so -512/-513/-514 rows are worth holding too.
	// Both are false in every other case, which leaves the rows unfolded: the
	// interrupted row at its exit, the continuation as a row of its own.
	restartBlock bool
	reexec       bool
	// restartSyscallSampled is set by newEventLoop from the run's sampling
	// configuration (restartSyscallSampled): restart_syscall is not at rate 1,
	// so a -516 row's own restart_syscall may be missing from the stream
	// without any record lost, and such rows are not held ("Sampling" above:
	// a guard on top of the RESUME record's time rule).
	restartSyscallSampled bool
	// drops knows since when the kernel's drop counter has stood at its
	// current value, which is what proves that no record was lost while a row
	// was held. Both folds ask it (restartProofLost); it stays at its zero
	// value in a run without a drop counter, where nobody asks.
	drops restartDropWatch
	// probes knows when a syscall's probes were last attached or detached at
	// runtime, which is what refuses the rows interrupted before that
	// ("Runtime probe changes" in the file comment). It stays at its zero
	// value - no change, nothing refused - in a run nobody changes probes in,
	// which is every headless run: only a TUI run listens (watchProbeChanges).
	probes restartProbeWatch
}

// restartProbeWatch answers "were syscall probes attached or detached at
// runtime at or after the boot-clock time `since`?" (task o03; see "Runtime
// probe changes" in the file comment). since is the time of a row's
// interrupted exit. A change at or after it means the row's continuation may
// have run while its tracepoints were off, and BPF's pending entry for the
// task - cleared at the change, should the clear have failed or lost a race -
// may stand for a re-execution that is long over.
//
// It is written by the goroutine that changes a probe (eventLoop.probesChanged,
// through the probe manager's change hook) and read by the event loop, hence
// the atomic and the channel; the tracker's other state belongs to the loop
// alone and is not touched from there.
type restartProbeWatch struct {
	// changedAt is the boot-clock reading taken at the latest report: after a
	// detach had destroyed its links, before an attach attached any, after
	// that attach was over, or when the hook was installed. 0 means no change
	// was reported.
	changedAt atomic.Uint64
	// wake tells the loop that changedAt moved, so it releases the rows held
	// from before without waiting for a record (processRawEvents). One slot:
	// the loop reads changedAt when it wakes, so a second change before then
	// needs no second token. nil in a loop built without newEventLoop, which
	// is then never woken and still refuses by time.
	wake chan struct{}
	// clearFailed remembers that a failed clear of restart_pending_map was
	// reported, so a family toggle that fails a hundred times warns once.
	clearFailed atomic.Bool
}

// note records a probe change stamped at (a boot-clock reading) and wakes the
// loop. The stamp only moves forward: two probes changed at once report from
// two goroutines, and the later reading must not be overwritten by the earlier
// one, or the rows interrupted between the two would fold again.
func (w *restartProbeWatch) note(at uint64) {
	for {
		seen := w.changedAt.Load()
		if at <= seen || w.changedAt.CompareAndSwap(seen, at) {
			break
		}
	}
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// changedSince reports whether a probe change was noted at or after since.
func (w *restartProbeWatch) changedSince(since uint64) bool {
	at := w.changedAt.Load()
	return at != 0 && at >= since
}

// restartDropWatch answers "may the kernel have dropped a ring-buffer record
// at or after the boot-clock time `since`?" for both folds. since is the time
// of the interrupted exit's record; records reserved after it are the ones
// the fold reasons about. A row folded once and interrupted again carries the
// continuation's exit (foldRestartExit), so each hop of a call stopped several
// times asks from its own interruption.
//
// What it knows. An observation is one read of the kernel's cumulative drop
// counter together with a boot-clock reading taken AFTER that read. The watch
// keeps the total of the latest observation and the stamp of the earliest
// observation that returned that same total (firstSeenAt). Observations come
// from two places: the periodic drop monitor (handleRingbufDropResult, on its
// own goroutine, hence the mutex), which keeps the watch current while no call
// is interrupted, and the fold itself, which reads the counter at RESUME and
// at the folding exit (lostSince), because the monitor's next poll may be a
// second away.
//
// The invariant: the counter returned `total` in a read that finished at or
// before firstSeenAt. The counter only grows, so if a read made now returns
// `total` as well, nothing was dropped between that earlier read and now.
//
// The rule. lostSince reads the counter now and answers "no loss" only when
// the read returns the watched total and firstSeenAt < since: the counter
// stood at this value in a read that finished before the interrupted exit was
// stamped and still stands there, so no record reserved after that exit was
// dropped. In every other case it answers "maybe lost" and the fold is
// refused, which includes the cases where nothing was lost after `since` but
// nothing proves it:
//
//   - the total moved and this read is the first to see it. The drop may be
//     an hour old or a microsecond old; a counter value says how many, not
//     when. The stamp becomes now, which is after `since`.
//   - the total moved before `since`, but the first observation that saw it
//     came after `since` (a monitor poll, or an earlier fold check, while the
//     row was already held). No observation between the drop and the
//     interruption covers it, so the proof is impossible and the choice is
//     the conservative one. This window is at most one monitor period wide.
//   - the counter cannot be read, or there is none.
//
// So a drop refuses the folds of the calls that were interrupted before the
// first observation that saw it, and no others: an old drop the monitor has
// seen does not keep a later interrupted call from folding.
//
// The zero value is an observation too: the counter is zero when the BPF
// object is loaded, before any record exists, so "0, first seen at time 0"
// is true; were the counter not zero (an object that outlived an earlier
// loop), the first read differs and is stamped like any other change.
//
// A snapshot of the counter taken when the row is held would not do instead:
// the loop consumes a backlog, so by the time it processes the interrupted
// exit, records reserved after it may already have been dropped and counted,
// and the snapshot would include them. Two observers may also report out of
// order (the monitor's read overtaken by the loop's): a total that differs
// from the watched one is always taken as a change and stamped with its own
// reading, which keeps the invariant and refuses the folds of the calls
// interrupted before the next read of the real total (usually one).
//
// The comparison of a record time with a user-space clock reading assumes no
// time-namespace boottime offset, like every other use of bootClockNs.
type restartDropWatch struct {
	mu          sync.Mutex
	total       uint64 // the kernel's cumulative drop count at the latest observation
	firstSeenAt uint64 // stamp of the earliest observation that returned total
}

// observe records one reading of the drop counter, stamped with a boot-clock
// time read after the counter was, and returns the stamp of the earliest
// observation that returned the same total.
func (w *restartDropWatch) observe(total, seenAt uint64) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	if total != w.total {
		w.total = total
		w.firstSeenAt = seenAt
	}
	return w.firstSeenAt
}

// lostSince reports whether a record may have been dropped at or after since
// (see the rule above). It reads the counter itself, and the clock after it.
// An unreadable or missing counter counts as a loss: without it nothing
// vouches for the stream. (The restart_syscall fold of a run that has no
// counter at all does not ask, restartProofLost.)
func (w *restartDropWatch) lostSince(since uint64, src ringbufDropSource, clock func() uint64) bool {
	if src == nil {
		return true
	}
	total, err := src.Total()
	if err != nil {
		return true
	}
	return w.observe(total, clock()) >= since
}

// restartPhase is where a held row stands on its way to a fold.
type restartPhase uint8

const (
	// restartWaiting: nothing has arrived since the interrupted exit.
	restartWaiting restartPhase = iota
	// restartInHandler: a handler the call survives is running; the tid's
	// syscalls are the handler's and pass through.
	restartInHandler
	// restartResumed: BPF announced the continuation; the tid's next record
	// must be the enter of its syscall (restart_syscall for -516, else the
	// same syscall), stamped with the announcement's time
	// (heldRestart.resumeTime).
	restartResumed
	// restartContinuing: the continuation's enter arrived (restart_syscall,
	// or the re-executed call); the tid's next record must be its exit.
	restartContinuing
)

// heldRestart is one interrupted row waiting for its continuation.
type heldRestart struct {
	pair  *event.Pair
	phase restartPhase
	// passed counts the records let through while the handler runs.
	passed int
	// detoured is set once a handler's rows were let through: they moved the
	// tid's gap baseline, which gapBase preserves as it was at the hold.
	detoured bool
	gapBase  uint64
	// resumeTime is the time of the RESUME record that put the row into
	// restartResumed. BPF stamps that record and the enter it announces with
	// the same clock read, so only an enter carrying exactly this time is the
	// announced one (isAnnouncedEnter).
	resumeTime uint64
	// continuation is the continuation's enter while the row stands in
	// restartContinuing: taken out of the stream for the fold, but kept, so a
	// release can park it again (reparkContinuation) and the continuation
	// still becomes a row. continuationKind is the registered kind it arrived
	// as, which carries its raw enter filter. An accepted fold recycles it
	// (dropContinuation), and so does a release by a record that says the task
	// is gone (reportsTaskGone). nil in every other phase.
	continuation     event.Event
	continuationKind rawRuntimeEvent
}

// maxHeldRestarts bounds the rows held at once. A held row normally lives
// for one stop of one thread; the bound only matters when the records that
// would release rows are lost (ring-buffer backpressure), and then it keeps
// the map from growing with dead tids. Rows beyond it are emitted unfolded.
const maxHeldRestarts = 4096

// maxHandlerRecords bounds the records of a tid (enters, exits and name
// fixups, so roughly half as many syscalls) that may pass while its held row
// waits for a restarting signal handler to return. A handler normally makes a
// handful of syscalls; the bound releases the row when the handler never
// returns (siglongjmp) or the RESUME record was lost.
const maxHandlerRecords = 256

// restartAction is what routeHeldRestart does with a record of a tid that
// holds a row.
type restartAction uint8

const (
	// restartRelease: the record ends the wait; the row is completed
	// unchanged, a continuation enter taken earlier is parked again, and the
	// record is processed normally.
	restartRelease restartAction = iota
	// restartConsume: the record was a step of the fold and is dropped.
	restartConsume
	// restartKeepEnter: the record is the continuation's enter, the one
	// RESUME announced. It leaves the stream but is kept with the row until
	// the fold is accepted or refused.
	restartKeepEnter
	// restartResume: the record is BPF's RESUME; it is dropped like a consumed
	// step, unless records were lost since the interrupted exit
	// (restartProofLost), in which case it releases the row.
	restartResume
	// restartPass: the record is processed normally and the row stays held.
	restartPass
	// restartEnterHandler: a restarting handler begins; the record goes on to
	// its (recycling) control handler and the row stays held.
	restartEnterHandler
	// restartFold: the record is the continuation's exit. It is folded only
	// when no record may have been lost since the interrupted exit
	// (restartProofLost); otherwise the row is released and the exit pairs
	// with the continuation's own enter.
	restartFold
)

// restartRetOf returns the return value of ep's exit and whether the exit
// carries one at all.
func restartRetOf(ep *event.Pair) (int64, bool) {
	carrier, ok := ep.ExitEv.(event.RetCarrier)
	if !ok {
		return 0, false
	}
	return carrier.GetRet(), true
}

// interrupted reports whether ep's exit carries one of the kernel's restart
// codes (-512/-513/-514/-516), whether or not the row can be held.
func interrupted(ep *event.Pair) bool {
	ret, ok := restartRetOf(ep)
	return ok && event.IsRestartRet(ret)
}

// restartSyscallSampled reports whether the run samples restart_syscall, given
// the trace IDs whose effective sampling rate is not 1
// (eventLoopConfig.aggregateIngestTraceIDs, built from the same rates
// applySyscallSamplingRates loads into BPF, keyed by enter trace ID). True for
// 1-in-N and for aggregate-only (rate 0) alike; false when nothing configures
// it, when its rate is 1, and when a family's 0 was promoted to 1 for a raw
// output mode.
func restartSyscallSampled(notAtRateOne map[types.TraceId]struct{}) bool {
	_, sampled := notAtRateOne[types.SYS_ENTER_RESTART_SYSCALL]
	return sampled
}

// holdable reports whether ep is an interrupted row worth parking: a -516
// exit of the kind the restart_syscall fold can patch, when BPF announces
// restart_syscall continuations (restartBlock), or - when it proves
// re-executions - any exit carrying -512/-513/-514. A run that samples
// restart_syscall parks no -516 row either ("Sampling" in the file comment).
// A row interrupted at or before the latest runtime probe change is not parked
// at all: nothing may be folded into it any more ("Runtime probe changes" in
// the file comment), so holding it would only delay it. The loop reaches such
// a row when it lags behind the ring buffer, or when a fold ends in a restart
// code again with a probe change behind it.
// The bound is checked against the rows held now, so a caller that replaces a
// tid's row releases that row first (holdRestart).
func (r *restartTracker) holdable(ep *event.Pair) bool {
	ret, ok := restartRetOf(ep)
	if !ok || len(r.held) >= maxHeldRestarts {
		return false
	}
	if r.probes.changedSince(ep.ExitEv.GetTime()) {
		return false
	}
	if event.IsRestartBlockRet(ret) {
		_, isRet := ep.ExitEv.(*types.RetEvent)
		return isRet && r.restartBlock && !r.restartSyscallSampled
	}
	return r.reexec && event.IsReexecutedRestartRet(ret)
}

// hold parks held.pair when it is holdable and reports whether it did. The
// caller must not touch the pair afterwards when it returns true. held keeps
// its gap bookkeeping, so a row held again after a fold that ended in another
// restart code still knows the baseline of its first enter.
func (r *restartTracker) hold(held *heldRestart) bool {
	if !r.holdable(held.pair) {
		return false
	}
	if r.held == nil {
		r.held = make(map[uint32]*heldRestart)
	}
	held.phase = restartWaiting
	held.passed = 0
	r.held[held.pair.ExitEv.GetTid()] = held
	return true
}

// lookup returns the row tid holds, if any.
func (r *restartTracker) lookup(tid uint32) (*heldRestart, bool) {
	held, ok := r.held[tid]
	return held, ok
}

// take removes and returns the row tid holds.
func (r *restartTracker) take(tid uint32) (*heldRestart, bool) {
	held, ok := r.held[tid]
	if !ok {
		return nil, false
	}
	delete(r.held, tid)
	return held, true
}

// reexecutingExecCaller finds the non-leader thread whose re-executed execve
// the successful exit `exit` (under the leader tid, tid == pid) completes, when
// the exec record that would have named the thread was lost (task r13,
// adoptLostExecCaller).
//
// An execve that exited -513 and was re-executed has its second enter kept
// with the held row (heldRestart.continuation), not parked, so the pair
// tracker's index of parked exec callers knows nothing of it. The row is found
// here instead: one of exit's process, held under a tid other than the
// leader's, whose kept enter is an exec enter of the syscall that exit belongs
// to. No other thread of the process can be the caller: a successful exec
// leaves the process with one task, and the rows of the threads de_thread
// killed were released by their exit records before the execve returned.
//
// Should more than one row qualify all the same (a killed sibling's exit record
// was lost as well as the exec record), the one whose execve was entered last
// is taken, as parkedExecCaller prefers the most recently parked caller; the
// tid breaks a tie, so the choice does not depend on map order. The scan is
// over the held rows only - none in most runs, a handful otherwise - and runs
// only for a successful execve exit that found neither an enter of its own nor
// a parked caller.
func (r *restartTracker) reexecutingExecCaller(exit *types.RetEvent) (uint32, bool) {
	var (
		caller  uint32
		entered uint64
		found   bool
	)
	for tid, held := range r.held {
		if !held.reexecutesExecOf(exit) {
			continue
		}
		at := held.continuation.GetTime()
		if !found || at > entered || (at == entered && tid > caller) {
			caller, entered, found = tid, at, true
		}
	}
	return caller, found
}

// reexecutesExecOf reports whether the row is an execve of a non-leader thread
// of exit's process that was interrupted and re-executed, with the re-executed
// enter taken for the fold, and exit is an exit of that same syscall (execve or
// execveat: a re-execution's exit carries the held exit's trace ID). A row has
// a continuation only while it stands in restartContinuing, so a row that
// still waits for its RESUME record or for the announced enter never
// qualifies, and neither does a -516 row: its continuation is a
// restart_syscall enter.
func (h *heldRestart) reexecutesExecOf(exit *types.RetEvent) bool {
	enter, isExec := h.continuation.(*types.ExecEvent)
	return isExec && enter.Pid == exit.Pid && enter.Tid != enter.Pid && h.continuationExitID() == exit.TraceId
}

// takeAll removes every held row and returns them oldest exit first, so the
// rows released at the end of a run keep their completion order.
func (r *restartTracker) takeAll() []*heldRestart {
	return r.takeInterruptedBy(math.MaxUint64)
}

// takeInterruptedBy removes the held rows whose interrupted exit is stamped at
// or before at and returns them oldest exit first. For a row folded once and
// interrupted again that exit is the continuation's (foldRestartExit), so the
// row is judged by its latest interruption, as the drop watch judges it.
func (r *restartTracker) takeInterruptedBy(at uint64) []*heldRestart {
	rows := make([]*heldRestart, 0, len(r.held))
	for tid, held := range r.held {
		if held.pair.ExitEv.GetTime() > at {
			continue
		}
		rows = append(rows, held)
		delete(r.held, tid)
	}
	slices.SortFunc(rows, func(a, b *heldRestart) int {
		return cmp.Compare(a.pair.ExitEv.GetTime(), b.pair.ExitEv.GetTime())
	})
	return rows
}

// restartSurvivesHandler is the kernel's handle_signal rule for an
// interrupted call when a user handler runs: -ERESTARTNOINTR (-513) is
// restarted regardless, -ERESTARTSYS (-512) only when the handler was
// installed with SA_RESTART, and -ERESTARTNOHAND (-514) and
// -ERESTART_RESTARTBLOCK (-516) never - the program gets EINTR.
// ior_restart_survives_handler in internal/c/restart.c is the same rule on
// the BPF side, which decides whether a RESUME record can follow at all.
func restartSurvivesHandler(ret int64, saRestart bool) bool {
	switch {
	case event.IsRestartNoIntrRet(ret):
		return true
	case event.IsRestartSysRet(ret):
		return saRestart
	}
	return false
}

// step applies one record of the held tid to the row and returns what the
// loop has to do with the record. A row that waits (restartWaiting) takes a
// control record of the restart-fold probes and nothing else: every syscall
// record of the tid releases it, a restart_syscall enter included - a
// continuation BPF did not announce is some other call's.
func (h *heldRestart) step(direction rawEventDirection, ev runtimeDecodedEvent) restartAction {
	if rec, ok := ev.(*types.SyscallRestartEvent); ok {
		return h.stepRestartRecord(rec)
	}
	switch h.phase {
	case restartInHandler:
		return h.stepHandlerRecord(direction, ev)
	case restartResumed:
		if h.isAnnouncedEnter(direction, ev) {
			h.phase = restartContinuing
			return restartKeepEnter
		}
	case restartContinuing:
		return h.stepContinuation(direction, ev)
	}
	return restartRelease
}

// stepRestartRecord applies a control record of the restart-fold probes: a
// HANDLER record to a row that waits, which a -516 row never survives
// (restartSurvivesHandler), and a RESUME record to a row that waits or whose
// handler runs. A record that does not fit the phase releases the row like
// any other unexpected record.
func (h *heldRestart) stepRestartRecord(rec *types.SyscallRestartEvent) restartAction {
	ret, _ := restartRetOf(h.pair)
	switch {
	case rec.Phase == types.RESTART_PHASE_HANDLER && h.phase == restartWaiting:
		if !restartSurvivesHandler(ret, rec.SaRestart != 0) {
			return restartRelease
		}
		h.phase = restartInHandler
		return restartEnterHandler
	case rec.Phase == types.RESTART_PHASE_RESUME && (h.phase == restartWaiting || h.phase == restartInHandler):
		h.phase = restartResumed
		h.resumeTime = rec.Time
		return restartResume
	}
	return restartRelease
}

// stepHandlerRecord lets the syscalls of a running signal handler through:
// its enters and exits and the name fixups between them. Any other record of
// the tid (its exit, a new task with its tid, an exec) ends the wait, and so
// does a handler that outlasts maxHandlerRecords.
//
// An exit that carries a restart code ends it too, whether or not it will
// pair. It is a call of the handler interrupted in turn, and every emitted
// exit in the restart-code range makes BPF replace or clear the task's one
// entry (ior_restart_on_exit): from here on a RESUME record announces the
// re-execution of that inner call, not of this row's. Waiting for the exit to
// pair (holdRestart) is not enough, because its enter may never have been
// parked - an open the raw enter filter shed (-path, -comm), or an enter lost
// to backpressure - and the outer row would then take the inner call's
// re-execution for its own when both are the same syscall.
func (h *heldRestart) stepHandlerRecord(direction rawEventDirection, ev runtimeDecodedEvent) restartAction {
	if direction == rawControlEvent {
		if _, isFixup := ev.(*types.OpenNameFixupEvent); !isFixup {
			return restartRelease
		}
	}
	if carrier, ok := ev.(event.RetCarrier); ok && direction == rawExitEvent && event.IsRestartRet(carrier.GetRet()) {
		return restartRelease
	}
	h.passed++
	if h.passed > maxHandlerRecords {
		return restartRelease
	}
	return restartPass
}

// stepContinuation expects the exit of the continuation whose enter was
// taken. A name fixup in between belongs to that enter (a re-executed open
// whose path read faulted again): it is spliced into the kept enter, as
// handleOpenNameFixupEvent would splice it into a parked one, so the enter is
// complete should a release park it again, and then goes with it.
func (h *heldRestart) stepContinuation(direction rawEventDirection, ev runtimeDecodedEvent) restartAction {
	if fixup, isFixup := ev.(*types.OpenNameFixupEvent); isFixup && h.reexecuted() {
		applyRecoveredFilename(h.continuation, fixup)
		return restartConsume
	}
	exitEv, ok := ev.(event.Event)
	if !ok || direction != rawExitEvent || exitEv.GetTraceId() != h.continuationExitID() {
		return restartRelease
	}
	if _, isRet := ev.(*types.RetEvent); !isRet && !h.reexecuted() {
		// The restart_syscall fold patches the held RetEvent from a RetEvent.
		return restartRelease
	}
	return restartFold
}

// reexecuted reports whether the row's continuation is a re-execution of the
// same syscall (-512/-513/-514) rather than restart_syscall (-516).
func (h *heldRestart) reexecuted() bool {
	ret, _ := restartRetOf(h.pair)
	return event.IsReexecutedRestartRet(ret)
}

// continuationExitID is the trace ID of the exit that completes the fold.
func (h *heldRestart) continuationExitID() types.TraceId {
	if h.reexecuted() {
		return h.pair.ExitEv.GetTraceId()
	}
	return types.SYS_EXIT_RESTART_SYSCALL
}

// continuationEnterID is the trace ID of the enter that carries the row on:
// restart_syscall for a -516 row, the row's own syscall for a re-execution.
func (h *heldRestart) continuationEnterID() types.TraceId {
	if h.reexecuted() {
		return h.pair.EnterEv.GetTraceId()
	}
	return types.SYS_ENTER_RESTART_SYSCALL
}

// isAnnouncedEnter reports whether ev is the enter the RESUME record
// announced: an enter of the continuation's syscall (continuationEnterID)
// that carries the RESUME record's time. BPF stamps both with one clock read
// (ior_restart_on_enter in internal/c/restart.c), and the announced enter may
// never arrive - sampled out, or refused by a full ring buffer - so the
// syscall alone does not identify it: the tid's next call of that syscall (a
// later stopped call's restart_syscall) would pass too, and a stranger's
// result would be folded into the row. A later enter has a later time (a
// clock too coarse to tell two enters of one thread apart is the one
// exception, see "A time rule that cannot tell" under "Known wrong folds" in
// restart.c). The syscall is checked as well because BPF announces the first
// traced enter of the task whatever it is: after -516 that is restart_syscall
// only when restart_syscall is traced.
func (h *heldRestart) isAnnouncedEnter(direction rawEventDirection, ev runtimeDecodedEvent) bool {
	enterEv, ok := ev.(event.Event)
	return ok && direction == rawEnterEvent && enterEv.GetTraceId() == h.continuationEnterID() &&
		enterEv.GetTime() == h.resumeTime
}

// tidRecord is what every decoded record that belongs to a task offers:
// syscall events and the control records alike carry the task's tid.
type tidRecord interface {
	GetTid() uint32
}

// routeHeldRestart applies the decision rules above to one decoded record
// before it is processed, and reports whether the fold took the record (a
// step of a held row's continuation), in which case the caller must not
// process it further. A record that releases the held row is not taken: the
// row is completed (and sent on ch) and a continuation enter taken earlier is
// parked again first - or recycled, when the record says the task that made
// the call is gone (reportsTaskGone) - then the record goes its usual way.
// Records of tids without a held row cost one length check. rawEvent is the
// registered kind ev was decoded as.
//
// The row is found by the record's own tid. The records that settle a row held
// under another tid do so in their own handlers: the exec record of a
// non-leader thread (releaseExecCallerRestart) and, when that record was lost,
// the execve's exit under the leader tid (adoptLostExecCaller).
func (e *eventLoop) routeHeldRestart(rawEvent rawRuntimeEvent, ev runtimeDecodedEvent, ch chan<- *event.Pair) bool {
	if len(e.restarts.held) == 0 {
		return false
	}
	rec, ok := ev.(tidRecord)
	if !ok {
		return false
	}
	tid := rec.GetTid()
	held, ok := e.restarts.lookup(tid)
	if !ok {
		return false
	}
	action := held.step(rawEvent.direction, ev)
	if e.restartAcrossProbeChange(held, action) || e.restartProofLost(held, action) {
		action = restartRelease
	}
	switch action {
	case restartKeepEnter:
		held.continuation, held.continuationKind = ev.(event.Event), rawEvent
		return true
	case restartConsume, restartResume:
		ev.Recycle()
		return true
	case restartFold:
		e.foldRestartExit(ev.(event.Event), ch)
		return true
	case restartEnterHandler:
		e.detourGapBaseline(held)
		return false
	case restartPass:
		return false
	}
	if reportsTaskGone(ev) {
		// Nothing will pair with the dead task's enter: it must not be parked.
		held.dropContinuation()
	}
	e.releaseHeldRestart(tid, ch)
	return false
}

// reportsTaskGone reports whether ev says that the task its tid named until
// now no longer exists: the task's own sched_process_exit record, or a
// task_newtask record, which gives the number to a brand-new task (the
// previous owner's exit record was lost). Both release the row held under that
// tid like any record that is not the next step of the fold - the interrupted
// call did return, with the restart code, and stays a row - but the
// continuation whose enter the fold had taken was still inside the kernel when
// its task died. It never returns, so the enter is recycled rather than parked
// again (routeHeldRestart).
//
// A task_newtask record also finds a row under its tid when the previous owner
// was a non-leader thread that exec'd with the exec record lost (such a thread
// gets no exit record under its old tid): recycling the enter is still right,
// unless the execve's exit is behind the newtask record in the ring (the tid
// numbers wrapped around within one exec), in which case that exit finds no
// row to adopt from (adoptLostExecCaller) and the exec's row is lost.
//
// Parking it bought nothing and cost something (task r13). After an exit
// record, or a task_newtask record of a task the trace follows, the control
// handler evicted the enter again within the same record
// (handleProcessExitEvent, retireRecycledTid) - but parking it first could
// push the oldest live enters out of a full pending-enter table
// (pairTracker.prune), and it seeded the comm cache and resolved an exec
// target for a task that does not exist. After a task_newtask record flagged
// ChildOutOfScope nothing evicted it at all: handleTaskNewtaskEvent returns
// before retiring the tid, since the kernel filter passes none of that task's
// records. A re-executed execve enter of a non-leader thread then stayed
// parked under a tid that was no longer its task's, and stayed a
// parkedExecCaller hint for its process until LRU trimming - a candidate for
// adoptLostExecCaller to pair with a later, unrelated execve exit of that pid.
//
// The exec record of a non-leader thread is not such a record, although the
// thread's old tid vanishes with it: the task lives on under the leader's tid
// and its execve does return there (releaseExecCallerRestart parks the enter
// for exactly that).
func reportsTaskGone(ev runtimeDecodedEvent) bool {
	switch ev.(type) {
	case *types.ProcessExitEvent, *types.TaskNewtaskEvent:
		return true
	}
	return false
}

// restartProofLost reports whether a step towards a fold must be refused
// because the kernel may have dropped records since the interrupted exit (see
// "Lost records" in the file comment and restartDropWatch). It is asked at the
// two steps of a fold that commit (commitsToFold): at RESUME, where the
// continuation is announced, a refusal releases the row before an enter is
// taken for it, and at the continuation's exit it keeps a result that may
// belong to another call out of the row. Either way the call ends up as two
// rows, the interrupted one and the continuation: at the exit, the release
// parks the enter taken for the fold again and the exit pairs with it. Each
// question is one read of the drop counter, paid only by interrupted calls.
//
// Without a drop counter the restart_syscall fold is not asked and folds on
// RESUME alone; the stranger it can then fold is the residual described under
// "Lost records". A sampled restart_syscall is not this function's business:
// such a run holds no -516 row in the first place (holdable; "Sampling" in
// the file comment), with or without a counter. A re-execution row is never
// held without a counter (foldProvenRestarts), and would be refused here if
// it were.
func (e *eventLoop) restartProofLost(held *heldRestart, action restartAction) bool {
	if !commitsToFold(action) {
		return false
	}
	if e.dropSrc == nil && !held.reexecuted() {
		return false
	}
	return e.restarts.drops.lostSince(held.pair.ExitEv.GetTime(), e.dropSrc, e.readDropStampClock)
}

// restartAcrossProbeChange reports whether a step towards a fold must be
// refused because syscall probes were attached or detached at runtime since
// the interrupted exit ("Runtime probe changes" in the file comment): the
// continuation may have run unseen, and what BPF announces now, or the exit
// that arrives now, may belong to a later call of the task. It is asked at the
// steps restartProofLost is asked at, for the same reasons, and costs one
// atomic load there. The woken loop releases such a row on its own
// (releaseRestartsBehindProbeChange); this is what holds when the record
// reaches the loop first, and for a row the loop held only after the change.
func (e *eventLoop) restartAcrossProbeChange(held *heldRestart, action restartAction) bool {
	return commitsToFold(action) && e.restarts.probes.changedSince(held.pair.ExitEv.GetTime())
}

// commitsToFold reports whether action is a step at which a fold asks for
// proof that it still stands - no record lost (restartProofLost), no probe
// changed (restartAcrossProbeChange): the record that announces the continuation
// (RESUME) and the continuation's exit. The announced enter between them is
// not such a step: RESUME, which names it by time, was asked just before it.
func commitsToFold(action restartAction) bool {
	return action == restartResume || action == restartFold
}

// detourGapBaseline prepares the tid's gap baseline for the rows of a signal
// handler that complete before the row they interrupted: the handler's first
// syscall measures its gap from the interrupted exit, and the held row keeps
// the baseline of its own enter (completeHeldRestart restores it).
func (e *eventLoop) detourGapBaseline(held *heldRestart) {
	tid := held.pair.ExitEv.GetTid()
	if !held.detoured {
		held.detoured = true
		held.gapBase = e.pairs.prevTime(tid)
	}
	e.pairs.setPrevTime(tid, held.pair.ExitEv.GetTime())
}

// holdRestart parks ep when it is an interrupted row whose continuation may
// still come, and reports whether it did. A tid that already holds a row is
// inside the signal handler that row waits for, and this is a call of that
// handler being interrupted in turn: BPF tracks one pending call per task,
// the latest (an exit with a restart code replaces or clears the task's
// entry, ior_restart_on_exit), so the outer row is released unchanged and ep
// takes its place.
//
// The outer row is released before ep is judged, and whether or not ep can
// then be held: BPF has moved on to the inner call either way, and its RESUME
// for the inner call's re-execution must not find the outer row still waiting
// - a handler reading again from the descriptor its interrupted call was
// reading would be folded into the outer row. Releasing first also frees the
// slot ep needs when the tracker is at its bound. (Since stepHandlerRecord
// releases on the interrupted exit itself, the row is normally gone by the
// time the pair gets here; the release below is what holds when a row
// reaches this point by any other route.)
func (e *eventLoop) holdRestart(ep *event.Pair, ch chan<- *event.Pair) bool {
	if !interrupted(ep) {
		return false
	}
	e.releaseHeldRestart(ep.ExitEv.GetTid(), ch)
	return e.restarts.hold(&heldRestart{pair: ep})
}

// foldRestartExit completes a fold with the continuation's exit: the held
// row takes its outcome, and is completed - or held again when the
// continuation was itself interrupted (a restart code once more).
func (e *eventLoop) foldRestartExit(exitEv event.Event, ch chan<- *event.Pair) {
	held, _ := e.restarts.take(exitEv.GetTid())
	// The fold is accepted: the continuation is part of this row now and its
	// enter is not needed any more.
	held.dropContinuation()
	if held.reexecuted() {
		// The same syscall's exit record, of whatever kind: it replaces the
		// interrupted one.
		held.pair.ExitEv.Recycle()
		held.pair.ExitEv = exitEv
	} else {
		// restart_syscall's exit carries a foreign trace ID, so only its
		// outcome is copied; stepContinuation admits RetEvents only, and
		// holdable parks -516 pairs only with a RetEvent exit.
		restartExit := exitEv.(*types.RetEvent)
		heldExit := held.pair.ExitEv.(*types.RetEvent)
		heldExit.Ret = restartExit.Ret
		heldExit.Time = restartExit.Time
		restartExit.Recycle()
	}
	if e.restarts.hold(held) {
		return
	}
	e.completeHeldRestart(held, ch)
}

// completeHeldRestart turns a held row into a row, folded or unchanged. A row
// whose signal handler's syscalls completed before it measures its gap from
// the baseline its enter had (gapBase), not from the handler's last row, and
// must not move the tid's baseline back behind the rows already emitted.
func (e *eventLoop) completeHeldRestart(held *heldRestart, ch chan<- *event.Pair) {
	if !held.detoured {
		e.completeTracepointPair(held.pair, ch)
		return
	}
	tid := held.pair.ExitEv.GetTid()
	afterHandler := e.pairs.prevTime(tid)
	e.pairs.setPrevTime(tid, held.gapBase)
	e.completeTracepointPair(held.pair, ch)
	if e.pairs.prevTime(tid) < afterHandler {
		e.pairs.setPrevTime(tid, afterHandler)
	}
}

// releaseHeldRestart releases the row tid holds, if any: the record that
// triggered it shows that the call is not carried on, or not provably.
func (e *eventLoop) releaseHeldRestart(tid uint32, ch chan<- *event.Pair) {
	if held, ok := e.restarts.take(tid); ok {
		e.releaseTakenRestart(held, ch)
	}
}

// releaseTakenRestart undoes a fold that will not happen, for a row already
// taken out of the tracker: the row is completed unchanged, then the
// continuation's enter, if the fold had taken it, becomes the tid's pending
// enter again. In that order, which is the order of the stream (the
// interrupted exit precedes the continuation's enter), so the row's exit
// handler and gap are settled before the next call of the tid is parked. The
// repark is deferred so that a panic in the row's exit handler, which the
// callers recover, does not cost the continuation its enter as well.
func (e *eventLoop) releaseTakenRestart(held *heldRestart, ch chan<- *event.Pair) {
	defer e.reparkContinuation(held, ch)
	e.completeHeldRestart(held, ch)
}

// reparkContinuation hands the continuation's enter back to the path every
// enter takes (syscallEntered), as if the fold had never taken it: its comm
// seeds the cache, the kind's raw enter filter decides whether this run wants
// it at all, and an exec enter gets its target snapshot. The exit that
// follows then pairs with it like any other. It does nothing when the enter is
// already gone: no continuation was taken, or routeHeldRestart recycled it
// because the task died inside the call (reportsTaskGone).
//
// It sends nothing on ch, which the bound of the pair channel relies on
// (pairChannelSlots): syscallEntered completes a row only for a syscall that
// never returns, and the enter kept here is one whose syscall has an exit -
// the interrupted call's own syscall, or restart_syscall.
//
// The tid usually has no pending enter at this point: the interrupted exit
// consumed the call's own, and in restartContinuing every further record of
// the tid comes through here first. It can have one all the same - an enter
// that passed while the row's handler ran (restartInHandler) and whose exit
// record never arrived. Parking displaces it exactly as the continuation's
// enter would have displaced it had the fold never taken it: pairTracker.set
// recycles the previous enter, a call that can no longer pair. No row comes
// of that either.
func (e *eventLoop) reparkContinuation(held *heldRestart, ch chan<- *event.Pair) {
	enterEv := held.continuation
	if enterEv == nil {
		return
	}
	held.continuation = nil
	e.syscallEntered(held.continuationKind, enterEv, ch)
}

// dropContinuation recycles the continuation's enter: once the fold that took
// it is accepted, or when the record that releases the row says the task died
// inside the continuation (routeHeldRestart, reportsTaskGone). The field is
// cleared first, so the enter can never be both recycled here and parked again
// by a release of the same row - the later one of a fold that ended in a
// restart code and keeps the heldRestart, or the one that follows at once for
// a gone task, whose reparkContinuation then finds nothing to park.
func (h *heldRestart) dropContinuation() {
	enterEv := h.continuation
	if enterEv == nil {
		return
	}
	h.continuation = nil
	enterEv.Recycle()
}

// handleSyscallRestartEvent is the control handler of the restart-fold
// records. routeHeldRestart has already applied the record to the row its tid
// holds; a record that arrives here belongs to a tid without one (the row was
// released, never held, or evicted; BPF announces a continuation whether or
// not userspace holds the row) or has done its work, so it is recycled.
func (e *eventLoop) handleSyscallRestartEvent(ev *types.SyscallRestartEvent) {
	ev.Recycle()
}

// foldProvenRestarts tells the loop what BPF proves for this run (trace
// setup, before the loop starts), which decides the rows it holds. Without
// the proof the rows are not held at all and stay as they were before either
// fold existed: the interrupted row, and the continuation as a row of its own.
//
// Both folds need the two probes (restartBlock; -516 rows):
//
//   - the signal_deliver probe attached, so every handler delivered to an
//     interrupted task is seen and a RESUME record means what it says.
//     Without it a RESUME record would also precede a program's own retry
//     after EINTR, and - after a handler that ended a -516 call and left by
//     siglongjmp - the restart_syscall of a later call.
//   - the sched_process_exit probe attached, so BPF forgets a task that dies
//     with a call pending (ior_restart_forget). Without it a later task with
//     the recycled tid would inherit the entry and its first syscall would be
//     announced as the dead task's continuation.
//
// The re-execution fold (reexec; -512/-513/-514 rows) needs a third thing:
//
//   - the drop counter can be read (dropSrc), so a fold can be refused when
//     records were lost while the row was held (restartProofLost). The
//     restart_syscall fold runs without it, unchecked ("Lost records" in the
//     file comment).
func (e *eventLoop) foldProvenRestarts(signalProbeAttached, exitProbeAttached bool) {
	e.restarts.restartBlock = signalProbeAttached && exitProbeAttached
	e.restarts.reexec = e.restarts.restartBlock && e.dropSrc != nil
}

// releaseAllHeldRestarts releases every row still held when the event loop
// stops, so a call interrupted near the end of the trace (or in a task that is
// still stopped) is emitted as it was rather than lost. A continuation enter
// taken for a fold that the stop cut short is parked again like on any other
// release; its call was still running when the trace ended and is, like every
// call in flight at the stop, not a row. Each row is emitted before the next
// is completed: pairs has room for one record's pairs only. It runs outside
// processRawEventSafe, so each release recovers a handler panic the same way:
// one bad row must not cost the others.
func (e *eventLoop) releaseAllHeldRestarts(pairs chan *event.Pair) {
	if len(e.restarts.held) == 0 {
		return
	}
	for _, held := range e.restarts.takeAll() {
		e.releaseTakenRestartSafe(held, pairs)
		e.drainPairs(pairs)
	}
}

// watchProbeChanges makes the loop listen to runtime probe changes (trace
// setup, before the loop starts): listen is the probe manager's SetChangeHook.
// Trace setup calls it only for a manager it published to a TUI
// (runTraceSetup); a headless run changes no probe, so it must not pay for the
// guard, least of all with folds refused over a clock it cannot compare (see
// probesChanged).
//
// Installing the hook is reported as a change, the first one the loop knows
// of. The TUI is handed the probe manager before the loop exists, so a probe
// it switched off and on in between was reported to nobody: the entries such a
// change left in restart_pending_map are cleared like at any report, and the
// calls interrupted before this point are not folded - the calls of the few
// milliseconds between the probe attach and the end of setup. The hook is set
// first, so a change that races the install is reported by one or the other.
// The wake token it leaves is taken by the loop when it starts and finds
// nothing held.
func (e *eventLoop) watchProbeChanges(listen func(hook func())) {
	// The order is the point: see above.
	listen(e.probesChanged)
	e.probesChanged()
}

// probesChanged is the probe manager's change hook
// (probemanager.Manager.SetChangeHook): a syscall's probes are about to be
// attached, or were just attached or detached, at runtime. It runs on the
// goroutine that changes the probe - never on the loop's - and touches only
// what is safe from there: the BPF map, the watch's atomics and channel, and
// the warning sink the drop monitor's goroutine reports through as well.
//
// The clock is read twice. The reading that counts is the one after the clear:
// every entry the clear removed was made before it, so the row that entry
// stood for is refused by time as well, and the two never disagree about a
// row. The reading before the clear only makes the stamp exist sooner. After
// an attach the new pair has been producing records since the kernel attached
// it, and until a stamp is stored the loop folds them into rows interrupted
// during the attach ("What is left open" in the file comment); the clear takes
// a third of a millisecond, two with the per-slot fallback, which that gap
// need not include. The stamp only moves forward (restartProbeWatch.note), so
// the first reading never undoes anything.
//
// A clear that fails is reported once and changes nothing else - the time rule
// does not depend on it. Without a map to clear (restartPending nil: tests,
// and an object override that has no restart probes and so announces nothing)
// only the stamps are taken.
//
// The stamp is a user-space CLOCK_BOOTTIME reading compared with record times
// from bpf_ktime_get_boot_ns, like every use of bootClockNs, and so assumes
// that ior does not run in a time namespace with a boottime offset (the BPF
// helper is not namespaced, the user-space clock is). With a positive offset
// the stamp lies in the records' future and every fold is refused until the
// records' clock has caught up with it - for the length of the offset after
// each probe change, the install included. With a negative offset the stamp
// lies in their past, the time rule refuses too little, and the clear of the
// map is the only guard. Nothing detects or corrects the offset here, as
// nowhere else in ior; only TUI runs take a stamp at all.
func (e *eventLoop) probesChanged() {
	e.restarts.probes.note(e.readDropStampClock())
	if e.restartPending != nil {
		if err := e.restartPending.Clear(); err != nil && e.restarts.probes.clearFailed.CompareAndSwap(false, true) {
			e.notifyWarningOrLog(fmt.Sprintf(
				"Could not clear the kernel's pending syscall restarts after a probe change (interrupted calls from before it stay unfolded all the same): %v", err))
		}
	}
	e.restarts.probes.note(e.readDropStampClock())
}

// releaseRestartsBehindProbeChange releases, in the woken loop, every held row
// that was interrupted at or before the latest runtime probe change: none of
// them can fold any more (restartAcrossProbeChange), so they are emitted now,
// unchanged and oldest exit first, instead of each waiting for its tid's next
// record. A continuation enter taken for a fold is parked again as on any
// release, and its exit then pairs with it as a row of its own. Rows
// interrupted after the change stay held: their fold is as sound as any.
// Like releaseAllHeldRestarts it runs outside processRawEventSafe, emits each
// row before the next is completed and recovers a handler panic per row.
func (e *eventLoop) releaseRestartsBehindProbeChange(pairs chan *event.Pair) {
	if len(e.restarts.held) == 0 {
		return
	}
	for _, held := range e.restarts.takeInterruptedBy(e.restarts.probes.changedAt.Load()) {
		e.releaseTakenRestartSafe(held, pairs)
		e.drainPairs(pairs)
	}
}

// releaseTakenRestartSafe releases one held row outside the per-record path -
// at the end of the run, or at a runtime probe change - turning a panic in its
// exit handler into a warning.
func (e *eventLoop) releaseTakenRestartSafe(held *heldRestart, pairs chan<- *event.Pair) {
	defer func() {
		if r := recover(); r != nil {
			e.notifyWarning(fmt.Sprintf("Recovered panic releasing a held restart row: %v", r))
		}
	}()
	e.releaseTakenRestart(held, pairs)
}
