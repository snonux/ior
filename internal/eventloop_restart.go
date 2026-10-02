package internal

import (
	"cmp"
	"fmt"
	"slices"
	"sync"

	"ior/internal/event"
	"ior/internal/types"
)

// Folding a kernel-restarted call into one row (tasks fs2 and 103).
//
// A signal that interrupts a blocked syscall makes it exit with a
// kernel-internal restart code, and the kernel may then carry the call on
// without the program ever learning it was interrupted. ior used to show such
// a call as two or more rows; here the pieces are folded back into the one
// call the program made. There are two ways the kernel carries a call on, and
// each has its own proof.
//
// (1) restart_syscall, for -ERESTART_RESTARTBLOCK (-516; task fs2). A blocked
// nanosleep, clock_nanosleep, poll or timed futex wait exits with -516. When
// no handler runs (SIGSTOP/SIGCONT, a ptrace or freezer stop), the kernel does
// not re-execute the call: it re-enters the task through restart_syscall,
// which finishes the same call from the restart block (for a relative sleep,
// against the original absolute expiry). restart_syscall can only resume a
// -516: the kernel sets it up in exactly that case, and only when no handler
// runs (a handled signal turns -516 into EINTR and the next record of the tid
// is the handler's work or its rt_sigreturn, never restart_syscall). So a -516
// row whose tid's very next record is a restart_syscall enter is provably the
// same call, and the syscall stream alone proves it.
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
// (foldReexecutedRestarts).
//
// RESUME names its enter by time. BPF emits RESUME before it knows whether
// the enter itself will be recorded: the enter may be sampled out (1-in-N
// sampling suppresses it with probability (N-1)/N) or lost to a full ring
// buffer. Both records are stamped with the handler's one clock read, so the
// fold takes only an enter whose time equals the RESUME record's
// (heldRestart.resumeTime); a later call of the same syscall, which is what
// follows RESUME when the re-execution went unrecorded, has a later time and
// releases the row. Carrying the interrupted call's sampling decision over to
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
// still held here). The check is host-wide, so under ring-buffer backpressure
// nothing is folded - the direction every doubt is resolved in. A refused
// fold costs no row: the call shows as it did before task 103, the
// interrupted row and the continuation's row.
//
// The decision rules (heldRestart.phase records where a held row stands):
//
//   - Hold (waiting): a pair whose exit carries -516 (a *types.RetEvent), or
//     -512/-513/-514 when re-execution folding is on, is parked here instead
//     of being completed (tracepointExited). Its exit handler, derived values
//     and pair filter all wait for the outcome. At most maxHeldRestarts rows
//     are held; beyond that the row is completed at once, unfolded.
//   - Handler (-512/-513 only): a HANDLER control record says a user handler
//     runs for the interrupted call. If the call survives it by the rules
//     above (restartSurvivesHandler; BPF applied the same rule and will send
//     RESUME only then), the row stays held while the handler's own syscalls
//     pass through as ordinary rows; otherwise the program gets EINTR and the
//     row is released at once. At most maxHandlerRecords records may pass (a
//     handler that leaves through siglongjmp never returns, and a lost RESUME
//     must not park the row for good).
//   - Resume: the continuation's enter arrives and is taken out of the
//     stream (no row, no raw enter filter: the decision must not depend on
//     what this run would show). For -516 it is the tid's restart_syscall
//     enter, right after the hold. For re-execution it is an enter of the
//     same syscall, and only as the tid's very next record after a RESUME
//     control record and stamped with that record's time. The enter is kept
//     with the row (heldRestart.continuation), not recycled: the fold can
//     still be refused, and then the continuation needs it to become a row.
//   - Fold: the tid's next record is the continuation's exit. For -516 its
//     return value and time replace the held exit's (the exit keeps the
//     original syscall's trace ID); for re-execution the exit record itself
//     replaces the held one (it is the same syscall's exit, of whatever
//     kind). The kept enter is recycled now. A fold that ends in a restart
//     code again is held again. A name fixup the re-executed enter triggers
//     is applied to the kept enter and consumed.
//   - Release: any record of the held tid that is not the next step above
//     (any enter, another exit, a control record such as the task's exit, a
//     fresh task with the recycled tid, a restart record that does not fit
//     the phase) first completes the held row unchanged, then is processed
//     normally. So does a RESUME record or a continuation's exit that arrives
//     after the kernel may have dropped records (see "Lost records" above),
//     and an exit of the tid with a restart code while its handler runs,
//     paired or not: BPF tracks the latest interrupted call of a task, so the
//     row it could announce a re-execution for is no longer this one
//     (stepHandlerRecord). A paired one is then held in the row's place
//     (when there is room, holdRestart). At the end of the run every held row
//     is completed too (releaseAllHeldRestarts). No held row is lost: it is
//     either folded or emitted as it was.
//   - One release is not triggered by a record of the held tid, because there
//     is none: a non-leader thread that execs continues under the leader's
//     tid, gets no exit record under its old one, and is never heard of under
//     that tid again. Its exec record names the old tid (OldTid), and that
//     releases the row held there (releaseExecCallerRestart) - the execve
//     itself when it was interrupted with -513 and re-executed, or the call
//     whose restarting handler exec'd instead of returning.
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
// proof was lost or unavailable, the continuation was sampled out, or the
// trace ended first.
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
// case) it is the HANDLER record or the handler's first syscall, typically
// microseconds later. Rows of other tids emitted meanwhile may therefore
// precede it although they exited later, and so do the rows of a restarting
// handler's own syscalls: they complete before the call they interrupted.
// Those rows measure their gap from the interrupted exit, and the folded row
// keeps the gap it had at its first enter (heldRestart.gapBase).
type restartTracker struct {
	held map[uint32]*heldRestart // keyed by tid
	// reexec is set by trace setup (foldReexecutedRestarts) before the loop
	// starts: the signal_deliver and sched_process_exit probes attached and
	// the drop counter is readable, so BPF can prove a re-execution and
	// -512/-513/-514 rows are worth holding. False in every other case, which
	// leaves those rows exactly as they were before task 103.
	reexec bool
	// drops knows since when the kernel's drop counter has stood at its
	// current value, which is what proves that no record was lost while a row
	// was held.
	drops restartDropWatch
}

// restartDropWatch answers "may the kernel have dropped a ring-buffer record
// at or after the boot-clock time `since`?" for the re-execution fold. since is
// the time of the interrupted exit's record; records reserved after it are
// the ones the fold reasons about.
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
// vouches for the stream.
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
	// restartResumed: BPF announced the re-execution; the tid's next record
	// must be the enter of the same syscall, stamped with the announcement's
	// time (heldRestart.resumeTime).
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
	// announced one (isReexecutedEnter).
	resumeTime uint64
	// continuation is the continuation's enter while the row stands in
	// restartContinuing: taken out of the stream for the fold, but kept, so a
	// release can park it again (reparkContinuation) and the continuation
	// still becomes a row. continuationKind is the registered kind it arrived
	// as, which carries its raw enter filter. An accepted fold recycles it
	// (dropContinuation). nil in every other phase.
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
	// restartKeepEnter: the record is the continuation's enter. It leaves the
	// stream but is kept with the row until the fold is accepted or refused.
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
	// restartFold: the record is the continuation's exit. A re-execution is
	// folded only when no record was lost since the interrupted exit
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

// holdable reports whether ep is an interrupted row worth parking: a -516
// exit of the kind the restart_syscall fold can patch, or - when BPF proves
// re-executions - any exit carrying -512/-513/-514. The bound is checked
// against the rows held now, so a caller that replaces a tid's row releases
// that row first (holdRestart).
func (r *restartTracker) holdable(ep *event.Pair) bool {
	ret, ok := restartRetOf(ep)
	if !ok || len(r.held) >= maxHeldRestarts {
		return false
	}
	if event.IsRestartBlockRet(ret) {
		_, isRet := ep.ExitEv.(*types.RetEvent)
		return isRet
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

// takeAll removes every held row and returns them oldest exit first, so the
// rows released at the end of a run keep their completion order.
func (r *restartTracker) takeAll() []*heldRestart {
	rows := make([]*heldRestart, 0, len(r.held))
	for tid, held := range r.held {
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
// loop has to do with the record.
func (h *heldRestart) step(direction rawEventDirection, ev runtimeDecodedEvent) restartAction {
	if rec, ok := ev.(*types.SyscallRestartEvent); ok {
		return h.stepRestartRecord(rec)
	}
	switch h.phase {
	case restartWaiting:
		if h.isRestartSyscallEnter(direction, ev) {
			h.phase = restartContinuing
			return restartKeepEnter
		}
	case restartInHandler:
		return h.stepHandlerRecord(direction, ev)
	case restartResumed:
		if h.isReexecutedEnter(direction, ev) {
			h.phase = restartContinuing
			return restartKeepEnter
		}
	case restartContinuing:
		return h.stepContinuation(direction, ev)
	}
	return restartRelease
}

// stepRestartRecord applies a control record of the restart-fold probes. Only
// a row interrupted with a re-execution code takes one; a -516 row's
// continuation is restart_syscall, so a record for it is a stray and
// releases the row like any other unexpected record.
func (h *heldRestart) stepRestartRecord(rec *types.SyscallRestartEvent) restartAction {
	ret, _ := restartRetOf(h.pair)
	if !event.IsReexecutedRestartRet(ret) {
		return restartRelease
	}
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

// isRestartSyscallEnter reports whether ev is the restart_syscall enter that
// resumes a -516 row.
func (h *heldRestart) isRestartSyscallEnter(direction rawEventDirection, ev runtimeDecodedEvent) bool {
	enterEv, ok := ev.(event.Event)
	return ok && direction == rawEnterEvent && !h.reexecuted() &&
		enterEv.GetTraceId() == types.SYS_ENTER_RESTART_SYSCALL
}

// isReexecutedEnter reports whether ev is the enter the RESUME record
// announced: an enter of the held row's own syscall that carries the RESUME
// record's time. BPF stamps both with one clock read (ior_restart_on_enter in
// internal/c/restart.c), and the announced enter may never arrive - sampled
// out, or refused by a full ring buffer - so the syscall alone does not
// identify it: the tid's next call of that syscall would pass too, and a
// stranger's result would be folded into the row. A later enter has a later
// time (a clock too coarse to tell two enters of one thread apart is the one
// exception, see "A time rule that cannot tell" under "Known wrong folds" in
// restart.c).
func (h *heldRestart) isReexecutedEnter(direction rawEventDirection, ev runtimeDecodedEvent) bool {
	enterEv, ok := ev.(event.Event)
	return ok && direction == rawEnterEvent && enterEv.GetTraceId() == h.pair.EnterEv.GetTraceId() &&
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
// parked again first, then the record goes its usual way. Records of tids
// without a held row cost one length check. rawEvent is the registered kind
// ev was decoded as.
//
// The row is found by the record's own tid. The one record that settles a row
// held under another tid, the exec record of a non-leader thread, does so in
// its control handler (releaseExecCallerRestart).
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
	if e.restartProofLost(held, action) {
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
	e.releaseHeldRestart(tid, ch)
	return false
}

// restartProofLost reports whether a step towards a re-execution fold must be
// refused because the kernel dropped records since the interrupted exit (see
// "Lost records" in the file comment and restartDropWatch). It is asked at
// the two steps that commit: RESUME, where a refusal releases the row before
// the re-executed enter is taken, and the continuation's exit, where it keeps
// a result that may belong to another call out of the row. Either way the
// call ends up as two rows, the interrupted one and the re-execution: at the
// exit, the release parks the enter taken for the fold again and the exit
// pairs with it. Each question is one read of the drop counter, paid only by
// interrupted calls. The restart_syscall fold is not asked: it does
// not depend on a control record, and its tid's very next records are the
// whole proof.
func (e *eventLoop) restartProofLost(held *heldRestart, action restartAction) bool {
	if action != restartResume && action != restartFold {
		return false
	}
	if !held.reexecuted() {
		return false
	}
	return e.restarts.drops.lostSince(held.pair.ExitEv.GetTime(), e.dropSrc, e.readDropStampClock)
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
// follows then pairs with it like any other.
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

// dropContinuation recycles the continuation's enter once the fold that took
// it is accepted. The field is cleared first, so the enter can never be both
// recycled here and parked again by a later release of the same row (a fold
// that ended in a restart code keeps the heldRestart).
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
// released, never held, or evicted) or has done its work, so it is recycled.
func (e *eventLoop) handleSyscallRestartEvent(ev *types.SyscallRestartEvent) {
	ev.Recycle()
}

// foldReexecutedRestarts tells the loop whether BPF proves re-executions for
// this run (trace setup, before the loop starts). Three things have to hold,
// and without any of them the rows are not held at all and stay exactly as
// they were:
//
//   - the signal_deliver probe attached, so every handler delivered to an
//     interrupted task is seen and a RESUME record means what it says.
//     Without it a RESUME record would also precede a program's own retry
//     after EINTR.
//   - the sched_process_exit probe attached, so BPF forgets a task that dies
//     with a call pending (ior_restart_forget). Without it a later task with
//     the recycled tid would inherit the entry and its first syscall would be
//     announced as the dead task's re-execution.
//   - the drop counter can be read (dropSrc), so a fold can be refused when
//     records were lost while the row was held (restartProofLost).
func (e *eventLoop) foldReexecutedRestarts(signalProbeAttached, exitProbeAttached bool) {
	e.restarts.reexec = signalProbeAttached && exitProbeAttached && e.dropSrc != nil
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

// releaseTakenRestartSafe releases one held row at the end of the run, turning
// a panic in its exit handler into a warning.
func (e *eventLoop) releaseTakenRestartSafe(held *heldRestart, pairs chan<- *event.Pair) {
	defer func() {
		if r := recover(); r != nil {
			e.notifyWarning(fmt.Sprintf("Recovered panic releasing a held restart row: %v", r))
		}
	}()
	e.releaseTakenRestart(held, pairs)
}
