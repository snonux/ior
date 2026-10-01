package internal

import (
	"cmp"
	"fmt"
	"slices"

	"ior/internal/event"
	"ior/internal/types"
)

// Folding restart_syscall into the call it resumes (task fs2).
//
// A signal that interrupts a blocked nanosleep, clock_nanosleep, poll or a
// timed futex wait makes it exit with -ERESTART_RESTARTBLOCK (-516). When no
// handler runs (SIGSTOP/SIGCONT, a ptrace or freezer stop), the kernel does
// not re-execute the call: it re-enters the task through restart_syscall,
// which finishes the same call from the restart block (for a relative sleep,
// against the original absolute expiry). ior used to show that as two or more
// rows - "clock_nanosleep ret=-516" and "restart_syscall ret=0", the latter
// without the requested sleep - for one call the program made once.
//
// What is folded, and why only that. restart_syscall can only resume a -516:
// the kernel sets it up in exactly that case, and only when no handler runs
// (a handled signal turns -516 into EINTR and the next record of the tid is
// the handler's work or its rt_sigreturn, never restart_syscall). So a -516
// row whose tid's very next record is a restart_syscall enter is provably the
// same call. The other restart codes (-512/-513/-514) are restarted by
// re-executing the original syscall, and a sys_enter of the same syscall
// cannot be told apart from a program that saw EINTR and retried by itself
// (the Go runtime and many C loops do exactly that); ior has no record of
// whether a handler ran. Those rows stay unfolded (follow-up task).
//
// The decision rules:
//
//   - Hold: a pair whose exit is a *types.RetEvent with ret -516 is parked
//     here instead of being completed (tracepointExited). Its exit handler,
//     derived values and pair filter all wait for the outcome. At most
//     maxHeldRestarts rows are held; beyond that a -516 row is completed at
//     once, unfolded.
//   - Resume: the held tid's next record is a restart_syscall enter. The
//     enter is consumed (no row, no raw enter filter: the decision must not
//     depend on whether this run would show restart_syscall).
//   - Fold: the resumed tid's next record is the restart_syscall exit. Its
//     return value and time replace the held exit's; the exit keeps the
//     original syscall's trace ID, so the row is still the original call.
//     A fold that ends in -516 again (stopped twice) is held again.
//   - Release: any other record of the held tid (any enter, a non-restart
//     exit, a control record such as the task's exit, a fresh task with
//     the recycled tid) first completes the held row unchanged, then is
//     processed normally. At the end of the run every held row is completed
//     too (releaseAllHeldRestarts). No row is lost: a held row is either
//     folded or emitted as it was.
//
// How the folded row looks: the original enter (name, arguments, requested
// sleep, enter time, gap to the previous row) with the final return value
// and exit time. Its latency is the whole wall-clock span from the
// interrupted enter to the final exit, stopped time included: that is how
// long the program was inside the call ("asked to sleep 2s, the call took
// 2.0s"), and a relative sleep resumed by restart_syscall still ends at the
// original deadline, so a short stop does not lengthen it at all. The sum of
// the separate pieces would hide the stop and is not a time the kernel or
// the program knows. The raw -516 is gone from the folded row (ret is what
// the call finally returned); a row still showing -516 is one that was not
// resumed (a handled signal, i.e. EINTR, or the end of the trace).
//
// Counting: numSyscalls counts the call once (at its first exit; the
// restart_syscall exit is not counted again), the pair filter and every
// consumer (stats engine, Parquet, CSV, flamegraph) see one row. Kernel-side
// aggregates (aggregate-only syscalls, sampled-out invocations) are counted
// by BPF per invocation and are not folded.
//
// Output order: rows are emitted when the call completes, as always. A held
// row is delayed until its tid's next record; for a folded call that is its
// real completion, and for a row released unchanged (the handled-signal
// case) it is the handler's first syscall, typically microseconds later.
// Rows of other tids emitted meanwhile may therefore precede it although
// they exited later.
type restartTracker struct {
	held map[uint32]heldRestart // keyed by tid
}

// heldRestart is one interrupted row waiting for its continuation.
type heldRestart struct {
	pair *event.Pair
	// resumed is set once the tid's restart_syscall enter arrived: the next
	// record of the tid should be its exit, which completes the fold.
	resumed bool
}

// maxHeldRestarts bounds the rows held at once. A held row normally lives
// for one stop of one thread; the bound only matters when the records that
// would release rows are lost (ring-buffer backpressure), and then it keeps
// the map from growing with dead tids. Rows beyond it are emitted unfolded.
const maxHeldRestarts = 4096

// hold parks ep when its exit is -ERESTART_RESTARTBLOCK and reports whether
// it did. The caller must not touch ep afterwards when it returns true.
func (r *restartTracker) hold(ep *event.Pair) bool {
	retEv, ok := ep.ExitEv.(*types.RetEvent)
	if !ok || !event.IsRestartBlockRet(retEv.Ret) || len(r.held) >= maxHeldRestarts {
		return false
	}
	if r.held == nil {
		r.held = make(map[uint32]heldRestart)
	}
	r.held[retEv.Tid] = heldRestart{pair: ep}
	return true
}

// lookup returns the row tid holds, if any.
func (r *restartTracker) lookup(tid uint32) (heldRestart, bool) {
	held, ok := r.held[tid]
	return held, ok
}

// markResumed records that tid's restart_syscall enter arrived.
func (r *restartTracker) markResumed(tid uint32) {
	if held, ok := r.held[tid]; ok {
		held.resumed = true
		r.held[tid] = held
	}
}

// take removes and returns the row tid holds.
func (r *restartTracker) take(tid uint32) (*event.Pair, bool) {
	held, ok := r.held[tid]
	if !ok {
		return nil, false
	}
	delete(r.held, tid)
	return held.pair, true
}

// takeAll removes every held row and returns them oldest exit first, so the
// rows released at the end of a run keep their completion order.
func (r *restartTracker) takeAll() []*event.Pair {
	pairs := make([]*event.Pair, 0, len(r.held))
	for tid, held := range r.held {
		pairs = append(pairs, held.pair)
		delete(r.held, tid)
	}
	slices.SortFunc(pairs, func(a, b *event.Pair) int {
		return cmp.Compare(a.ExitEv.GetTime(), b.ExitEv.GetTime())
	})
	return pairs
}

// tidRecord is what every decoded record that belongs to a task offers:
// syscall events and the control records alike carry the task's tid.
type tidRecord interface {
	GetTid() uint32
}

// routeHeldRestart applies the decision rules above to one decoded record
// before it is processed, and reports whether the fold consumed the record
// (the restart_syscall enter or exit of a held row), in which case the
// caller must not process it further. A record that releases the held row
// is not consumed: the row is completed (and sent on ch) first, then the
// record goes its usual way. Records of tids without a held row cost one
// length check.
func (e *eventLoop) routeHeldRestart(direction rawEventDirection, ev runtimeDecodedEvent, ch chan<- *event.Pair) bool {
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
	switch restartContinuation(direction, ev, held.resumed) {
	case types.SYS_ENTER_RESTART_SYSCALL:
		e.restarts.markResumed(tid)
		ev.Recycle()
		return true
	case types.SYS_EXIT_RESTART_SYSCALL:
		e.foldRestartExit(ev.(*types.RetEvent), ch)
		return true
	}
	e.releaseHeldRestart(tid, ch)
	return false
}

// restartContinuation returns the restart_syscall trace ID ev stands for when
// it is the next step of a held row's fold - its enter while the row waits to
// be resumed, its exit (a RetEvent, which the fold needs) once resumed - and
// 0 for any other record, which releases the row.
func restartContinuation(direction rawEventDirection, ev runtimeDecodedEvent, resumed bool) types.TraceId {
	syscallEv, ok := ev.(event.Event)
	if !ok {
		return 0
	}
	switch {
	case direction == rawEnterEvent && !resumed &&
		syscallEv.GetTraceId() == types.SYS_ENTER_RESTART_SYSCALL:
		return types.SYS_ENTER_RESTART_SYSCALL
	case direction == rawExitEvent && resumed &&
		syscallEv.GetTraceId() == types.SYS_EXIT_RESTART_SYSCALL:
		if _, isRet := ev.(*types.RetEvent); isRet {
			return types.SYS_EXIT_RESTART_SYSCALL
		}
	}
	return 0
}

// foldRestartExit completes a fold: the held row takes the restart_syscall
// exit's return value and time, and is completed - or held again when the
// continuation was interrupted by another stop (-516 once more).
func (e *eventLoop) foldRestartExit(restartExit *types.RetEvent, ch chan<- *event.Pair) {
	ep, _ := e.restarts.take(restartExit.Tid)
	// hold only parks pairs whose exit is a *types.RetEvent.
	heldExit := ep.ExitEv.(*types.RetEvent)
	heldExit.Ret = restartExit.Ret
	heldExit.Time = restartExit.Time
	restartExit.Recycle()
	if e.restarts.hold(ep) {
		return
	}
	e.completeTracepointPair(ep, ch)
}

// releaseHeldRestart completes the row tid holds unchanged, if any: the record
// that triggered it shows that no restart_syscall resumes the call.
func (e *eventLoop) releaseHeldRestart(tid uint32, ch chan<- *event.Pair) {
	if ep, ok := e.restarts.take(tid); ok {
		e.completeTracepointPair(ep, ch)
	}
}

// releaseAllHeldRestarts completes every row still held when the event loop
// stops, so a call interrupted near the end of the trace (or in a task that is
// still stopped) is emitted as it was rather than lost. Each row is emitted
// before the next is completed: pairs has room for one record's pairs only.
// It runs outside processRawEventSafe, so each completion recovers a handler
// panic the same way: one bad row must not cost the others.
func (e *eventLoop) releaseAllHeldRestarts(pairs chan *event.Pair) {
	if len(e.restarts.held) == 0 {
		return
	}
	for _, ep := range e.restarts.takeAll() {
		e.completeHeldRestartSafe(ep, pairs)
		e.drainPairs(pairs)
	}
}

// completeHeldRestartSafe completes one held row released at the end of the
// run, turning a panic in its exit handler into a warning.
func (e *eventLoop) completeHeldRestartSafe(ep *event.Pair, pairs chan<- *event.Pair) {
	defer func() {
		if r := recover(); r != nil {
			e.notifyWarning(fmt.Sprintf("Recovered panic releasing a held restart row: %v", r))
		}
	}()
	e.completeTracepointPair(ep, pairs)
}
