package internal

import (
	"ior/internal/event"
	"ior/internal/types"
)

// completeNoReturnEnter turns the enter of a noreturn syscall (exit,
// exit_group, rt_sigreturn; types.TraceId.NoReturn) into a complete row at
// once (task pr2).
//
// These syscalls never return to their caller, so no sys_exit record ever
// arrives for them: the generator emits no exit handler (isNoreturnSyscall in
// internal/generate/codegen.go), and for rt_sigreturn the kernel would not
// fire one anyway (restore_sigcontext sets orig_ax to -1). Parking the enter
// like any other, as storeEnter used to, meant a run tracing them got no row
// at all: the enter sat in the pair tracker until the tid's next enter
// superseded it, the LRU trimmed it, or sched_process_exit evicted it - or,
// when the next enter was lost, an unrelated exit consumed it and was counted
// as a spurious mismatch.
//
// The enter is the whole observable event, so it is the row. The pair gets a
// synthetic exit (noReturnExit) at the enter's own timestamp, which yields a
// Duration of 0 and no return value, and Pair.NoReturn tells the consumers
// that this 0 is "no latency" rather than a measurement. Everything else runs
// exactly as for a paired exit, so the row honours every filter dimension
// (handleTracepointExit ends in finishPair), counts once in numSyscalls and,
// when kept, in numSyscallsAfterFilter, and advances the tid's gap baseline:
// the next syscall of a thread that returned from a signal handler measures
// its gap from the rt_sigreturn, which is when the thread resumed.
//
// Kernel-side the hook ior_on_noreturn_syscall_enter writes no
// syscall_enter_state_map entry, so nothing leaks there, and counts the
// enters it does not emit (sampling) untimed in the aggregate map, so the
// stream and the aggregate keep partitioning the invocations.
func (e *eventLoop) completeNoReturnEnter(enterEv event.Event, ch chan<- *event.Pair) {
	tid := enterEv.GetTid()
	e.queueCommLookup(tid)
	e.dropSupersededEnter(tid)

	ep := event.NewPair(enterEv)
	ep.ExitEv = noReturnExit(enterEv)
	ep.NoReturn = true
	e.numSyscalls++

	e.applyDerivedPairValues(ep)
	if !e.handleTracepointExit(ep) {
		return
	}
	e.finalizeTracepointPair(ep)
	sendPair(ch, ep)
}

// dropSupersededEnter recycles an enter still parked under tid. A task that
// enters a syscall is at the syscall boundary, so whatever enter it left
// parked lost its exit record and can never pair any more; storeEnter's
// pairTracker.set recycles it for the same reason when the next enter is
// parked. A noreturn enter is not parked, so it has to do that itself, or the
// stale enter would outlive the row - for exit/exit_group until the
// sched_process_exit eviction, for rt_sigreturn until the thread's next enter.
func (e *eventLoop) dropSupersededEnter(tid uint32) {
	if stale, ok := e.pairs.consume(tid); ok && stale != nil {
		stale.Recycle()
	}
}

// noReturnExit builds the stand-in exit event of a noreturn pair: a
// *types.NullEvent, which carries no ret field (it is not an
// event.RetCarrier), stamped with the enter's time, pid and tid. Its trace ID
// is the enter's minus one, the ID the kernel gives the syscall's sys_exit
// tracepoint, so the pair keeps the enter/exit ID relation tracepointExited
// checks for real pairs. Pair.Recycle hands it to the NullEvent pool like a
// decoded one.
func noReturnExit(enterEv event.Event) *types.NullEvent {
	return &types.NullEvent{
		EventType: types.EXIT_NULL_EVENT,
		TraceId:   enterEv.GetTraceId() - 1,
		Time:      enterEv.GetTime(),
		Pid:       enterEv.GetPid(),
		Tid:       enterEv.GetTid(),
	}
}
