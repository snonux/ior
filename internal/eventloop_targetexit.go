package internal

import (
	"context"
	"time"

	"ior/internal/types"
)

// targetWatchInterval is how often the liveness watcher checks the -pid / -tid
// target: short enough that a dead target ends the run promptly, long enough
// that a pidfd poll or one /proc/<pid>/stat read is free.
const targetWatchInterval = 500 * time.Millisecond

// exitTarget is what this loop's headless run ends with: the -tid thread,
// else the -pid process (traceTarget); ok is false without either filter.
func (e *eventLoop) exitTarget() (traceTarget, bool) {
	return newTraceTarget(e.cfg.pidFilter, e.cfg.tidFilter)
}

// endTraceOnTargetExit ends a headless -pid trace once the traced process is
// gone (task vr2). Before this the loop only counted the group-dead record of
// the -pid target and kept probing until -duration (900s by default, so a
// `ior -plain -pid N` whose N had exited idled for fifteen minutes), and the
// kernel may hand the freed pid to an unrelated process in the meantime,
// which the still-armed PID filter would then trace as if it were the target.
// strace -p and perf record -p end with their target for the same reasons.
//
// The trigger is the deduplicated group-dead sched_process_exit record of the
// process whose tgid is the -pid filter (applyProcessDeath calls this after
// the duplicate check). Only that record proves the whole process died: a
// thread exit, the legacy 24-byte record whose group_dead flag is unknown
// (IsGroupDeadKnown false), and an exit of any other pid all leave the trace
// running. The ring buffer is ordered, so every event the target produced
// before dying has been handled by the time its exit record is; cancelling
// the trace context here loses none of them, and the normal shutdown path
// then drains, prints the statistics and finalises the recording.
//
// It is armed per loop (stopOnTargetExit, set by runTraceLoop for the
// headless modes only). The TUI keeps its own contract: a session outlives a
// dead target so the collected data stays on screen, the picker reports
// "pid N exited - pick a process", and ending the session from under Bubble
// Tea would bypass its lifecycle.
//
// -pid P with -tid T ends on P's group-dead record here too; the thread rule
// (endTraceOnTargetThreadExit) ends it earlier, when T itself exits. -tid
// alone is that thread rule only.
//
// A single ring record is a fragile trigger: one lost to ring-buffer
// backpressure never ends the run, and a target that dies while ior is still
// attaching its probes (about five seconds) never produces one. The liveness
// watcher (watchTargetLiveness) is the fallback for both and reaches the same
// stop through targetExited.
//
// It runs on the event-loop goroutine only.
func (e *eventLoop) endTraceOnTargetExit(ev *types.ProcessExitEvent) {
	if !e.stopOnTargetExit {
		return
	}
	if e.cfg.pidFilter <= 0 || ev.Pid != uint32(e.cfg.pidFilter) {
		return
	}
	e.targetExited(traceTarget{id: int(ev.Pid)})
}

// endTraceOnTargetThreadExit ends a headless -tid trace when the traced
// thread itself exits (task os2), the -tid counterpart of
// endTraceOnTargetExit: strace -p TID likewise follows one task and ends with
// it. Before this a -tid run whose thread (or whole process) had died idled
// to -duration, and a recycled tid or pid was then traced under the old
// filter.
//
// The trigger is a sched_process_exit record whose tid is the -tid filter,
// whatever its group_dead flag says (including the legacy record with an
// unknown flag, which still carries the tid): the record is the thread's own
// do_exit, so after it the thread can never issue another syscall. The BPF
// side forwards exactly these records (filter() admits the traced tid). The
// one exception is a record flagged TidInherited (see below): its task died,
// but its tid did not.
//
// Kernel semantics decided here:
//   - A non-leader thread: the run ends when that thread exits, while its
//     process may live on. The same holds for -pid P -tid T.
//   - The thread-group leader (-tid equal to the pid): the leader's own
//     do_exit fires its record even while sibling threads run on (it stays a
//     zombie until they are gone, but it executes nothing more), so the run
//     ends when the leader thread exits, not when the process does. That is
//     the meaning of a thread filter, and the siblings' records were never in
//     scope. strace -p LEADER waits for the whole group; ior does not, because
//     the events it traces for the leader stop at that point.
//   - Whole-process death (exit_group, a fatal signal): every thread runs
//     do_exit, the traced one included, so its record ends the run too.
//   - A non-leader thread of a -tid <leader> process calls execve: de_thread
//     kills the old leader, whose record carries the leader's tid, but the
//     exec'ing thread then takes over that tid and its start time and runs on
//     as the new program. The BPF tid filter keeps tracing it, the liveness
//     watch follows it too (the pidfd and /proc/<tid> refer to the inheriting
//     task, the start time matches), and strace -p keeps tracing it, so the
//     run continues and ends when the new program exits. The BPF handler
//     marks that record (IOR_EXIT_TID_INHERITED, from signal->group_exec_task
//     being another thread) and it is skipped here. Should the exec'ing
//     thread be killed in de_thread instead, the whole process dies and the
//     group-dead record of the leader's process (forwarded by the -tid
//     bypass, ior_process_exit_in_scope) ends the run: for a leader target a
//     group-dead record of tgid == -tid means whichever task held the tid is
//     gone. For a non-leader target no tgid equals the tid, so that record
//     never matches; its own record precedes it anyway.
//   - -tid <non-leader> when that thread calls execve: it takes the leader's
//     tid and its own tid ends without a record of its own; the liveness
//     watcher (the /proc entry vanished, the pidfd turned readable) ends the
//     run, since the BPF filter no longer matches the program's new tid.
//
// Tid reuse: a matching record cannot be a recycled tid. A recycled tid only
// exists once the original task is gone, and that end already stopped the
// run: through its own record, through the group-dead record above, or
// through the liveness watch, whose start-time snapshot also catches a death
// (and reuse) before the probes attached. A flagged record does not free the
// tid (the exec'ing task holds it), so skipping it opens no reuse window.
//
// Runs on the event-loop goroutine only, after the exit's state was retired.
func (e *eventLoop) endTraceOnTargetThreadExit(ev *types.ProcessExitEvent) {
	if !e.stopOnTargetExit || e.cfg.tidFilter <= 0 {
		return
	}
	tid := uint32(e.cfg.tidFilter)
	ownExit := ev.Tid == tid && !ev.TidInherited()
	leaderProcessDied := ev.Pid == tid && ev.IsGroupDead()
	if !ownExit && !leaderProcessDied {
		return
	}
	e.targetExited(traceTarget{id: e.cfg.tidFilter, thread: true})
}

// targetExited stops the trace because the target is gone, announcing it on
// the status sink. It is the one place all triggers (the group-dead record,
// the traced thread's exit record and the liveness watcher) go through and
// fires once: a later record for the same pid (a recycled pid dying, or a late
// duplicate) or the watcher noticing the same death must not cancel twice or
// repeat the status line. Safe to call from any goroutine.
func (e *eventLoop) targetExited(target traceTarget) {
	if !e.targetExitSeen.CompareAndSwap(false, true) {
		return
	}
	e.notifyStatus("Traced", target.String(), "exited, stopping the trace")
	if e.stopTrace != nil {
		e.stopTrace()
	}
}

// watchTargetLiveness is the fallback trigger for a headless -pid / -tid run:
// it asks gone every interval (and once right away, since the target may have
// died while the probes were attaching) and ends the trace through
// targetExited when the target is gone or its id was recycled (see
// targetWatch.gone). It returns when ctx ends or after it fired. gone is
// injectable so tests need no real process.
func (e *eventLoop) watchTargetLiveness(ctx context.Context, interval time.Duration, gone func() bool) {
	target, ok := e.exitTarget()
	if !ok || gone == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// ctx is checked before every poll so that a trace already ending for
	// another reason (signal, -duration) does not claim the target died.
	for ctx.Err() == nil {
		if gone() {
			e.targetExited(target)
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}
