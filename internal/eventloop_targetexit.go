package internal

import (
	"context"
	"time"

	"ior/internal/types"
)

// targetWatchInterval is how often the liveness watcher checks the -pid
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
// The trigger is any sched_process_exit record whose tid is the -tid filter,
// whatever its group_dead flag says (including the legacy record with an
// unknown flag, which still carries the tid): the record is the thread's own
// do_exit, so after it the thread can never issue another syscall. The BPF
// side forwards exactly these records (filter() admits the traced tid), so no
// BPF change is needed. A match cannot be a recycled tid: a recycled tid can
// only exist after the original exited, and that exit already ended the run
// (the liveness watcher's start-time snapshot covers a death before the probes
// attached).
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
//     do_exit, the traced one included, so its record ends the run too. The
//     group-dead record that the -tid bypass forwards from another thread
//     (ior_process_exit_in_scope) is not needed as a trigger and is not used.
//   - An execve in a non-leader thread renames it to the leader's tid and
//     reaps the old leader; the original tid then has no record, and the
//     liveness watcher (its /proc entry vanished) ends the run instead.
//
// Runs on the event-loop goroutine only, after the exit's state was retired.
func (e *eventLoop) endTraceOnTargetThreadExit(ev *types.ProcessExitEvent) {
	if !e.stopOnTargetExit {
		return
	}
	if e.cfg.tidFilter <= 0 || ev.Tid != uint32(e.cfg.tidFilter) {
		return
	}
	e.targetExited(traceTarget{id: int(ev.Tid), thread: true})
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
