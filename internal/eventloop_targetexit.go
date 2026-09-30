package internal

import "ior/internal/types"

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
// Tea would bypass its lifecycle. -tid is deliberately not covered: the
// traced thread ending does not end the process, and a whole-process death
// under -tid is not tied to a pid the user named (follow-up task).
//
// It runs on the event-loop goroutine only, and fires once: a later record
// for the same pid (a recycled pid dying, or a late duplicate) must not
// cancel twice or repeat the status line.
func (e *eventLoop) endTraceOnTargetExit(ev *types.ProcessExitEvent) {
	if !e.stopOnTargetExit || e.targetExitSeen {
		return
	}
	if e.cfg.pidFilter <= 0 || ev.Pid != uint32(e.cfg.pidFilter) {
		return
	}
	e.targetExitSeen = true
	e.notifyStatus("Traced process", ev.Pid, "exited, stopping the trace")
	if e.stopTrace != nil {
		e.stopTrace()
	}
}
