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
// -tid: with -pid P and -tid T together, pidFilter is P (> 0), so the run DOES
// end on P's group-dead record, although T is what is being traced. -tid alone
// (no -pid) is not covered here: the traced thread ending does not end the
// process, and whole-process death is not tied to a pid the user named; the
// follow-up task os2 covers it.
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
	e.targetExited(ev.Pid)
}

// targetExited stops the trace because the -pid target is gone, announcing it
// on the status sink. It is the one place both triggers (the group-dead record
// and the liveness watcher) go through and fires once: a later record for the
// same pid (a recycled pid dying, or a late duplicate) or the watcher noticing
// the same death must not cancel twice or repeat the status line. Safe to call
// from any goroutine.
func (e *eventLoop) targetExited(pid uint32) {
	if !e.targetExitSeen.CompareAndSwap(false, true) {
		return
	}
	e.notifyStatus("Traced process", pid, "exited, stopping the trace")
	if e.stopTrace != nil {
		e.stopTrace()
	}
}

// watchTargetLiveness is the fallback trigger for a headless -pid run: it asks
// gone every interval (and once right away, since the target may have died
// while the probes were attaching) and ends the trace through targetExited
// when the target is gone or its pid was recycled (see targetWatch.gone). It
// returns when ctx ends or after it fired. gone is injectable so tests need
// no real process.
func (e *eventLoop) watchTargetLiveness(ctx context.Context, interval time.Duration, gone func() bool) {
	pid := e.cfg.pidFilter
	if pid <= 0 || gone == nil {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// ctx is checked before every poll so that a trace already ending for
	// another reason (signal, -duration) does not claim the target died.
	for ctx.Err() == nil {
		if gone() {
			e.targetExited(uint32(pid))
			return
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}
