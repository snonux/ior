package internal

import "strconv"

// traceTarget is what a headless run follows and ends with (tasks vr2, os2):
// the -tid thread when one is given, otherwise the -pid process. Everything
// that decides "the target is gone" (the exit-record trigger, the liveness
// watch, the status line) works from this one value, so the two flags cannot
// be interpreted differently in different places.
//
// -tid wins over -pid because it is the narrower scope: with both given
// (-pid P -tid T, T a thread of P) the run follows T. P's death ends T too,
// so nothing is lost by not following P as well.
type traceTarget struct {
	id     int  // the tid (thread) or tgid (process), always > 0
	thread bool // id is a thread id: only that one task ends the run
}

// newTraceTarget resolves the -pid and -tid filter values (<= 0: not set)
// into the target of a headless run. ok is false when neither is set, which
// leaves the run without a target to end with.
func newTraceTarget(pid, tid int) (target traceTarget, ok bool) {
	switch {
	case tid > 0:
		return traceTarget{id: tid, thread: true}, true
	case pid > 0:
		return traceTarget{id: pid}, true
	}
	return traceTarget{}, false
}

// kind names what the target is, for status lines and comments.
func (t traceTarget) kind() string {
	if t.thread {
		return "thread"
	}
	return "process"
}

// String is "thread 42" or "process 42".
func (t traceTarget) String() string {
	return t.kind() + " " + strconv.Itoa(t.id)
}
