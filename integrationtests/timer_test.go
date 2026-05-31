package integrationtests

import "testing"

// posixTimerTraceArgs restricts tracing to the POSIX timer-family syscalls so
// the test output is dominated by the lifecycle calls the workload issues.
// Note: timerfd_create is intentionally NOT in this list — it belongs to the
// IPC/eventfd family and returns an fd, whereas timer_create returns a timer_t
// through an output pointer (a null_event in the tracer).
var posixTimerTraceArgs = []string{
	"-trace-syscalls",
	"timer_create,timer_settime,timer_gettime,timer_getoverrun,timer_delete,timerfd_create",
}

// TestPosixTimerLifecycle verifies the POSIX per-process timer family is traced
// end-to-end. The workload runs timer_create -> timer_settime -> timer_gettime
// -> timer_getoverrun -> timer_delete; each must appear as an enter event.
func TestPosixTimerLifecycle(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("posix-timer-lifecycle", defaultDuration, posixTimerTraceArgs)
	if err != nil {
		t.Fatalf("run scenario posix-timer-lifecycle: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_timer_create", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_timer_settime", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_timer_gettime", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_timer_getoverrun", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_timer_delete", Comm: "ioworkload", MinCount: 1},
	})

	// timer_create is a null_event: it must NOT capture an fd-style path the way
	// the fd-returning siblings do. In particular it must not be confused with
	// timerfd_create, whose records carry a "timerfd:" descriptor path. Guard
	// against that regression: no timer_create record should have a timerfd path.
	if got := totalTracepointPathCount(result, "enter_timer_create", "timerfd:"); got != 0 {
		t.Fatalf("enter_timer_create records with a timerfd: descriptor path = %d, want 0; "+
			"timer_create returns a timer_t, not an fd, and must not be classified like timerfd_create", got)
	}
}
