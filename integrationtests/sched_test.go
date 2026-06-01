package integrationtests

import "testing"

// schedTraceArgs restricts tracing to the Sched-family syscalls the sched-basic
// workload issues, so the captured output is dominated by those calls. The
// tracer names each tracepoint after the underlying kernel syscall, so the
// names below match the sched_* syscall names verbatim. sched_setscheduler and
// sched_setattr are intentionally absent: the scenario never invokes them (they
// would require CAP_SYS_NICE and would disrupt real-time scheduling).
var schedTraceArgs = []string{
	"-trace-syscalls",
	"sched_yield,sched_getaffinity,sched_setaffinity,sched_getscheduler,sched_getparam,sched_getattr,sched_get_priority_max,sched_get_priority_min,sched_rr_get_interval",
}

// TestSchedBasic verifies the Sched syscall family is traced end-to-end. The
// sched-basic workload self-targets every call (pid 0 == the calling thread,
// pinned with LockOSThread): it yields once, reads its CPU affinity mask and
// re-applies the IDENTICAL mask (a byte-for-byte no-op), then queries — but
// never modifies — its scheduling policy, parameters, extended attributes,
// priority range, and round-robin interval. Nothing alters the process's
// scheduling state, so the calls are safe and unprivileged. Each required
// syscall must appear as an enter event attributed to the ioworkload process.
func TestSchedBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("sched-basic", defaultDuration, schedTraceArgs)
	if err != nil {
		t.Fatalf("run scenario sched-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_sched_yield", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sched_getaffinity", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sched_getscheduler", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sched_getparam", Comm: "ioworkload", MinCount: 1},
	})
}
