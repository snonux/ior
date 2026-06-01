package integrationtests

import "testing"

// miscTraceArgs restricts tracing to the Misc-family syscalls the misc-basic
// workload issues, so the captured output is dominated by those calls.
// Note: the tracer names the uname tracepoint after the underlying kernel
// syscall sys_newuname, i.e. "newuname" (not "uname"). vmsplice and alarm are
// issued too, but the must-haves below are the three pure-read calls whose
// tracepoints are guaranteed to fire deterministically.
var miscTraceArgs = []string{
	"-trace-syscalls",
	"getcpu,newuname,sysinfo,vmsplice,alarm",
}

// TestMiscBasic verifies the Misc syscall family is traced end-to-end. The
// misc-basic workload issues getcpu, uname (sys_newuname), sysinfo, vmsplice
// (into a self-drained pipe), and alarm(0) — all unprivileged, non-blocking,
// and free of global side effects. Each required syscall must appear as an
// enter event attributed to the ioworkload process.
func TestMiscBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("misc-basic", defaultDuration, miscTraceArgs)
	if err != nil {
		t.Fatalf("run scenario misc-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_getcpu", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_newuname", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_sysinfo", Comm: "ioworkload", MinCount: 1},
	})
}
