package integrationtests

import "testing"

// priorityTraceArgs restricts tracing to the two priority-family syscalls the
// priority-basic workload issues. The tracer names each tracepoint after the
// underlying kernel syscall, so the names below match the syscall names
// verbatim.
var priorityTraceArgs = []string{"-trace-syscalls", "getpriority,setpriority"}

// TestPriorityBasic verifies the getpriority/setpriority pair is traced
// end-to-end. The priority-basic workload self-targets both calls
// (PRIO_PROCESS, who 0 == the calling process): it reads the current nice value
// with getpriority and re-applies the IDENTICAL value with setpriority (a
// byte-for-byte no-op), so the process's priority is never altered and no
// privilege is required. Both syscalls classify as FamilyProcess with a KindNull
// enter (PRIO_PROCESS is an opcode, not an fd) and an UNCLASSIFIED return (the
// value is a nice value, not a byte count), so asserting the enter tracepoints
// appear — attributed to the ioworkload process — is the right end-to-end check.
func TestPriorityBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("priority-basic", defaultDuration, priorityTraceArgs)
	if err != nil {
		t.Fatalf("run scenario priority-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_getpriority", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_setpriority", Comm: "ioworkload", MinCount: 1},
	})
}

// ioprioTraceArgs restricts tracing to the two I/O-priority syscalls the
// ioprio-basic workload issues. Each tracepoint is named after the underlying
// kernel syscall, so the names below match verbatim.
var ioprioTraceArgs = []string{"-trace-syscalls", "ioprio_get,ioprio_set"}

// TestIoprioBasic verifies the ioprio_get/ioprio_set pair (the I/O-priority
// analogues of getpriority/setpriority) is traced end-to-end. The ioprio-basic
// workload self-targets both calls (IOPRIO_WHO_PROCESS, who 0 == the calling
// process): it reads the current I/O priority with ioprio_get and re-applies it
// (or a harmless best-effort default when none is set) with ioprio_set, so no
// other process is affected and no privilege is required. Both syscalls classify
// as FamilyProcess with a KindNull enter (IOPRIO_WHO_PROCESS is an opcode, not an
// fd) and an UNCLASSIFIED return (the value is an I/O-priority word, not a byte
// count), so asserting the enter tracepoints appear — attributed to the
// ioworkload process — is the right end-to-end check.
func TestIoprioBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("ioprio-basic", defaultDuration, ioprioTraceArgs)
	if err != nil {
		t.Fatalf("run scenario ioprio-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_ioprio_get", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_ioprio_set", Comm: "ioworkload", MinCount: 1},
	})
}
