package integrationtests

import "testing"

// sysvShmTraceArgs restricts tracing to the SysV shared-memory family so the
// captured output is dominated by the lifecycle calls the workload issues.
var sysvShmTraceArgs = []string{
	"-trace-syscalls",
	"shmget,shmat,shmdt,shmctl",
}

// TestSysVShmBasic verifies the SysV shared-memory family is traced end-to-end.
// The workload runs shmget(IPC_PRIVATE) -> shmat -> write -> shmdt ->
// shmctl(IPC_RMID); each call must appear as an enter event, and each must have
// a positive duration (proving the enter/exit pair was correlated by the
// tracer). The workload always issues IPC_RMID, so no kernel segment leaks.
func TestSysVShmBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("sysv-shm-basic", defaultDuration, sysvShmTraceArgs)
	if err != nil {
		t.Fatalf("run scenario sysv-shm-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_shmget", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_shmat", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_shmdt", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_shmctl", Comm: "ioworkload", MinCount: 1},
	})

	// Each syscall must have been correlated to its exit (positive duration),
	// proving the enter/exit pair was traced rather than just the enter.
	for _, tp := range []string{"enter_shmget", "enter_shmat", "enter_shmdt", "enter_shmctl"} {
		assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: tp, Comm: "ioworkload"})
	}
}
