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

// sysvMsgTraceArgs restricts tracing to the SysV message-queue family so the
// captured output is dominated by the lifecycle calls the workload issues.
var sysvMsgTraceArgs = []string{
	"-trace-syscalls",
	"msgget,msgsnd,msgrcv,msgctl",
}

// TestSysVMsgBasic verifies the SysV message-queue family is traced end-to-end.
// The workload runs msgget(IPC_PRIVATE) -> msgsnd -> msgrcv -> msgctl(IPC_RMID);
// each call must appear as an enter event with a positive duration (proving the
// enter/exit pair was correlated). The workload always issues IPC_RMID, so no
// kernel message queue leaks.
func TestSysVMsgBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("sysv-msg-basic", defaultDuration, sysvMsgTraceArgs)
	if err != nil {
		t.Fatalf("run scenario sysv-msg-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_msgget", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_msgsnd", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_msgrcv", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_msgctl", Comm: "ioworkload", MinCount: 1},
	})

	for _, tp := range []string{"enter_msgget", "enter_msgsnd", "enter_msgrcv", "enter_msgctl"} {
		assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: tp, Comm: "ioworkload"})
	}

	// msgrcv is READ_CLASSIFIED: its exit handler reports ctx->ret, the number
	// of bytes copied into the caller's buffer. The workload sends the literal
	// "ior-sysv-msg" (12 bytes, scenario_sysv.go sysvMsgText) and reads it back,
	// so the captured byte count must be at least the payload length. (msgsnd is
	// UNCLASSIFIED, so only msgrcv carries a meaningful READ byte count.)
	assertEventBytesAtLeast(t, result,
		ExpectedEvent{Tracepoint: "enter_msgrcv", Comm: "ioworkload"},
		uint64(len("ior-sysv-msg")))
}

// sysvSemTraceArgs restricts tracing to the SysV semaphore family so the
// captured output is dominated by the lifecycle calls the workload issues.
var sysvSemTraceArgs = []string{
	"-trace-syscalls",
	"semget,semop,semctl",
}

// TestSysVSemBasic verifies the SysV semaphore family is traced end-to-end. The
// workload runs semget(IPC_PRIVATE) -> semop(+1) -> semop(-1) ->
// semctl(IPC_RMID); each distinct syscall must appear as an enter event with a
// positive duration (proving the enter/exit pair was correlated). The workload
// always issues IPC_RMID, so no kernel semaphore set leaks.
func TestSysVSemBasic(t *testing.T) {
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("sysv-sem-basic", defaultDuration, sysvSemTraceArgs)
	if err != nil {
		t.Fatalf("run scenario sysv-sem-basic: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_semget", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_semop", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_semctl", Comm: "ioworkload", MinCount: 1},
	})

	for _, tp := range []string{"enter_semget", "enter_semop", "enter_semctl"} {
		assertEventDurationPositive(t, result, ExpectedEvent{Tracepoint: tp, Comm: "ioworkload"})
	}
}
