package integrationtests

import (
	"testing"

	iorparquet "ior/internal/parquet"
)

// restartTraceArgs traces exactly the calls the signal-restart workload makes.
// restart_syscall is included so a regression that reports the kernel restart
// path as errors would show up alongside it.
var restartTraceArgs = []string{
	"-trace-syscalls", "read,write,pipe2,clock_nanosleep,restart_syscall",
}

// TestKernelRestartCodesAreNotErrors covers task aq2. A signal that interrupts
// a blocked syscall makes it exit with a kernel-internal restart code
// (-ERESTARTSYS -512, -ERESTART_RESTARTBLOCK -516) that user space never sees.
// The workload interrupts a blocking read (restarted by the kernel, so the
// program only ever sees the later read that returns 1) and a nanosleep. ior
// keeps the raw return value visible but must not flag these rows as errors.
// Both stay separate rows (task fs2 folds only restart_syscall): the read is
// re-executed rather than resumed, and the sleep's SIGUSR1 handler turns its
// -516 into EINTR, so no restart_syscall follows and the held -516 row is
// released unchanged.
func TestKernelRestartCodesAreNotErrors(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "signal-restart", defaultDuration,
		restartTraceArgs, []string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	notError := false
	AssertRowsPresent(t, rows, []ExpectedRow{
		{Syscall: "read", Comm: "ioworkload", RetVal: ptrTo(int64(-512)), IsError: &notError},
		{Syscall: "read", Comm: "ioworkload", RetVal: ptrTo(int64(1)), IsError: &notError},
		{Syscall: "clock_nanosleep", Comm: "ioworkload", RetVal: ptrTo(int64(-516)), IsError: &notError},
	})

	for _, row := range rows {
		restart := row.Ret == -512 || row.Ret == -513 || row.Ret == -514 || row.Ret == -516
		if restart && row.IsError {
			t.Errorf("%s ret=%d is flagged is_error=true; kernel restart codes are not errors",
				row.Syscall, row.Ret)
		}
	}
}

// stopRestartSleepNs mirrors cmd/ioworkload's stopRestartSleepNs.
const stopRestartSleepNs = int64(600_000_000)

// TestStoppedSleepIsOneRow covers task fs2. The stop-restart workload sleeps
// 600ms in clock_nanosleep while an external stopper sends SIGSTOP and, 200ms
// later, SIGCONT. The kernel ends the call with -516 and resumes it through
// restart_syscall; before the fold ior reported two rows for the one call
// (clock_nanosleep ret=-516, then restart_syscall ret=0 without the requested
// sleep). Now the sleeping thread must show exactly one clock_nanosleep row:
// ret 0, the requested 600ms, and a latency covering the whole call. Other
// Go runtime threads also get stopped inside timed futex waits, whose
// restart_syscall continuations stay rows of their own because futex is not
// traced here, so only the sleeping (main) thread is checked for leftovers.
func TestStoppedSleepIsOneRow(t *testing.T) {
	rows, pid := runParquetScenarioRows(t, "stop-restart", defaultDuration,
		[]string{"-trace-syscalls", "clock_nanosleep,restart_syscall"},
		[]string{"IOR_WORKLOAD_STARTUP_DELAY_MS=500"})

	var sleeps []iorparquet.Record
	for _, row := range rows {
		// main.go pins the scenario to the main thread, so its tid is the pid.
		if row.TID != uint32(pid) {
			continue
		}
		switch row.Syscall {
		case "restart_syscall":
			t.Errorf("restart_syscall row on the sleeping thread was not folded: %+v", row)
		case "clock_nanosleep":
			sleeps = append(sleeps, row)
		}
	}
	if len(sleeps) != 1 {
		t.Fatalf("sleeping thread has %d clock_nanosleep rows, want exactly 1: %+v", len(sleeps), sleeps)
	}
	sleep := sleeps[0]
	if sleep.Ret != 0 || sleep.IsError {
		t.Errorf("folded row ret=%d is_error=%t, want ret=0 is_error=false", sleep.Ret, sleep.IsError)
	}
	if sleep.RequestedSleepNS != stopRestartSleepNs {
		t.Errorf("folded row requested_sleep_ns=%d, want %d", sleep.RequestedSleepNS, stopRestartSleepNs)
	}
	// The resumed sleep ends at the original deadline, so the whole call
	// lasts at least the request (unless the stop outlasted it, which only
	// makes it longer).
	if sleep.LatencyNS < uint64(stopRestartSleepNs) {
		t.Errorf("folded row latency_ns=%d, want >= the requested %d", sleep.LatencyNS, stopRestartSleepNs)
	}
}
