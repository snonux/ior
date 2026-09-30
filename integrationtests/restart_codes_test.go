package integrationtests

import "testing"

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
