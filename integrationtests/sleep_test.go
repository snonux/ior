package integrationtests

import "testing"

const (
	sleepParquetDuration    = 6
	sleepWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

var sleepTraceArgs = []string{"-trace-families", "Time"}

func TestSleepRequestedTimespecInParquet(t *testing.T) {
	rows, _ := runParquetScenarioRows(t, "sleep-syscalls", sleepParquetDuration,
		sleepTraceArgs, []string{sleepWorkloadStartupEnv})

	// The workload issues, per loop iteration: a relative nanosleep (2ms), a
	// relative clock_nanosleep (3ms), and an ABSOLUTE clock_nanosleep
	// (TIMER_ABSTIME) whose request is an absolute CLOCK_MONOTONIC timestamp.
	// The absolute one must be reported as the -1 sentinel, never as a bogus
	// multi-decade "sleep duration" (task a20).
	notError := false
	zero := int64(0)
	zeroBytes := uint64(0)
	AssertRowsPresent(t, rows, []ExpectedRow{
		{
			Syscall:          "nanosleep",
			Comm:             "ioworkload",
			RetVal:           &zero,
			IsError:          &notError,
			Bytes:            &zeroBytes,
			RequestedSleepNs: ptrTo(int64(2_000_000)),
		},
		{
			Syscall:          "clock_nanosleep",
			Comm:             "ioworkload",
			RetVal:           &zero,
			IsError:          &notError,
			Bytes:            &zeroBytes,
			RequestedSleepNs: ptrTo(int64(3_000_000)),
		},
		{
			Syscall:          "clock_nanosleep",
			Comm:             "ioworkload",
			RetVal:           &zero,
			IsError:          &notError,
			Bytes:            &zeroBytes,
			RequestedSleepNs: ptrTo(int64(-1)),
		},
	})
}
