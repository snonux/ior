package integrationtests

import "testing"

const (
	sleepParquetDuration    = 6
	sleepWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

var sleepTraceArgs = []string{"-trace-families", "Time"}

func TestSleepTracepoints(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{sleepWorkloadStartupEnv}
	result, pid, err := h.RunWithIorArgs("sleep-syscalls", defaultDuration, sleepTraceArgs)
	if err != nil {
		t.Fatalf("run scenario sleep-syscalls: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_nanosleep", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_clock_nanosleep", Comm: "ioworkload", MinCount: 1},
	})
}

func TestSleepRequestedTimespecInParquet(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{sleepWorkloadStartupEnv}
	path, pid, err := h.RunParquetWithIorArgs("sleep-syscalls", sleepParquetDuration, sleepTraceArgs)
	if err != nil {
		t.Fatalf("run sleep-syscalls parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	// The workload issues, per loop iteration: a relative nanosleep (2ms), a
	// relative clock_nanosleep (3ms), and an ABSOLUTE clock_nanosleep
	// (TIMER_ABSTIME) whose request is an absolute CLOCK_MONOTONIC timestamp.
	// The absolute one must be reported as the -1 sentinel, never as a bogus
	// multi-decade "sleep duration" (task a20).
	var sawNanosleep bool
	var sawClockNanosleepRel bool
	var sawClockNanosleepAbs bool
	for _, row := range rows {
		switch row.Syscall {
		case "nanosleep":
			if row.RequestedSleepNS == 2_000_000 {
				sawNanosleep = true
			}
			if row.Bytes != 0 {
				t.Fatalf("nanosleep bytes = %d, want 0", row.Bytes)
			}
		case "clock_nanosleep":
			switch row.RequestedSleepNS {
			case 3_000_000:
				sawClockNanosleepRel = true
			case -1:
				// Absolute (TIMER_ABSTIME) sleep: sentinel, not a duration.
				sawClockNanosleepAbs = true
			default:
				// Any large positive value here means the absolute wakeup
				// timestamp leaked through as a duration — the bug in a20.
				if row.RequestedSleepNS > 1_000_000_000 {
					t.Fatalf("clock_nanosleep RequestedSleepNS = %d looks like an absolute timestamp; TIMER_ABSTIME must record -1", row.RequestedSleepNS)
				}
			}
			if row.Bytes != 0 {
				t.Fatalf("clock_nanosleep bytes = %d, want 0", row.Bytes)
			}
		}
	}

	if !sawNanosleep {
		t.Fatal("expected nanosleep row with RequestedSleepNS=2000000")
	}
	if !sawClockNanosleepRel {
		t.Fatal("expected relative clock_nanosleep row with RequestedSleepNS=3000000")
	}
	if !sawClockNanosleepAbs {
		t.Fatal("expected absolute (TIMER_ABSTIME) clock_nanosleep row with RequestedSleepNS=-1")
	}
}
