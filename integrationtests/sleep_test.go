package integrationtests

import "testing"

const (
	sleepParquetDuration    = 6
	sleepWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

func TestSleepTracepoints(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{sleepWorkloadStartupEnv}
	result, pid, err := h.Run("sleep-syscalls", defaultDuration)
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
	path, pid, err := h.RunParquet("sleep-syscalls", sleepParquetDuration)
	if err != nil {
		t.Fatalf("run sleep-syscalls parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	var sawNanosleep bool
	var sawClockNanosleep bool
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
			if row.RequestedSleepNS == 3_000_000 {
				sawClockNanosleep = true
			}
			if row.Bytes != 0 {
				t.Fatalf("clock_nanosleep bytes = %d, want 0", row.Bytes)
			}
		}
	}

	if !sawNanosleep {
		t.Fatal("expected nanosleep row with RequestedSleepNS=2000000")
	}
	if !sawClockNanosleep {
		t.Fatal("expected clock_nanosleep row with RequestedSleepNS=3000000")
	}
}

