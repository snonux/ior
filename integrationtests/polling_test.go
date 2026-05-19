package integrationtests

import "testing"

const (
	pollingParquetDuration    = 10
	pollingWorkloadStartupEnv = "IOR_WORKLOAD_STARTUP_DELAY_MS=1000"
)

func TestPollingEpollTracepoints(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{pollingWorkloadStartupEnv}
	result, pid, err := h.Run("polling-epoll", defaultDuration)
	if err != nil {
		t.Fatalf("run scenario polling-epoll: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsPresent(t, result, []ExpectedEvent{
		{Tracepoint: "enter_epoll_ctl", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_epoll_wait", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_epoll_pwait", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_epoll_pwait2", Comm: "ioworkload", MinCount: 1},
	})
}

func TestPollingEpollReadyCountInParquet(t *testing.T) {
	h := newTestHarness(t)
	h.WorkloadEnv = []string{pollingWorkloadStartupEnv}
	path, pid, err := h.RunParquet("polling-epoll", pollingParquetDuration)
	if err != nil {
		t.Fatalf("run polling-epoll parquet scenario: %v", err)
	}

	rows := filterRecordsByPID(readParquetRecords(t, path), uint32(pid))
	if len(rows) == 0 {
		t.Fatalf("expected parquet rows for workload PID %d", pid)
	}

	wantReadyCount := map[string]bool{
		"epoll_wait":   false,
		"epoll_pwait":  false,
		"epoll_pwait2": false,
	}
	for _, row := range rows {
		_, tracked := wantReadyCount[row.Syscall]
		if !tracked {
			continue
		}
		if row.Ret > 0 {
			wantReadyCount[row.Syscall] = true
		}
		if row.Bytes != 0 {
			t.Fatalf("%s bytes = %d, want 0 for ready-count events", row.Syscall, row.Bytes)
		}
	}

	for syscall, ok := range wantReadyCount {
		if !ok {
			t.Fatalf("expected %s row with positive ready-count ret in parquet output", syscall)
		}
	}
}
