package integrationtests

import (
	"strings"
	"testing"
)

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
	})

	if !hasTracepoint(result, "enter_epoll_pwait2") {
		t.Log("enter_epoll_pwait2 not observed; treating as unsupported-kernel path")
	}
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

	wantReadyCount := map[string]bool{"epoll_wait": false, "epoll_pwait": false}
	var sawPwait2 bool
	var sawPwait2ReadyCount bool
	for _, row := range rows {
		switch row.Syscall {
		case "epoll_wait", "epoll_pwait":
			if row.Ret > 0 {
				wantReadyCount[row.Syscall] = true
			}
			if row.Bytes != 0 {
				t.Fatalf("%s bytes = %d, want 0 for ready-count events", row.Syscall, row.Bytes)
			}
		case "epoll_pwait2":
			sawPwait2 = true
			if row.Ret > 0 {
				sawPwait2ReadyCount = true
			}
			if row.Bytes != 0 {
				t.Fatalf("%s bytes = %d, want 0 for ready-count events", row.Syscall, row.Bytes)
			}
		}
	}

	for syscall, ok := range wantReadyCount {
		if !ok {
			t.Fatalf("expected %s row with positive ready-count ret in parquet output", syscall)
		}
	}
	if sawPwait2 && !sawPwait2ReadyCount {
		t.Fatalf("expected epoll_pwait2 row with positive ready-count ret when epoll_pwait2 is present")
	}
	if !sawPwait2 {
		t.Log("epoll_pwait2 parquet rows not observed; treating as unsupported-kernel path")
	}
}

func hasTracepoint(result TestResult, tracepoint string) bool {
	for _, rec := range result.Records {
		if strings.Contains(rec.TraceID.String(), tracepoint) {
			return true
		}
	}
	return false
}
