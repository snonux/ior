package integrationtests

import (
	"strings"
	"syscall"
	"testing"
)

var iouringTraceArgs = []string{"-trace-syscalls", "io_uring_setup,io_uring_enter,io_uring_register,close"}

func TestIouringSetup(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnter(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-enter", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_enter",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringRegister(t *testing.T) {
	requireIoUring(t)
	runScenarioResultWithIorArgs(t, "iouring-register", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_register",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnterEbadf(t *testing.T) {
	runParquetErrorScenario(t, "iouring-enter-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "io_uring_enter",
		FD:      ptrTo(int32(99999)),
	}, iouringTraceArgs)
}

func TestIouringRegisterEbadf(t *testing.T) {
	runParquetErrorScenario(t, "iouring-register-ebadf", syscall.EBADF, ExpectedRow{
		Syscall: "io_uring_register",
		FD:      ptrTo(int32(99999)),
	}, iouringTraceArgs)
}

// TestIouringRegisteredRing pins task cq2: io_uring_enter with
// IORING_ENTER_REGISTERED_RING and io_uring_register with
// IORING_REGISTER_USE_REGISTERED_RING pass a registered-ring index in the fd
// argument. The workload parks a decoy file on fd 0, where that index (0 for a
// fresh thread) used to resolve; the rows must name the ring instead and carry
// no descriptor.
func TestIouringRegisteredRing(t *testing.T) {
	requireIoUring(t)
	rows, _ := runParquetScenarioRows(t, "iouring-registered-ring", defaultDuration, iouringTraceArgs, nil)

	var enterRows, registerRows int
	for _, row := range rows {
		if row.Syscall != "io_uring_enter" && row.Syscall != "io_uring_register" {
			continue
		}
		if strings.Contains(row.File, "ioworkload-iouring-decoy-") {
			t.Errorf("%s row attributed to the decoy file on fd 0: %+v", row.Syscall, row)
		}
		if strings.HasPrefix(row.File, "io_uring:reg[") {
			if row.FD != -1 {
				t.Errorf("%s registered-ring row carries fd %d, want -1: %+v", row.Syscall, row.FD, row)
			}
			if row.Syscall == "io_uring_enter" {
				enterRows++
			} else {
				registerRows++
			}
		}
	}
	// The scenario issues five of each through the registered ring.
	if enterRows < 5 || registerRows < 5 {
		t.Errorf("registered-ring rows: enter=%d register=%d, want >= 5 each", enterRows, registerRows)
		logRowSummary(t, rows)
	}
}
