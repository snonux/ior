package integrationtests

import (
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
