package integrationtests

import "testing"

var iouringTraceArgs = []string{"-trace-syscalls", "io_uring_setup,io_uring_enter,io_uring_register,close"}

func TestIouringSetup(t *testing.T) {
	runScenarioResultWithIorArgs(t, "iouring-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnter(t *testing.T) {
	runScenarioResultWithIorArgs(t, "iouring-enter", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_enter",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringRegister(t *testing.T) {
	runScenarioResultWithIorArgs(t, "iouring-register", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_register",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringEnterEbadf(t *testing.T) {
	runScenarioResultWithIorArgs(t, "iouring-enter-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_enter",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}

func TestIouringRegisterEbadf(t *testing.T) {
	runScenarioResultWithIorArgs(t, "iouring-register-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_register",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, iouringTraceArgs)
}
