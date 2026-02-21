package integrationtests

import "testing"

func TestIouringSetup(t *testing.T) {
	runScenario(t, "iouring-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestIouringEnter(t *testing.T) {
	runScenario(t, "iouring-enter", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_enter",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestIouringRegister(t *testing.T) {
	runScenario(t, "iouring-register", []ExpectedEvent{
		{
			Tracepoint: "enter_io_uring_register",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
