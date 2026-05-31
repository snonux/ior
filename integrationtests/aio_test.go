package integrationtests

import "testing"

// aioTraceArgs traces the classic Linux AIO (io_setup) family syscalls plus
// close. io_setup/io_destroy are classified KindNull (FamilyAIO): the enter
// event captures no fd/path (nr_events is a count, ctx_idp an output pointer)
// and the exit event carries the raw return value.
var aioTraceArgs = []string{"-trace-syscalls", "io_setup,io_destroy,close"}

// TestAioSetup exercises io_setup(2) end-to-end and asserts ior records the
// enter_io_setup tracepoint for the AIO family workload.
func TestAioSetup(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-setup", []ExpectedEvent{
		{
			Tracepoint: "enter_io_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioTraceArgs)
}

// TestAioSetupEinval drives io_setup(2) with nr_events = 0 (EINVAL). The
// syscall fails, but ior still captures the enter_io_setup tracepoint.
func TestAioSetupEinval(t *testing.T) {
	runScenarioResultWithIorArgs(t, "aio-setup-einval", []ExpectedEvent{
		{
			Tracepoint: "enter_io_setup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, aioTraceArgs)
}
