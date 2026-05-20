package integrationtests

import "testing"

func TestPerSyscallSamplingAggregateOnlySuppressesRingbufEvents(t *testing.T) {
	enableParallelIfRequested(t)
	h := newTestHarness(t)
	result, pid, err := h.RunWithIorArgs("open-basic", defaultDuration, []string{
		"-syscall-sampling-syscalls", "openat=0",
	})
	if err != nil {
		t.Fatalf("run scenario open-basic with sampling: %v", err)
	}

	AssertNoUnexpectedPID(t, result, pid)
	AssertNoUnexpectedComm(t, result, "ioworkload")
	AssertEventsAbsent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_openat",
			Comm:       "ioworkload",
		},
	})
	AssertEventsPresent(t, result, []ExpectedEvent{
		{
			Tracepoint: "enter_close",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
