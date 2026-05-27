package integrationtests

import "testing"

var pidfdTraceArgs = []string{"-trace-syscalls", "pidfd_open,pidfd_getfd,openat,write,close"}

func TestPidfdGetfdSuccess(t *testing.T) {
	runScenarioResultWithIorArgs(t, "pidfd-getfd-success", []ExpectedEvent{
		{
			PathContains: "pidfd-getfd-source.txt",
			Tracepoint:   "enter_pidfd_getfd",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, pidfdTraceArgs)
}

func TestPidfdGetfdFailure(t *testing.T) {
	runScenarioResultWithIorArgs(t, "pidfd-getfd-failure", []ExpectedEvent{
		{
			Tracepoint: "enter_pidfd_getfd",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	}, pidfdTraceArgs)
}
