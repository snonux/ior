package integrationtests

import "testing"

func TestPidfdGetfdSuccess(t *testing.T) {
	runScenario(t, "pidfd-getfd-success", []ExpectedEvent{
		{
			PathContains: "pidfd-getfd-source.txt",
			Tracepoint:   "enter_pidfd_getfd",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestPidfdGetfdFailure(t *testing.T) {
	runScenario(t, "pidfd-getfd-failure", []ExpectedEvent{
		{
			Tracepoint: "enter_pidfd_getfd",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
