package integrationtests

import "testing"

func TestFcntlDupfd(t *testing.T) {
	runScenario(t, "fcntl-dupfd", []ExpectedEvent{
		{
			PathContains: "fcntlfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestFcntlSetfl(t *testing.T) {
	runScenario(t, "fcntl-setfl", []ExpectedEvent{
		{
			PathContains: "fcntlsetflfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     2,
		},
	})
}

func TestFcntlDupfdCloexec(t *testing.T) {
	runScenario(t, "fcntl-dupfd-cloexec", []ExpectedEvent{
		{
			PathContains: "fcntlcloexecfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestFcntlInvalidFd(t *testing.T) {
	runScenario(t, "fcntl-invalid-fd", []ExpectedEvent{
		{
			Tracepoint: "enter_fcntl",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestFcntlDupfdMax(t *testing.T) {
	runScenario(t, "fcntl-dupfd-max", []ExpectedEvent{
		{
			PathContains: "fcntldupfdmaxfile.txt",
			Tracepoint:   "enter_fcntl",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
