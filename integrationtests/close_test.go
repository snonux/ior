package integrationtests

import "testing"

func TestCloseBasic(t *testing.T) {
	runScenario(t, "close-basic", []ExpectedEvent{
		{
			PathContains: "closefile-",
			Tracepoint:   "enter_close",
			Comm:         "ioworkload",
			MinCount:     3,
		},
	})
}

func TestCloseRange(t *testing.T) {
	runScenario(t, "close-range", []ExpectedEvent{
		{
			PathContains: "closerangefile-",
			Tracepoint:   "enter_close_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
