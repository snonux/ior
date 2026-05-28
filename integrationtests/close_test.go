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

func TestCloseRangeBounded(t *testing.T) {
	runScenario(t, "close-range-bounded", []ExpectedEvent{
		{
			PathContains: "closerangelow-",
			Tracepoint:   "enter_close_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "closerangehigh.txt",
			Tracepoint:   "enter_write",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestCloseInvalidFd(t *testing.T) {
	runScenario(t, "close-invalid-fd", []ExpectedEvent{
		{
			Tracepoint: "enter_close",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestCloseDoubleClose(t *testing.T) {
	runScenario(t, "close-double-close", []ExpectedEvent{
		{
			PathContains: "doubleclosefile.txt",
			Tracepoint:   "enter_close",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_close",
			Comm:       "ioworkload",
			MinCount:   2,
		},
	})
}

func TestCloseRangeEmpty(t *testing.T) {
	runScenario(t, "close-range-empty", []ExpectedEvent{
		{
			Tracepoint: "enter_close_range",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
