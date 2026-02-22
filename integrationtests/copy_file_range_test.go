package integrationtests

import "testing"

func TestCopyFileRangeBasic(t *testing.T) {
	runScenario(t, "copy-file-range-basic", []ExpectedEvent{
		{
			PathContains: "copyrangesrc.txt",
			Tracepoint:   "enter_copy_file_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestCopyFileRangeBadDstFd(t *testing.T) {
	runScenario(t, "copy-file-range-bad-dst-fd", []ExpectedEvent{
		{
			PathContains: "copyrangeebadfsrc.txt",
			Tracepoint:   "enter_copy_file_range",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
