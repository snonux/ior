package integrationtests

import "testing"

func TestTruncateBasic(t *testing.T) {
	runScenario(t, "truncate-basic", []ExpectedEvent{
		{
			PathContains: "truncfile.txt",
			Tracepoint:   "enter_truncate",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestTruncateFtruncate(t *testing.T) {
	runScenario(t, "truncate-ftruncate", []ExpectedEvent{
		{
			PathContains: "ftruncfile.txt",
			Tracepoint:   "enter_ftruncate",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestTruncateEnoent(t *testing.T) {
	runScenario(t, "truncate-enoent", []ExpectedEvent{
		{
			PathContains: "truncate-enoent-missing.txt",
			Tracepoint:   "enter_truncate",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestTruncateFtruncateEbadf(t *testing.T) {
	runScenario(t, "truncate-ftruncate-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_ftruncate",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
