package integrationtests

import "testing"

func TestUnlinkBasic(t *testing.T) {
	runScenario(t, "unlink-basic", []ExpectedEvent{
		{
			PathContains: "unlinkme.txt",
			Tracepoint:   "enter_unlink",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkUnlinkat(t *testing.T) {
	runScenario(t, "unlink-unlinkat", []ExpectedEvent{
		{
			PathContains: "unlinkat-file.txt",
			Tracepoint:   "enter_unlinkat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestUnlinkRmdir(t *testing.T) {
	runScenario(t, "unlink-rmdir", []ExpectedEvent{
		{
			PathContains: "rmdir-me",
			Tracepoint:   "enter_rmdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
