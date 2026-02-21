package integrationtests

import "testing"

func TestDupBasic(t *testing.T) {
	runScenario(t, "dup-basic", []ExpectedEvent{
		{
			PathContains: "dupfile.txt",
			Tracepoint:   "enter_dup",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDupDup2(t *testing.T) {
	runScenario(t, "dup-dup2", []ExpectedEvent{
		{
			PathContains: "dup2file.txt",
			Tracepoint:   "enter_dup2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDupDup3(t *testing.T) {
	runScenario(t, "dup-dup3", []ExpectedEvent{
		{
			PathContains: "dup3file.txt",
			Tracepoint:   "enter_dup3",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
