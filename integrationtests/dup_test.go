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

func TestDupInvalidFd(t *testing.T) {
	runScenario(t, "dup-invalid-fd", []ExpectedEvent{
		{
			Tracepoint: "enter_dup",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}

func TestDup2SameFd(t *testing.T) {
	runScenario(t, "dup2-same-fd", []ExpectedEvent{
		{
			PathContains: "dup2samefile.txt",
			Tracepoint:   "enter_dup2",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDup3InvalidFlags(t *testing.T) {
	runScenario(t, "dup3-invalid-flags", []ExpectedEvent{
		{
			PathContains: "dup3flagsfile.txt",
			Tracepoint:   "enter_dup3",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
