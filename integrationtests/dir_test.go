package integrationtests

import "testing"

func TestDirBasic(t *testing.T) {
	runScenario(t, "dir-basic", []ExpectedEvent{
		{
			PathContains: "subdir",
			Tracepoint:   "enter_mkdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDirMkdirat(t *testing.T) {
	runScenario(t, "dir-mkdirat", []ExpectedEvent{
		{
			PathContains: "mkdirat-subdir",
			Tracepoint:   "enter_mkdirat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDirChdir(t *testing.T) {
	runScenario(t, "dir-chdir", []ExpectedEvent{
		{
			PathContains: "dir-chdir",
			Tracepoint:   "enter_chdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDirGetdents(t *testing.T) {
	runScenario(t, "dir-getdents", []ExpectedEvent{
		{
			PathContains: "dir-getdents",
			Tracepoint:   "enter_getdents64",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
