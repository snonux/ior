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

func TestDirGetcwd(t *testing.T) {
	runScenario(t, "dir-getcwd", []ExpectedEvent{
		{
			PathContains: "dir-getcwd",
			Tracepoint:   "enter_getcwd",
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

func TestDirMkdirEexist(t *testing.T) {
	runScenario(t, "dir-mkdir-eexist", []ExpectedEvent{
		{
			PathContains: "mkdir-eexist-subdir",
			Tracepoint:   "enter_mkdir",
			Comm:         "ioworkload",
			MinCount:     2,
		},
	})
}

func TestDirChdirEnoent(t *testing.T) {
	runScenario(t, "dir-chdir-enoent", []ExpectedEvent{
		{
			PathContains: "chdir-enoent-missing",
			Tracepoint:   "enter_chdir",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

func TestDirGetdentsEbadf(t *testing.T) {
	runScenario(t, "dir-getdents-ebadf", []ExpectedEvent{
		{
			Tracepoint: "enter_getdents64",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
