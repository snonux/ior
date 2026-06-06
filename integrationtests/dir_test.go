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

// TestDirMknodatFifo verifies mknodat(2) is traced end-to-end. The
// dir-mknodat-fifo workload creates an unprivileged FIFO node under AT_FDCWD,
// so enter_mknodat fires with pathname@args[1] (after dirfd@args[0]). Matching
// the distinct fifo name via PathContains proves the args[1] capture, mirroring
// the mkdirat coverage above.
func TestDirMknodatFifo(t *testing.T) {
	runScenario(t, "dir-mknodat-fifo", []ExpectedEvent{
		{
			PathContains: "mknodat-fifo",
			Tracepoint:   "enter_mknodat",
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
