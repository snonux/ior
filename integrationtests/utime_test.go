package integrationtests

import "testing"

// TestUtimeBasic verifies that ior captures the enter_utime tracepoint with the
// real file path. utime(2) takes a genuine filesystem path at args[0]
// ("filename"), so it must be path-classified (KindPathname), just like its
// siblings utimensat/futimesat.
func TestUtimeBasic(t *testing.T) {
	runScenario(t, "utime-basic", []ExpectedEvent{
		{
			PathContains: "utimefile.txt",
			Tracepoint:   "enter_utime",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

// TestUtimeUtimes verifies the microsecond-resolution sibling utimes(2) is
// likewise path-classified and its filename path captured.
func TestUtimeUtimes(t *testing.T) {
	runScenario(t, "utime-utimes", []ExpectedEvent{
		{
			PathContains: "utimesfile.txt",
			Tracepoint:   "enter_utimes",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}

// TestUtimeEnoent verifies the path is still captured on the error path:
// utime(2) on a missing file fails with ENOENT, but ior records enter_utime
// because the filename is read on syscall entry.
func TestUtimeEnoent(t *testing.T) {
	runScenario(t, "utime-enoent", []ExpectedEvent{
		{
			PathContains: "utime-enoent-missing.txt",
			Tracepoint:   "enter_utime",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
