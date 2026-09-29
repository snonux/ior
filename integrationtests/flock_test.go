package integrationtests

import "testing"

// TestFlockBasic asserts end-to-end tracing of the FamilyFS flock syscall. The
// flock-basic scenario opens a temp file, takes an exclusive advisory lock
// (LOCK_EX) and releases it (LOCK_UN), then closes the file.
//
// flock is captured as KindFd at args[0]; ior resolves that fd to the
// underlying file path via the procfd cache, so the enter_flock record carries
// the temp filename. Its return value is UNCLASSIFIED, so we only assert the
// enter path (path + count), not a byte total.
func TestFlockBasic(t *testing.T) {
	runScenario(t, "flock-basic", []ExpectedEvent{
		{
			PathContains: "flockfile.txt",
			Tracepoint:   "enter_flock",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	})
}
