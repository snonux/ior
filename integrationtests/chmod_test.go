package integrationtests

import "testing"

// TestChmodBasic verifies ior captures the chmod permission-change family
// end-to-end. chmod and fchmodat take a real filesystem path (args[0] and
// args[1] respectively), so both must be path-classified (KindPathname) and
// the file path captured. fchmod operates on an open fd (KindFd) and carries
// no path, so we only assert the tracepoint fired. fchmodat2 is best-effort
// (ENOSYS on kernels < 6.6) and not asserted; the running kernel is 6.x+, so
// it does fire in practice, but the older siblings are the stable assertions.
func TestChmodBasic(t *testing.T) {
	runScenario(t, "chmod-basic", []ExpectedEvent{
		{
			PathContains: "chmodfile.txt",
			Tracepoint:   "enter_chmod",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "chmodfile.txt",
			Tracepoint:   "enter_fchmodat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_fchmod",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
