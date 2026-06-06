package integrationtests

import "testing"

// TestChownBasic verifies ior captures the chown ownership-change family
// end-to-end. chown, lchown and fchownat all take a real filesystem path
// (args[0], args[0] and args[1] respectively), so each must be path-classified
// (KindPathname) with the path captured: chown/fchownat on the regular file
// (chownfile.txt) and lchown on the symlink (chownlink). fchown operates on an
// open fd (KindFd) and carries no path, so we only assert the tracepoint fired.
// Every call uses owner/group -1/-1 ("no change"), so the scenario runs
// unprivileged (no CAP_CHOWN). Mirrors the chmod coverage (scenario_chown.go /
// chown_test.go).
func TestChownBasic(t *testing.T) {
	runScenario(t, "chown-basic", []ExpectedEvent{
		{
			PathContains: "chownfile.txt",
			Tracepoint:   "enter_chown",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "chownlink",
			Tracepoint:   "enter_lchown",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			PathContains: "chownfile.txt",
			Tracepoint:   "enter_fchownat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
		{
			Tracepoint: "enter_fchown",
			Comm:       "ioworkload",
			MinCount:   1,
		},
	})
}
