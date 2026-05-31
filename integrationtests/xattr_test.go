package integrationtests

import "testing"

// xattrTraceArgs restricts tracing to the getxattrat tracepoints so the test is
// not perturbed by unrelated xattr/open traffic.
var xattrTraceArgs = []string{"-trace-syscalls", "getxattrat,setxattr,openat"}

// TestXattrGetxattrat verifies ior traces getxattrat(2) (Linux 6.13+)
// end-to-end. getxattrat takes a dirfd plus a real filesystem path at args[1]
// (NOT args[0]=dfd) and an xattr NAME at args[3]; only the path must be
// captured. The path is read on syscall entry, so enter_getxattrat must carry
// the file path "xattrfile.txt" and never the xattr name "user.ior".
func TestXattrGetxattrat(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-getxattrat", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_getxattrat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrTraceArgs)

	// The captured path must be the filesystem path, never the xattr name.
	for _, rec := range result.Records {
		if rec.TraceID.String() == "enter_getxattrat" && rec.Path == "user.ior" {
			t.Errorf("getxattrat captured xattr name %q as path instead of file path", rec.Path)
		}
	}

	// getxattrat returns the xattr value size in bytes; ior READ-classifies the
	// exit, so the recorded byte count must reflect the 16-byte value written by
	// the workload (consistent with getxattr/lgetxattr/fgetxattr).
	exp := ExpectedEvent{Tracepoint: "enter_getxattrat", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, uint64(len("getxattrat-value")))
	assertEventDurationPositive(t, result, exp)
}
