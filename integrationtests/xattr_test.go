package integrationtests

import "testing"

// xattrTraceArgs restricts tracing to the getxattrat tracepoints so the test is
// not perturbed by unrelated xattr/open traffic.
var xattrTraceArgs = []string{"-trace-syscalls", "getxattrat,setxattr,openat"}

// xattrListTraceArgs restricts tracing to the listxattrat tracepoints so the
// test is not perturbed by unrelated xattr/open traffic.
var xattrListTraceArgs = []string{"-trace-syscalls", "listxattrat,setxattr,openat"}

// xattrRemoveTraceArgs restricts tracing to the removexattrat tracepoints so
// the test is not perturbed by unrelated xattr/open traffic.
var xattrRemoveTraceArgs = []string{"-trace-syscalls", "removexattrat,setxattr,openat"}

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

// TestXattrSetxattr verifies ior traces the PATH-based setxattr(2) end-to-end.
// setxattr(const char *path, const char *name, const void *value, size_t size,
// int flags) takes a real filesystem PATH at args[0] (kind=pathname) and the
// xattr NAME at args[1]; only the path must be captured on entry, so
// enter_setxattr must carry the file path "xattrfile.txt" and never the xattr
// name "user.ior". Crucially, setxattr returns 0 on success / -1 on error — its
// `size` argument is the INPUT value length, NOT a byte count returned by the
// call. The exit is therefore UNCLASSIFIED (contrast getxattr/listxattr, which
// DO return byte counts and are READ-classified), so the recorded byte total
// must be exactly zero. This reuses the xattr-getxattrat scenario, whose
// workload performs syscall.Setxattr(path, "user.ior", ...) and is traced via
// xattrTraceArgs ("getxattrat,setxattr,openat").
func TestXattrSetxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-getxattrat", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_setxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrTraceArgs)

	// The captured path must be the filesystem path, never the xattr name.
	for _, rec := range result.Records {
		if rec.TraceID.String() == "enter_setxattr" && rec.Path == "user.ior" {
			t.Errorf("setxattr captured xattr name %q as path instead of file path", rec.Path)
		}
	}

	// setxattr is UNCLASSIFIED: its return is a 0/-1 status, never a byte count
	// (the `size` arg is the input value length). The accounted bytes for the
	// setxattr events must therefore be exactly zero — guarding against the
	// msgsnd-style bug of treating a status return as bytes written.
	exp := ExpectedEvent{Tracepoint: "enter_setxattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrListxattrat verifies ior traces listxattrat(2) (Linux 6.13+)
// end-to-end. listxattrat takes a dirfd plus a real filesystem path at args[1]
// (NOT args[0]=dfd); only the path must be captured. The path is read on
// syscall entry, so enter_listxattrat must carry the file path "xattrfile.txt".
func TestXattrListxattrat(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-listxattrat", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_listxattrat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrListTraceArgs)

	// listxattrat returns the size in bytes of the xattr name list; ior
	// READ-classifies the exit, so the recorded byte count must reflect at least
	// the NUL-terminated "user.ior" name set by the workload (consistent with
	// listxattr/llistxattr/flistxattr).
	exp := ExpectedEvent{Tracepoint: "enter_listxattrat", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, uint64(len("user.ior")+1))
	assertEventDurationPositive(t, result, exp)
}

// TestXattrRemovexattrat verifies ior traces removexattrat(2) (Linux 6.13+)
// end-to-end. removexattrat takes a dirfd plus a real filesystem path at
// args[1] (NOT args[0]=dfd); the xattr name is at args[3] and must NOT be
// captured. The path is read on syscall entry, so enter_removexattrat must
// carry the file path "xattrfile.txt", never the name "user.ior".
func TestXattrRemovexattrat(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-removexattrat", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_removexattrat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrRemoveTraceArgs)

	// The captured path must be the filesystem path, never the xattr name.
	for _, rec := range result.Records {
		if rec.TraceID.String() == "enter_removexattrat" && rec.Path == "user.ior" {
			t.Errorf("removexattrat captured xattr name %q as path instead of file path", rec.Path)
		}
	}

	// removexattrat is UNCLASSIFIED: it REMOVES an attribute and returns a 0/-1
	// status, never a byte count (contrast getxattrat/listxattrat, which return
	// value/name-list sizes). The accounted bytes must therefore be exactly
	// zero — matching removexattr/lremovexattr/fremovexattr, and guarding
	// against wrongly READ-classifying it like its getxattrat/listxattrat
	// siblings.
	exp := ExpectedEvent{Tracepoint: "enter_removexattrat", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}
