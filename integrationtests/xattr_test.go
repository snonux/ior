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

// The trace selectors below scope tracing to exactly the path/fd-based xattr
// variant under test (plus setxattr/openat used to prime the attribute), so the
// substring-based assertion matcher cannot pick up sibling tracepoints. The
// syscall filter is exact-match, so e.g. tracing "getxattr" does NOT enable
// lgetxattr/fgetxattr/getxattrat.
var (
	xattrGetTraceArgs        = []string{"-trace-syscalls", "getxattr,setxattr,openat"}
	xattrLgetTraceArgs       = []string{"-trace-syscalls", "lgetxattr,setxattr,openat"}
	xattrListPathTraceArgs   = []string{"-trace-syscalls", "listxattr,setxattr,openat"}
	xattrLlistTraceArgs      = []string{"-trace-syscalls", "llistxattr,setxattr,openat"}
	xattrLsetTraceArgs       = []string{"-trace-syscalls", "lsetxattr,setxattr,openat"}
	xattrSetatTraceArgs      = []string{"-trace-syscalls", "setxattrat,setxattr,openat"}
	xattrRemovePathTraceArgs = []string{"-trace-syscalls", "removexattr,setxattr,openat"}
	xattrLremoveTraceArgs    = []string{"-trace-syscalls", "lremovexattr,setxattr,openat"}
	// The fd family runs all four fd-based syscalls in one scenario, so trace
	// them together.
	xattrFdTraceArgs = []string{"-trace-syscalls", "fsetxattr,fgetxattr,flistxattr,fremovexattr,openat"}
)

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

// assertNoXattrNameAsPath fails if any record for the given enter tracepoint
// captured the xattr NAME ("user.ior") as its path instead of the file path.
func assertNoXattrNameAsPath(t *testing.T, result TestResult, tracepoint string) {
	t.Helper()
	for _, rec := range result.Records {
		if rec.TraceID.String() == tracepoint && rec.Path == "user.ior" {
			t.Errorf("%s captured xattr name %q as path instead of file path", tracepoint, rec.Path)
		}
	}
}

// TestXattrGetxattr verifies ior traces the PATH-based getxattr(2) end-to-end.
// getxattr(const char *path, const char *name, void *value, size_t size) takes
// the filesystem PATH at args[0] and the xattr NAME at args[1]; only the path
// must be captured on entry. getxattr returns the xattr value size in bytes, so
// ior READ-classifies the exit and the recorded byte count must reflect at
// least the value written by the workload (consistent with
// lgetxattr/fgetxattr/getxattrat).
func TestXattrGetxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-getxattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_getxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrGetTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_getxattr")

	exp := ExpectedEvent{Tracepoint: "enter_getxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, 1)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrLgetxattr verifies ior traces the no-follow PATH-based lgetxattr(2)
// end-to-end. lgetxattr has getxattr's signature but does NOT follow symlinks;
// the workload targets a regular file, so it returns the value size (user.*
// xattrs on a bare symlink are kernel-restricted). The PATH is at args[0]; the
// exit is READ-classified.
func TestXattrLgetxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-lgetxattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_lgetxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrLgetTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_lgetxattr")

	exp := ExpectedEvent{Tracepoint: "enter_lgetxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, 1)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrListxattr verifies ior traces the PATH-based listxattr(2) end-to-end.
// listxattr(const char *path, char *list, size_t size) takes the PATH at
// args[0]; it returns the size in bytes of the NUL-separated xattr name list,
// so ior READ-classifies the exit (consistent with llistxattr/flistxattr/
// listxattrat).
func TestXattrListxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-listxattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_listxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrListPathTraceArgs)

	exp := ExpectedEvent{Tracepoint: "enter_listxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, 1)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrLlistxattr verifies ior traces the no-follow PATH-based llistxattr(2)
// end-to-end. As with lgetxattr the target is a regular file, so it returns the
// name-list size. The PATH is at args[0]; the exit is READ-classified.
func TestXattrLlistxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-llistxattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_llistxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrLlistTraceArgs)

	exp := ExpectedEvent{Tracepoint: "enter_llistxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, exp, 1)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrLsetxattr verifies ior traces the no-follow PATH-based lsetxattr(2)
// end-to-end. lsetxattr(const char *path, const char *name, const void *value,
// size_t size, int flags) takes the PATH at args[0] and the xattr NAME at
// args[1]; only the path must be captured. lsetxattr returns 0/-1 (its `size`
// arg is the INPUT value length), so the exit is UNCLASSIFIED — the accounted
// bytes must be exactly zero (contrast getxattr/lgetxattr, which ARE READ-
// classified), matching setxattr/setxattrat/fsetxattr.
func TestXattrLsetxattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-lsetxattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_lsetxattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrLsetTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_lsetxattr")

	exp := ExpectedEvent{Tracepoint: "enter_lsetxattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrSetxattrat verifies ior traces the -at variant setxattrat(2) (Linux
// 6.13+) end-to-end. setxattrat takes a dirfd plus a real filesystem PATH at
// args[1] (NOT args[0]=dfd) and the xattr NAME at args[3]; only the path must be
// captured. setxattrat SETS an attribute and returns 0/-1 (the value size is an
// INPUT field of struct xattr_args), so the exit is UNCLASSIFIED — the accounted
// bytes must be exactly zero (guarding against accidental READ-classification
// like its getxattrat/listxattrat siblings), matching setxattr/lsetxattr/
// fsetxattr.
func TestXattrSetxattrat(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-setxattrat", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_setxattrat",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrSetatTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_setxattrat")

	exp := ExpectedEvent{Tracepoint: "enter_setxattrat", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrRemovexattr verifies ior traces the PATH-based removexattr(2)
// end-to-end. removexattr(const char *path, const char *name) takes the PATH at
// args[0] and the xattr NAME at args[1]; only the path must be captured.
// removexattr returns 0/-1, never a byte count, so the exit is UNCLASSIFIED —
// the accounted bytes must be exactly zero, matching lremovexattr/fremovexattr/
// removexattrat.
func TestXattrRemovexattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-removexattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_removexattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrRemovePathTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_removexattr")

	exp := ExpectedEvent{Tracepoint: "enter_removexattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrLremovexattr verifies ior traces the no-follow PATH-based
// lremovexattr(2) end-to-end. As with the other l* variants the target is a
// regular file, so it removes the user.* attr. The PATH is at args[0]; the exit
// is UNCLASSIFIED.
func TestXattrLremovexattr(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-lremovexattr", []ExpectedEvent{
		{
			PathContains: "xattrfile.txt",
			Tracepoint:   "enter_lremovexattr",
			Comm:         "ioworkload",
			MinCount:     1,
		},
	}, xattrLremoveTraceArgs)

	assertNoXattrNameAsPath(t, result, "enter_lremovexattr")

	exp := ExpectedEvent{Tracepoint: "enter_lremovexattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, exp, 0)
	assertEventDurationPositive(t, result, exp)
}

// TestXattrFd verifies ior traces the entire fd-based xattr family end-to-end:
// fsetxattr/fgetxattr/flistxattr/fremovexattr. Each takes the FD at args[0]
// (kind=fd, no path) rather than a pathname. fgetxattr and flistxattr return
// value/name-list sizes and are READ-classified (bytes>0); fsetxattr and
// fremovexattr return 0/-1 status and are UNCLASSIFIED (bytes==0). All four
// fire on the single open fd in the xattr-fd scenario.
func TestXattrFd(t *testing.T) {
	result, _ := runScenarioResultWithIorArgs(t, "xattr-fd", []ExpectedEvent{
		{Tracepoint: "enter_fsetxattr", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_fgetxattr", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_flistxattr", Comm: "ioworkload", MinCount: 1},
		{Tracepoint: "enter_fremovexattr", Comm: "ioworkload", MinCount: 1},
	}, xattrFdTraceArgs)

	// READ-classified fd reads: returned value/name-list sizes are accounted.
	fget := ExpectedEvent{Tracepoint: "enter_fgetxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, fget, 1)
	assertEventDurationPositive(t, result, fget)

	flist := ExpectedEvent{Tracepoint: "enter_flistxattr", Comm: "ioworkload"}
	assertEventBytesAtLeast(t, result, flist, 1)
	assertEventDurationPositive(t, result, flist)

	// UNCLASSIFIED fd ops: 0/-1 status returns, never a byte count.
	fset := ExpectedEvent{Tracepoint: "enter_fsetxattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, fset, 0)
	assertEventDurationPositive(t, result, fset)

	fremove := ExpectedEvent{Tracepoint: "enter_fremovexattr", Comm: "ioworkload"}
	assertEventBytesEqual(t, result, fremove, 0)
	assertEventDurationPositive(t, result, fremove)
}
