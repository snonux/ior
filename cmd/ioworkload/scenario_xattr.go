package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getxattrat is syscall number 464 on amd64 (added in Linux 6.13). Go's
// syscall package does not yet export SYS_GETXATTRAT, so we invoke it by its
// raw number. Its signature is:
//
//	getxattrat(int dfd, const char *pathname, unsigned int at_flags,
//	           const char *name, struct xattr_args *uargs, size_t usize)
//
// The filesystem PATH is at args[1] (after the dirfd), while args[3] ("name")
// is the xattr NAME (e.g. "user.ior") and must NOT be captured as a path. The
// syscall returns the size in bytes of the xattr value (a read byte-count),
// or -1 on error.
const sysGetxattrat = 464

// listxattrat is syscall number 465 on amd64 (added in Linux 6.13, right after
// getxattrat). Go's syscall package does not export SYS_LISTXATTRAT, so we
// invoke it by its raw number. Its signature is:
//
//	listxattrat(int dfd, const char *pathname, unsigned int at_flags,
//	            char *list, size_t size)
//
// The filesystem PATH is at args[1] (after the dirfd); args[3] is the userspace
// buffer that receives the NUL-separated list of xattr names. The syscall
// returns the size in bytes of the name list (a read byte-count), or -1 on
// error — exactly like listxattr/llistxattr/flistxattr.
const sysListxattrat = 465

// removexattrat is syscall number 466 on amd64 (added in Linux 6.13, right
// after listxattrat). Go's syscall package does not export SYS_REMOVEXATTRAT,
// so we invoke it by its raw number. Its signature is:
//
//	removexattrat(int dfd, const char *pathname, unsigned int at_flags,
//	              const char *name)
//
// The filesystem PATH is at args[1] (after the dirfd); args[3] is the xattr
// NAME (e.g. "user.ior") and must NOT be captured as a path. Unlike
// getxattrat/listxattrat, removexattrat REMOVES an attribute and returns 0 on
// success / -1 on error (a status, NOT a read byte-count) — so its exit is
// UNCLASSIFIED, exactly like removexattr/lremovexattr/fremovexattr.
const sysRemovexattrat = 466

// setxattrat is syscall number 463 on amd64 (added in Linux 6.13, the first of
// the xattr -at quartet). Go's syscall package does not export SYS_SETXATTRAT,
// so we invoke it by its raw number. Its signature is:
//
//	setxattrat(int dfd, const char *pathname, unsigned int at_flags,
//	           const char *name, const struct xattr_args *uargs, size_t usize)
//
// The filesystem PATH is at args[1] (after the dirfd); args[3] is the xattr
// NAME and must NOT be captured as a path. Unlike getxattrat/listxattrat,
// setxattrat SETS an attribute and returns 0 on success / -1 on error (a
// status, NOT a read byte-count — the value size is an INPUT field of
// xattr_args) — so its exit is UNCLASSIFIED, exactly like
// setxattr/lsetxattr/fsetxattr.
const sysSetxattrat = 463

// xattrArgs mirrors struct xattr_args from <linux/xattr.h> (Linux 6.13+):
// a userspace value buffer pointer plus its size and flags.
type xattrArgs struct {
	value uint64 // __aligned_u64: pointer to the value buffer
	size  uint32 // size of the value buffer
	flags uint32 // operation flags (0 for getxattrat)
}

// xattrGetxattrat creates a file on tmpfs (/tmp), sets a user xattr on it, then
// reads that xattr back via the raw getxattrat(2) syscall with AT_FDCWD. This
// exercises ior's getxattrat tracing end-to-end and confirms:
//   - the real filesystem path (args[1]) is captured, NOT the dirfd or the
//     xattr name string at args[3];
//   - the syscall exit is READ-classified so the returned value size is
//     accounted as read bytes, consistent with getxattr/lgetxattr/fgetxattr.
func xattrGetxattrat() error {
	dir, cleanup, err := makeTempDir("xattr-getxattrat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	const xattrName = "user.ior"
	value := []byte("getxattrat-value")
	if err := syscall.Setxattr(path, xattrName, value, 0); err != nil {
		return fmt.Errorf("setxattr: %w", err)
	}

	if err := callGetxattrat(path, xattrName, len(value)); err != nil {
		return err
	}
	return nil
}

// callGetxattrat performs the raw getxattrat(AT_FDCWD, path, 0, name, args,
// sizeof(args)) call and verifies it returns the expected value size.
func callGetxattrat(path, name string, wantSize int) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}

	buf := make([]byte, 256)
	args := xattrArgs{
		value: uint64(uintptr(unsafe.Pointer(&buf[0]))),
		size:  uint32(len(buf)),
		flags: 0,
	}

	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	ret, _, errno := syscall.Syscall6(
		sysGetxattrat,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		0, // at_flags
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(&args)),
		unsafe.Sizeof(args),
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(&buf[0])
	runtime.KeepAlive(&args)
	if errno != 0 {
		return fmt.Errorf("getxattrat: %w", errno)
	}
	if int(ret) != wantSize {
		return fmt.Errorf("getxattrat returned %d, want %d", int(ret), wantSize)
	}
	return nil
}

// xattrListxattrat creates a file on tmpfs (/tmp), sets a user xattr on it, then
// lists that file's xattr names via the raw listxattrat(2) syscall with
// AT_FDCWD. This exercises ior's listxattrat tracing end-to-end and confirms:
//   - the real filesystem path (args[1]) is captured, NOT the dirfd;
//   - the syscall exit is READ-classified so the returned name-list size is
//     accounted as read bytes, consistent with listxattr/llistxattr/flistxattr.
func xattrListxattrat() error {
	dir, cleanup, err := makeTempDir("xattr-listxattrat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	const xattrName = "user.ior"
	if err := syscall.Setxattr(path, xattrName, []byte("listxattrat-value"), 0); err != nil {
		return fmt.Errorf("setxattr: %w", err)
	}

	// The returned list is the NUL-terminated xattr name, e.g. "user.ior\0".
	return callListxattrat(path, len(xattrName)+1)
}

// callListxattrat performs the raw listxattrat(AT_FDCWD, path, 0, list,
// sizeof(list)) call and verifies it returns at least the expected list size.
// The kernel may report additional system xattr names (e.g. "security.*"), so
// we assert the returned size is at least wantMinSize rather than exact.
func callListxattrat(path string, wantMinSize int) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}

	list := make([]byte, 256)
	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	ret, _, errno := syscall.Syscall6(
		sysListxattrat,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		0, // at_flags
		uintptr(unsafe.Pointer(&list[0])),
		uintptr(len(list)),
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(&list[0])
	if errno != 0 {
		return fmt.Errorf("listxattrat: %w", errno)
	}
	if int(ret) < wantMinSize {
		return fmt.Errorf("listxattrat returned %d, want at least %d", int(ret), wantMinSize)
	}
	return nil
}

// xattrRemovexattrat creates a file on tmpfs (/tmp), sets a user xattr on it,
// then removes that xattr via the raw removexattrat(2) syscall with AT_FDCWD.
// This exercises ior's removexattrat tracing end-to-end and confirms:
//   - the real filesystem path (args[1]) is captured, NOT the dirfd or the
//     xattr name string at args[3];
//   - the syscall exit is UNCLASSIFIED — removexattrat returns a 0/-1 status,
//     never a byte count, so no read bytes are attributed (contrast
//     getxattrat/listxattrat). This matches removexattr/lremovexattr/
//     fremovexattr.
func xattrRemovexattrat() error {
	dir, cleanup, err := makeTempDir("xattr-removexattrat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	const xattrName = "user.ior"
	if err := syscall.Setxattr(path, xattrName, []byte("removexattrat-value"), 0); err != nil {
		return fmt.Errorf("setxattr: %w", err)
	}

	return callRemovexattrat(path, xattrName)
}

// callRemovexattrat performs the raw removexattrat(AT_FDCWD, path, 0, name)
// call and verifies it succeeds (returns 0).
func callRemovexattrat(path, name string) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}

	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	ret, _, errno := syscall.Syscall6(
		sysRemovexattrat,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		0, // at_flags
		uintptr(unsafe.Pointer(nameBytes)),
		0,
		0,
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(nameBytes)
	if errno != 0 {
		return fmt.Errorf("removexattrat: %w", errno)
	}
	if int(ret) != 0 {
		return fmt.Errorf("removexattrat returned %d, want 0", int(ret))
	}
	return nil
}

// xattrName is the user-namespace attribute name used by every xattr scenario.
// User xattrs must live under the "user." prefix and are only permitted on
// regular files/dirs on a supporting filesystem (tmpfs satisfies this).
const xattrName = "user.ior"

// makeXattrFile creates an empty regular file under a fresh temp dir and sets a
// user.* xattr on it so subsequent get/list/remove syscalls have something to
// operate on. It returns the file path, the value that was set (so callers can
// assert the READ byte count), and the dir cleanup func.
func makeXattrFile(prefix string, value []byte) (string, func(), error) {
	dir, cleanup, err := makeTempDir(prefix)
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)
	if err := syscall.Setxattr(path, xattrName, value, 0); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("setxattr: %w", err)
	}
	return path, cleanup, nil
}

// xattrGetxattr creates a file, sets a user xattr on it, then reads that xattr
// back via the path-based getxattr(2) syscall (which FOLLOWS symlinks; here the
// path is a regular file). golang.org/x/sys/unix.Getxattr issues the raw
// syscall directly (no glibc redirection), so the enter_getxattr tracepoint
// fires with the file path at args[0] and the exit is READ-classified with the
// returned value size as the byte count, consistent with
// lgetxattr/fgetxattr/getxattrat.
func xattrGetxattr() error {
	value := []byte("getxattr-value")
	path, cleanup, err := makeXattrFile("xattr-getxattr", value)
	if err != nil {
		return err
	}
	defer cleanup()

	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, xattrName, buf)
	if err != nil {
		return fmt.Errorf("getxattr: %w", err)
	}
	if n != len(value) {
		return fmt.Errorf("getxattr returned %d, want %d", n, len(value))
	}
	return nil
}

// xattrLgetxattr is the no-follow counterpart of xattrGetxattr. lgetxattr(2)
// does NOT follow symlinks, but since the target path is a regular file (not a
// symlink) it behaves identically to getxattr and returns the value size — this
// is the deterministic way to fire the tracepoint, because user.* xattrs on a
// symlink itself are kernel-restricted (EPERM). The enter_lgetxattr tracepoint
// captures the file path at args[0]; the exit is READ-classified.
func xattrLgetxattr() error {
	value := []byte("lgetxattr-value")
	path, cleanup, err := makeXattrFile("xattr-lgetxattr", value)
	if err != nil {
		return err
	}
	defer cleanup()

	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, xattrName, buf)
	if err != nil {
		return fmt.Errorf("lgetxattr: %w", err)
	}
	if n != len(value) {
		return fmt.Errorf("lgetxattr returned %d, want %d", n, len(value))
	}
	return nil
}

// xattrListxattr creates a file, sets a user xattr on it, then lists the file's
// xattr names via the path-based listxattr(2) syscall. enter_listxattr captures
// the file path at args[0]; the exit is READ-classified with the NUL-separated
// name-list byte count (at least len("user.ior")+1), consistent with
// llistxattr/flistxattr/listxattrat.
func xattrListxattr() error {
	path, cleanup, err := makeXattrFile("xattr-listxattr", []byte("listxattr-value"))
	if err != nil {
		return err
	}
	defer cleanup()

	buf := make([]byte, 256)
	n, err := unix.Listxattr(path, buf)
	if err != nil {
		return fmt.Errorf("listxattr: %w", err)
	}
	if n < len(xattrName)+1 {
		return fmt.Errorf("listxattr returned %d, want at least %d", n, len(xattrName)+1)
	}
	return nil
}

// xattrLlistxattr is the no-follow counterpart of xattrListxattr. As with
// lgetxattr, the target is a regular file so llistxattr(2) returns the name-list
// size deterministically (user.* on a bare symlink is restricted).
// enter_llistxattr captures the file path; the exit is READ-classified.
func xattrLlistxattr() error {
	path, cleanup, err := makeXattrFile("xattr-llistxattr", []byte("llistxattr-value"))
	if err != nil {
		return err
	}
	defer cleanup()

	buf := make([]byte, 256)
	n, err := unix.Llistxattr(path, buf)
	if err != nil {
		return fmt.Errorf("llistxattr: %w", err)
	}
	if n < len(xattrName)+1 {
		return fmt.Errorf("llistxattr returned %d, want at least %d", n, len(xattrName)+1)
	}
	return nil
}

// xattrLsetxattr creates a file, sets an initial xattr, then updates it via the
// no-follow path-based lsetxattr(2) syscall. As with the other l* variants the
// target is a regular file, so lsetxattr succeeds (user.* on a bare symlink is
// restricted). enter_lsetxattr captures the file path at args[0]; the exit is
// UNCLASSIFIED — lsetxattr returns 0/-1, never a byte count (its `size` arg is
// the INPUT value length), exactly like setxattr/setxattrat/fsetxattr.
func xattrLsetxattr() error {
	path, cleanup, err := makeXattrFile("xattr-lsetxattr", []byte("lsetxattr-initial"))
	if err != nil {
		return err
	}
	defer cleanup()

	if err := unix.Lsetxattr(path, xattrName, []byte("lsetxattr-updated"), 0); err != nil {
		return fmt.Errorf("lsetxattr: %w", err)
	}
	return nil
}

// xattrSetxattrat creates a file then sets a user xattr on it via the raw
// setxattrat(2) syscall with AT_FDCWD. This exercises ior's setxattrat tracing
// end-to-end and confirms the real filesystem path (args[1]) is captured (NOT
// the dirfd or the xattr name at args[3]) and that the exit is UNCLASSIFIED
// (0/-1 status, never a byte count), matching setxattr/lsetxattr/fsetxattr.
// setxattrat is Linux 6.13+; if the kernel lacks it (ENOSYS) the scenario
// reports the error so the caller can treat it as best-effort.
func xattrSetxattrat() error {
	dir, cleanup, err := makeTempDir("xattr-setxattrat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	syscall.Close(fd)

	return callSetxattrat(path, xattrName, []byte("setxattrat-value"))
}

// callSetxattrat performs the raw setxattrat(AT_FDCWD, path, 0, name, args,
// sizeof(args)) call. The value to write is passed via struct xattr_args (its
// `size` field is the value length); the syscall returns 0 on success / -1 on
// error — never a byte count.
func callSetxattrat(path, name string, value []byte) error {
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	nameBytes, err := syscall.BytePtrFromString(name)
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}

	args := xattrArgs{
		value: uint64(uintptr(unsafe.Pointer(&value[0]))),
		size:  uint32(len(value)),
		flags: 0,
	}

	// Use a runtime int variable so the negative AT_FDCWD survives the uintptr
	// conversion: converting the negative constant directly overflows uintptr.
	dirfd := _AT_FDCWD
	ret, _, errno := syscall.Syscall6(
		sysSetxattrat,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		0, // at_flags
		uintptr(unsafe.Pointer(nameBytes)),
		uintptr(unsafe.Pointer(&args)),
		unsafe.Sizeof(args),
	)
	runtime.KeepAlive(pathBytes)
	runtime.KeepAlive(nameBytes)
	runtime.KeepAlive(&value[0])
	runtime.KeepAlive(&args)
	if errno != 0 {
		return fmt.Errorf("setxattrat: %w", errno)
	}
	if int(ret) != 0 {
		return fmt.Errorf("setxattrat returned %d, want 0", int(ret))
	}
	return nil
}

// xattrRemovexattr creates a file, sets a user xattr on it, then removes it via
// the path-based removexattr(2) syscall. enter_removexattr captures the file
// path at args[0] (NOT the xattr name at args[1]); the exit is UNCLASSIFIED —
// removexattr returns 0/-1, never a byte count, matching
// lremovexattr/fremovexattr/removexattrat.
func xattrRemovexattr() error {
	path, cleanup, err := makeXattrFile("xattr-removexattr", []byte("removexattr-value"))
	if err != nil {
		return err
	}
	defer cleanup()

	if err := unix.Removexattr(path, xattrName); err != nil {
		return fmt.Errorf("removexattr: %w", err)
	}
	return nil
}

// xattrLremovexattr is the no-follow counterpart of xattrRemovexattr. The target
// is a regular file, so lremovexattr(2) removes the user.* attr deterministically
// (user.* on a bare symlink is restricted). enter_lremovexattr captures the file
// path at args[0]; the exit is UNCLASSIFIED.
func xattrLremovexattr() error {
	path, cleanup, err := makeXattrFile("xattr-lremovexattr", []byte("lremovexattr-value"))
	if err != nil {
		return err
	}
	defer cleanup()

	if err := unix.Lremovexattr(path, xattrName); err != nil {
		return fmt.Errorf("lremovexattr: %w", err)
	}
	return nil
}

// xattrFd exercises the entire fd-based xattr family on an open file descriptor:
// fsetxattr (set), fgetxattr (READ), flistxattr (READ), then fremovexattr
// (remove). golang.org/x/sys/unix issues the raw syscalls directly, so each
// tracepoint fires with the FD at args[0] (kind=fd, no path). fgetxattr and
// flistxattr are READ-classified (return value/name-list sizes); fsetxattr and
// fremovexattr are UNCLASSIFIED (return 0/-1 status).
func xattrFd() error {
	dir, cleanup, err := makeTempDir("xattr-fd")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "xattrfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	value := []byte("fxattr-value")
	if err := unix.Fsetxattr(fd, xattrName, value, 0); err != nil {
		return fmt.Errorf("fsetxattr: %w", err)
	}

	buf := make([]byte, 256)
	n, err := unix.Fgetxattr(fd, xattrName, buf)
	if err != nil {
		return fmt.Errorf("fgetxattr: %w", err)
	}
	if n != len(value) {
		return fmt.Errorf("fgetxattr returned %d, want %d", n, len(value))
	}

	list := make([]byte, 256)
	ln, err := unix.Flistxattr(fd, list)
	if err != nil {
		return fmt.Errorf("flistxattr: %w", err)
	}
	if ln < len(xattrName)+1 {
		return fmt.Errorf("flistxattr returned %d, want at least %d", ln, len(xattrName)+1)
	}

	if err := unix.Fremovexattr(fd, xattrName); err != nil {
		return fmt.Errorf("fremovexattr: %w", err)
	}
	return nil
}
