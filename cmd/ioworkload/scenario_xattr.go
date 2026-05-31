package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
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
