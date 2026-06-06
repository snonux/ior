package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// sysFchmodat2 is syscall number 452 on amd64 (added in Linux 6.6). Go's
// syscall package does not export SYS_FCHMODAT2, so we invoke it by its raw
// number. Its signature is:
//
//	fchmodat2(int dfd, const char *pathname, mode_t mode, unsigned int flags)
//
// Like fchmodat, the filesystem PATH is at args[1] (after the dirfd), so ior
// must capture it as a path event (KindPathname) and tag it FamilyFS. fchmodat2
// adds an explicit flags argument (e.g. AT_SYMLINK_NOFOLLOW) that plain
// fchmodat lacks. On kernels older than 6.6 the syscall returns ENOSYS, so the
// caller treats it as best-effort and only asserts the older siblings.
const sysFchmodat2 = 452

// chmodBasic drives the chmod permission-change family end-to-end on a file the
// caller owns, so every call is UNPRIVILEGED. It exercises, in order:
//
//   - chmod(path, mode)            — path at args[0], KindPathname, FamilyFS
//   - fchmodat(AT_FDCWD, path, …)  — path at args[1], KindPathname, FamilyFS
//   - fchmod(fd, mode)             — fd at args[0],   KindFd,       FamilyFS
//   - fchmodat2(AT_FDCWD, path, …) — path at args[1], KindPathname (best-effort)
//
// We use raw syscalls (rather than syscall.Chmod etc.) so each distinct
// tracepoint actually fires; glibc/Go wrappers can redirect chmod to fchmodat
// and hide the syscall under test. The modes are harmless (0644 → 0640 → 0644),
// so nothing destructive happens, and the temp file is cleaned up.
func chmodBasic() error {
	dir, cleanup, err := makeTempDir("chmod-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "chmodfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}

	if err := callChmod(pathBytes); err != nil {
		return err
	}
	if err := callFchmodat(pathBytes); err != nil {
		return err
	}
	if err := callFchmod(fd); err != nil {
		return err
	}
	// fchmodat2 is best-effort: ENOSYS on kernels < 6.6 is tolerated.
	if err := callFchmodat2(pathBytes); err != nil {
		return err
	}
	return nil
}

// callChmod issues raw chmod(path, 0640). chmod takes the filesystem path at
// args[0], so ior captures it as a KindPathname event under enter_chmod.
func callChmod(pathBytes *byte) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_CHMOD,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(0o640),
		0,
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("chmod: %w", errno)
	}
	return nil
}

// callFchmodat issues raw fchmodat(AT_FDCWD, path, 0644, 0). The path is at
// args[1] (after the dirfd), so ior captures it as a KindPathname event under
// enter_fchmodat. A runtime int holds AT_FDCWD so the negative value survives
// the uintptr conversion instead of overflowing.
func callFchmodat(pathBytes *byte) error {
	dirfd := _AT_FDCWD
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FCHMODAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(0o644),
		0, // flags
		0,
		0,
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("fchmodat: %w", errno)
	}
	return nil
}

// callFchmod issues raw fchmod(fd, 0644). fchmod operates on an open fd at
// args[0] (KindFd) and carries no path, so ior records enter_fchmod keyed by
// the descriptor rather than a filename.
func callFchmod(fd int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_FCHMOD,
		uintptr(fd),
		uintptr(0o644),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("fchmod: %w", errno)
	}
	return nil
}

// callFchmodat2 issues raw fchmodat2(AT_FDCWD, path, 0640, 0). The path is at
// args[1], so it is KindPathname like fchmodat. fchmodat2 is best-effort: on
// kernels older than 6.6 it returns ENOSYS, which we tolerate rather than fail.
func callFchmodat2(pathBytes *byte) error {
	dirfd := _AT_FDCWD
	_, _, errno := syscall.Syscall6(
		sysFchmodat2,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(0o640),
		0, // flags
		0,
		0,
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 && errno != syscall.ENOSYS {
		return fmt.Errorf("fchmodat2: %w", errno)
	}
	return nil
}
