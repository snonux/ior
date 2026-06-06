package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// chownBasic drives the chown ownership-change family end-to-end on a file and
// a symlink the caller owns. Every call passes owner/group -1/-1 ("don't
// change either id"), which the kernel accepts without CAP_CHOWN, so the whole
// scenario is UNPRIVILEGED and nothing is actually modified. It exercises, in
// order:
//
//   - chown(path, -1, -1)               — path at args[0], KindPathname, FamilyFS
//   - lchown(symlink, -1, -1)           — path at args[0], KindPathname, FamilyFS
//   - fchownat(AT_FDCWD, path, -1,-1,0) — path at args[1], KindPathname, FamilyFS
//   - fchown(fd, -1, -1)                — fd   at args[0], KindFd,       FamilyFS
//
// We use raw syscalls (rather than os.Chown / syscall.Chown etc.) so each
// distinct tracepoint actually fires; glibc/Go wrappers can redirect chown to
// fchownat and hide the syscall under test. The temp file and symlink are
// cleaned up afterwards.
func chownBasic() error {
	dir, cleanup, err := makeTempDir("chown-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "chownfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	symlink := filepath.Join(dir, "chownlink")
	if err := syscall.Symlink(path, symlink); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	symlinkBytes, err := syscall.BytePtrFromString(symlink)
	if err != nil {
		return fmt.Errorf("symlink bytes: %w", err)
	}

	if err := callChown(pathBytes); err != nil {
		return err
	}
	if err := callLchown(symlinkBytes); err != nil {
		return err
	}
	if err := callFchownat(pathBytes); err != nil {
		return err
	}
	if err := callFchown(fd); err != nil {
		return err
	}
	return nil
}

// callChown issues raw chown(path, -1, -1). chown takes the filesystem path at
// args[0], so ior captures it as a KindPathname event under enter_chown. Owner
// and group -1 mean "leave both unchanged", so no CAP_CHOWN is required.
func callChown(pathBytes *byte) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_CHOWN,
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(_UID_NOCHANGE),
		uintptr(_GID_NOCHANGE),
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("chown: %w", errno)
	}
	return nil
}

// callLchown issues raw lchown(symlink, -1, -1). Like chown the path is at
// args[0] (KindPathname), but lchown acts on the symlink itself rather than its
// target. The -1/-1 owner/group keep it unprivileged.
func callLchown(symlinkBytes *byte) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_LCHOWN,
		uintptr(unsafe.Pointer(symlinkBytes)),
		uintptr(_UID_NOCHANGE),
		uintptr(_GID_NOCHANGE),
	)
	runtime.KeepAlive(symlinkBytes)
	if errno != 0 {
		return fmt.Errorf("lchown: %w", errno)
	}
	return nil
}

// callFchownat issues raw fchownat(AT_FDCWD, path, -1, -1, 0). The path is at
// args[1] (after the dirfd), so ior captures it as a KindPathname event under
// enter_fchownat. A runtime int holds AT_FDCWD so the negative value survives
// the uintptr conversion instead of overflowing.
func callFchownat(pathBytes *byte) error {
	dirfd := _AT_FDCWD
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FCHOWNAT,
		uintptr(dirfd),
		uintptr(unsafe.Pointer(pathBytes)),
		uintptr(_UID_NOCHANGE),
		uintptr(_GID_NOCHANGE),
		0, // flags
		0,
	)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("fchownat: %w", errno)
	}
	return nil
}

// callFchown issues raw fchown(fd, -1, -1). fchown operates on an open fd at
// args[0] (KindFd) and carries no path, so ior records enter_fchown keyed by
// the descriptor rather than a filename.
func callFchown(fd int) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_FCHOWN,
		uintptr(fd),
		uintptr(_UID_NOCHANGE),
		uintptr(_GID_NOCHANGE),
	)
	if errno != 0 {
		return fmt.Errorf("fchown: %w", errno)
	}
	return nil
}

// _UID_NOCHANGE and _GID_NOCHANGE are the (uid_t)-1 / (gid_t)-1 sentinels that
// tell the chown family "leave this id unchanged". Using them for both owner
// and group means the call performs no ownership change and therefore needs no
// CAP_CHOWN, keeping the scenario fully unprivileged. They are -1 cast to the
// unsigned 32-bit id types, i.e. 0xFFFFFFFF, which we form directly so the
// value passed through uintptr is the kernel's expected (uid_t)-1.
const (
	_UID_NOCHANGE uint32 = 0xFFFFFFFF
	_GID_NOCHANGE uint32 = 0xFFFFFFFF
)
