package main

import (
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// fionread is the FIONREAD ioctl request (number of bytes available to read).
// golang.org/x/sys/unix does not export it as a portable constant, so we define
// it here. The value 0x541B is shared by the architectures this project targets
// (amd64, arm64; see scenario_mountfs.go's listns arch table).
const fionread = 0x541B

// fionclex and fioclex are FIONCLEX/FIOCLEX from <asm-generic/ioctls.h>
// (shared by amd64 and arm64; x/sys/unix does not export them). They clear
// and set the descriptor's close-on-exec flag, like fcntl F_SETFD.
const (
	fionclex = 0x5450
	fioclex  = 0x5451
)

// ioctlBasic issues a benign, deterministic ioctl on a known fd so the
// enter_ioctl tracepoint fires under our control rather than only implicitly
// (via the Go runtime / terminal). ioctl is FamilyFS / KindFcntl (fd@arg0,
// cmd@arg1, arg@arg2; the cmd lets ior track FIOCLEX/FIONCLEX), so the
// captured event resolves the fd to the temp file path.
//
// We open a regular temp file and call FIONREAD via unix.IoctlGetInt, which
// reports the number of bytes available to read. On a regular file this is a
// harmless query that does not mutate state; we ignore its result. The file is
// cleaned up via the deferred cleanup.
func ioctlBasic() error {
	dir, cleanup, err := makeTempDir("ioctl-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "ioctlfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// FIONREAD on a regular file is safe and portable. Even if the kernel
	// rejects it for this fd type, the enter_ioctl tracepoint fires on syscall
	// entry, so coverage holds regardless of the return value.
	if _, err := unix.IoctlGetInt(fd, fionread); err != nil {
		// Tolerated: the sys_enter_ioctl tracepoint has already fired.
		return nil
	}
	return nil
}

// ioctlCloexec toggles close-on-exec with ioctl FIOCLEX and then FIONCLEX on a
// descriptor opened without O_CLOEXEC, writing after each toggle. ior can only
// report O_CLOEXEC on the first write, and not on the second, if the
// generated sys_enter_ioctl handler captures the ioctl cmd and userspace
// applies it to the tracked fd, so the integration test checks exactly the
// cmd capture end to end. F_GETFD after each toggle guards that the kernel
// agrees with what the test expects.
func ioctlCloexec() error {
	dir, cleanup, err := makeTempDir("ioctl-cloexec")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "ioctlcloexecfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if err := ioctlToggleAndWrite(fd, fioclex, true, "after FIOCLEX"); err != nil {
		return err
	}
	return ioctlToggleAndWrite(fd, fionclex, false, "after FIONCLEX")
}

// ioctlToggleAndWrite issues one FIOCLEX/FIONCLEX request, verifies the
// resulting FD_CLOEXEC state with F_GETFD, and writes msg through fd so the
// tracer's next fd row exposes the tracked state.
func ioctlToggleAndWrite(fd int, req uintptr, wantCloexec bool, msg string) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, 0); errno != 0 {
		return fmt.Errorf("ioctl %#x: %w", req, errno)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_GETFD %s: %w", msg, errno)
	}
	if got := flags&syscall.FD_CLOEXEC != 0; got != wantCloexec {
		return fmt.Errorf("fcntl F_GETFD %s: FD_CLOEXEC = %v, want %v", msg, got, wantCloexec)
	}
	if _, err := syscall.Write(fd, []byte(msg)); err != nil {
		return fmt.Errorf("write %s: %w", msg, err)
	}
	return nil
}
