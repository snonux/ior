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

// ioctlBasic issues a benign, deterministic ioctl on a known fd so the
// enter_ioctl tracepoint fires under our control rather than only implicitly
// (via the Go runtime / terminal). ioctl is FamilyFS / KindFd (fd@arg0), so
// the captured event resolves the fd to the temp file path.
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
