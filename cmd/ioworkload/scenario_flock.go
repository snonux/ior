package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// flockBasic exercises the flock syscall end-to-end. It opens a temp file,
// acquires an exclusive advisory lock (LOCK_EX), releases it (LOCK_UN), then
// closes the file and removes the temp dir.
//
// flock is unprivileged (FamilyFS) and captured as KindFd at args[0]; ior
// resolves that fd to the underlying file path via the procfd cache, so the
// enter_flock record carries the temp filename. Its return value is
// UNCLASSIFIED (0 on success), so this scenario only locks in the enter path.
func flockBasic() error {
	dir, cleanup, err := makeTempDir("flock-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "flockfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use raw syscall.Flock so the exact sys_enter_flock tracepoint fires.
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock LOCK_EX: %w", err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_UN); err != nil {
		return fmt.Errorf("flock LOCK_UN: %w", err)
	}
	return nil
}
