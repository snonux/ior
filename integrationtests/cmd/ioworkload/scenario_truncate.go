package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// truncateBasic opens a file, writes data, then truncates it via
// syscall.Truncate which uses SYS_TRUNCATE directly on amd64 (path-based).
func truncateBasic() error {
	dir, cleanup, err := makeTempDir("truncate-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "truncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if _, err := syscall.Write(fd, []byte("truncate this content")); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("write: %w", err)
	}
	syscall.Close(fd)

	return syscall.Truncate(path, 5)
}

// truncateFtruncate opens a file, writes data, then truncates it via
// syscall.Ftruncate which uses SYS_FTRUNCATE directly on amd64 (fd-based).
func truncateFtruncate() error {
	dir, cleanup, err := makeTempDir("truncate-ftruncate")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "ftruncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if _, err := syscall.Write(fd, []byte("ftruncate this content")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return syscall.Ftruncate(fd, 5)
}

// truncateEnoent attempts to truncate a nonexistent file via raw SYS_TRUNCATE.
// The syscall fails with ENOENT, but ior captures the enter_truncate
// tracepoint because the path is read on entry.
func truncateEnoent() error {
	dir, cleanup, err := makeTempDir("truncate-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "truncate-enoent-missing.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_TRUNCATE, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
	runtime.KeepAlive(pathBytes)
	if errno == 0 {
		return fmt.Errorf("expected ENOENT, but truncate succeeded")
	}
	return nil
}

// truncateFtruncateEbadf calls raw SYS_FTRUNCATE on an invalid fd (99999).
// The syscall fails with EBADF, but ior captures the enter_ftruncate
// tracepoint because it is recorded on syscall entry.
func truncateFtruncateEbadf() error {
	_, _, errno := syscall.Syscall(syscall.SYS_FTRUNCATE, 99999, 0, 0)
	if errno == 0 {
		return fmt.Errorf("expected EBADF, but ftruncate succeeded")
	}
	return nil
}
