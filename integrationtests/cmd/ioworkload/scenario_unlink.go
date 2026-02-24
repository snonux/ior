package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// unlinkBasic creates a file and unlinks it via raw SYS_UNLINK.
// We use the raw syscall because Go's syscall.Unlink wraps unlinkat on amd64.
func unlinkBasic() error {
	dir, cleanup, err := makeTempDir("unlink-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "unlinkme.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINK, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
	runtime.KeepAlive(pathBytes)
	if errno != 0 {
		return fmt.Errorf("unlink: %w", errno)
	}
	return nil
}

// unlinkUnlinkat creates a file and unlinks it via unlinkat(2).
func unlinkUnlinkat() error {
	dir, cleanup, err := makeTempDir("unlink-unlinkat")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "unlinkat-file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	nameBytes, err := syscall.BytePtrFromString("unlinkat-file.txt")
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirFD), uintptr(unsafe.Pointer(nameBytes)), 0)
	runtime.KeepAlive(nameBytes)
	if errno != 0 {
		return fmt.Errorf("unlinkat: %w", errno)
	}
	return nil
}

// unlinkRmdir creates a directory and removes it via raw SYS_RMDIR.
// We use the raw syscall because Go's syscall.Rmdir wraps unlinkat on amd64.
func unlinkRmdir() error {
	dir, cleanup, err := makeTempDir("unlink-rmdir")
	if err != nil {
		return err
	}
	defer cleanup()

	// Retry with fresh paths to avoid a single one-shot syscall that can race
	// tracepoint attach during parallel integration test startup.
	for i := 0; i < 5; i++ {
		subDir := filepath.Join(dir, fmt.Sprintf("rmdir-me-%d", i))
		if err := syscall.Mkdir(subDir, 0o755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}

		pathBytes, err := syscall.BytePtrFromString(subDir)
		if err != nil {
			return fmt.Errorf("path bytes: %w", err)
		}
		_, _, errno := syscall.Syscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
		runtime.KeepAlive(pathBytes)
		if errno != 0 {
			return fmt.Errorf("rmdir: %w", errno)
		}
	}
	return nil
}

// unlinkEnoent attempts to unlink a nonexistent file via raw SYS_UNLINK.
// The syscall fails with ENOENT, but ior captures the tracepoint on entry.
func unlinkEnoent() error {
	dir, cleanup, err := makeTempDir("unlink-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "unlink-enoent-missing.txt")
	pathBytes, err := syscall.BytePtrFromString(path)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_UNLINK, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
		runtime.KeepAlive(pathBytes)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but unlink succeeded")
		}
	}
	return nil
}

// unlinkRmdirNotempty attempts to rmdir a non-empty directory via raw SYS_RMDIR.
// The syscall fails with ENOTEMPTY, but ior captures the tracepoint on entry.
func unlinkRmdirNotempty() error {
	dir, cleanup, err := makeTempDir("unlink-rmdir-notempty")
	if err != nil {
		return err
	}
	defer cleanup()

	subDir := filepath.Join(dir, "rmdir-notempty")
	if err := syscall.Mkdir(subDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	// Create a file inside so the directory is non-empty.
	filePath := filepath.Join(subDir, "blocker.txt")
	fd, err := syscall.Open(filePath, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("create blocker: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close blocker: %w", err)
	}

	pathBytes, err := syscall.BytePtrFromString(subDir)
	if err != nil {
		return fmt.Errorf("path bytes: %w", err)
	}
	_, _, errno := syscall.Syscall(syscall.SYS_RMDIR, uintptr(unsafe.Pointer(pathBytes)), 0, 0)
	runtime.KeepAlive(pathBytes)
	if errno == 0 {
		return fmt.Errorf("expected ENOTEMPTY, but rmdir succeeded")
	}
	return nil
}

// unlinkUnlinkatEnoent attempts to unlinkat a nonexistent file.
// The syscall fails with ENOENT, but ior captures the tracepoint on entry.
func unlinkUnlinkatEnoent() error {
	dir, cleanup, err := makeTempDir("unlink-unlinkat-enoent")
	if err != nil {
		return err
	}
	defer cleanup()

	dirFD, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer syscall.Close(dirFD)

	nameBytes, err := syscall.BytePtrFromString("unlinkat-enoent-missing.txt")
	if err != nil {
		return fmt.Errorf("name bytes: %w", err)
	}
	for i := 0; i < 5; i++ {
		_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(dirFD), uintptr(unsafe.Pointer(nameBytes)), 0)
		runtime.KeepAlive(nameBytes)
		if errno == 0 {
			return fmt.Errorf("expected ENOENT, but unlinkat succeeded")
		}
	}
	return nil
}
