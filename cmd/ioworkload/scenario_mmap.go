package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// mmapBasic creates a file-backed shared mapping.
// mmap(2) allows closing the fd after mapping without invalidating the mapping.
func mmapBasic() error {
	dir, cleanup, err := makeTempDir("mmap-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "mmapfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("mmap shared page data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	copy(mapped[:4], []byte("MMAP"))
	return nil
}

// mmapMsyncSync maps a file and flushes modifications via msync(2).
// Per msync(2), callers should specify exactly one of MS_SYNC or MS_ASYNC.
func mmapMsyncSync() error {
	dir, cleanup, err := makeTempDir("mmap-msync-sync")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "msyncfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("msync shared page data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	copy(mapped[:5], []byte("MSYNC"))

	_, _, errno := syscall.Syscall(syscall.SYS_MSYNC, uintptr(unsafe.Pointer(&mapped[0])), uintptr(len(mapped)), uintptr(syscall.MS_SYNC))
	if errno != 0 {
		return fmt.Errorf("msync: %w", errno)
	}
	return nil
}

// mmapMsyncInvalidFlags calls msync(2) with both MS_SYNC and MS_ASYNC.
// The kernel returns EINVAL, but enter_msync should still be captured.
func mmapMsyncInvalidFlags() error {
	dir, cleanup, err := makeTempDir("mmap-msync-invalid-flags")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "msyncinvalidfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	data := []byte("msync invalid flags data")
	if _, err := syscall.Write(fd, data); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	mapped, err := syscall.Mmap(fd, 0, len(data), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(mapped)

	flags := syscall.MS_SYNC | syscall.MS_ASYNC
	_, _, errno := syscall.Syscall(syscall.SYS_MSYNC, uintptr(unsafe.Pointer(&mapped[0])), uintptr(len(mapped)), uintptr(flags))
	if errno != syscall.EINVAL {
		return fmt.Errorf("expected EINVAL from msync with both MS_SYNC|MS_ASYNC, got %v", errno)
	}
	return nil
}
