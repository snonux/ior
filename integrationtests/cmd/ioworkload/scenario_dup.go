package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// dupBasic opens a file, dups the fd, writes via the dup, closes both.
func dupBasic() error {
	dir, cleanup, err := makeTempDir("dup-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dupfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, err := syscall.Dup(fd)
	if err != nil {
		return fmt.Errorf("dup: %w", err)
	}
	defer syscall.Close(newFd)

	if _, err := syscall.Write(newFd, []byte("via dup")); err != nil {
		return fmt.Errorf("write via dup: %w", err)
	}
	return nil
}

// dupDup2 opens a file and duplicates the fd onto a specific target fd via dup2.
func dupDup2() error {
	dir, cleanup, err := makeTempDir("dup-dup2")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup2file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use a high fd number to avoid collisions.
	targetFd := 500
	if err := syscall.Dup2(fd, targetFd); err != nil {
		return fmt.Errorf("dup2: %w", err)
	}
	defer syscall.Close(targetFd)

	if _, err := syscall.Write(targetFd, []byte("via dup2")); err != nil {
		return fmt.Errorf("write via dup2: %w", err)
	}
	return nil
}

// dupDup3 opens a file and duplicates the fd onto a specific target fd via dup3
// with O_CLOEXEC flag.
func dupDup3() error {
	dir, cleanup, err := makeTempDir("dup-dup3")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup3file.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use a high fd number to avoid collisions.
	targetFd := 501
	if err := syscall.Dup3(fd, targetFd, syscall.O_CLOEXEC); err != nil {
		return fmt.Errorf("dup3: %w", err)
	}
	defer syscall.Close(targetFd)

	if _, err := syscall.Write(targetFd, []byte("via dup3")); err != nil {
		return fmt.Errorf("write via dup3: %w", err)
	}
	return nil
}

// dupInvalidFd attempts to dup a very high invalid fd number.
// The syscall fails with EBADF, but ior should capture the enter_dup
// tracepoint because arguments are read on syscall entry.
func dupInvalidFd() error {
	_, err := syscall.Dup(99999)
	if err == nil {
		return fmt.Errorf("expected dup of invalid fd to fail")
	}
	return nil
}

// dup2SameFd calls dup2 with the same fd for both oldfd and newfd.
// Per POSIX, dup2(fd, fd) is a no-op that returns fd without closing
// and reopening. ior should capture the enter_dup2 tracepoint.
func dup2SameFd() error {
	dir, cleanup, err := makeTempDir("dup2-same-fd")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup2samefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.Dup2(fd, fd); err != nil {
		return fmt.Errorf("dup2 same fd: %w", err)
	}
	return nil
}

// dup3InvalidFlags calls dup3 with an invalid flags value.
// dup3 only accepts O_CLOEXEC; any other flag causes EINVAL.
// ior should capture the enter_dup3 tracepoint.
func dup3InvalidFlags() error {
	dir, cleanup, err := makeTempDir("dup3-invalid-flags")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "dup3flagsfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	targetFd := 502
	_, _, errno := syscall.Syscall(syscall.SYS_DUP3, uintptr(fd), uintptr(targetFd), 0xBAD)
	if errno == 0 {
		syscall.Close(targetFd)
		return fmt.Errorf("expected dup3 with invalid flags to fail")
	}
	return nil
}
