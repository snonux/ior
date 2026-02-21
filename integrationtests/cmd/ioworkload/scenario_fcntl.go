package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

// fcntlDupfd uses fcntl F_DUPFD to duplicate a file descriptor.
func fcntlDupfd() error {
	dir, cleanup, err := makeTempDir("fcntl-dupfd")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_DUPFD: %w", errno)
	}
	defer syscall.Close(int(newFd))

	if _, err := syscall.Write(int(newFd), []byte("via fcntl")); err != nil {
		return fmt.Errorf("write via fcntl dup: %w", err)
	}
	return nil
}

// fcntlSetfl uses fcntl F_GETFL/F_SETFL to read and modify file status flags.
func fcntlSetfl() error {
	dir, cleanup, err := makeTempDir("fcntl-setfl")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlsetflfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_GETFL: %w", errno)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_SETFL, flags|syscall.O_APPEND)
	if errno != 0 {
		return fmt.Errorf("fcntl F_SETFL: %w", errno)
	}

	if _, err := syscall.Write(fd, []byte("appended via fcntl setfl")); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// fcntlDupfdCloexec uses fcntl F_DUPFD_CLOEXEC to duplicate a file descriptor
// with the close-on-exec flag set.
func fcntlDupfdCloexec() error {
	dir, cleanup, err := makeTempDir("fcntl-dupfd-cloexec")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntlcloexecfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	newFd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return fmt.Errorf("fcntl F_DUPFD_CLOEXEC: %w", errno)
	}
	defer syscall.Close(int(newFd))

	if _, err := syscall.Write(int(newFd), []byte("via fcntl dupfd cloexec")); err != nil {
		return fmt.Errorf("write via fcntl dup cloexec: %w", err)
	}
	return nil
}

// fcntlInvalidFd calls fcntl F_GETFL on an invalid fd (99999).
// The syscall fails with EBADF, but ior should capture the enter_fcntl
// tracepoint because it is recorded on syscall entry.
func fcntlInvalidFd() error {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 99999, syscall.F_GETFL, 0)
	if errno == 0 {
		return fmt.Errorf("expected fcntl on invalid fd to fail")
	}
	return nil
}

// fcntlDupfdMax opens a file and calls fcntl F_DUPFD with a minfd value
// that exceeds the process RLIMIT_NOFILE. The kernel rejects this with
// EINVAL, but ior should capture the enter_fcntl tracepoint.
func fcntlDupfdMax() error {
	dir, cleanup, err := makeTempDir("fcntl-dupfd-max")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "fcntldupfdmaxfile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	// Use a minfd far beyond any realistic RLIMIT_NOFILE.
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD, 1<<30)
	if errno == 0 {
		return fmt.Errorf("expected fcntl F_DUPFD with extreme minfd to fail")
	}
	return nil
}
