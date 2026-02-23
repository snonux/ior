package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// pidfdGetfdSuccess duplicates an existing file descriptor through pidfd_getfd.
func pidfdGetfdSuccess() error {
	dir, cleanup, err := makeTempDir("pidfd-getfd-success")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "pidfd-getfd-source.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer syscall.Close(fd)

	pidfd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open self: %w", err)
	}
	defer syscall.Close(pidfd)

	dupFd, err := pidfdGetfd(pidfd, fd, 0)
	if err != nil {
		return fmt.Errorf("pidfd_getfd: %w", err)
	}

	if _, err := syscall.Write(dupFd, []byte("via pidfd_getfd")); err != nil {
		syscall.Close(dupFd)
		return fmt.Errorf("write dup fd: %w", err)
	}

	// Keep the duplicated fd alive briefly so eventloop can resolve /proc fd path.
	time.Sleep(500 * time.Millisecond)
	if err := syscall.Close(dupFd); err != nil {
		return fmt.Errorf("close dup fd: %w", err)
	}
	return nil
}

// pidfdGetfdFailure performs a guaranteed-failing pidfd_getfd call while
// also probing a cross-process call that may fail under ptrace/Yama policy.
func pidfdGetfdFailure() error {
	pidfd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open self: %w", err)
	}
	defer syscall.Close(pidfd)

	// Best-effort probe. Depending on kernel ptrace/Yama policy, this may fail
	// with EPERM/EACCES; if it succeeds we close the returned fd and continue.
	if initPidfd, err := pidfdOpen(1, 0); err == nil {
		func() {
			defer syscall.Close(initPidfd)
			if probeFd, err := pidfdGetfd(initPidfd, 1, 0); err == nil {
				syscall.Close(probeFd)
			}
		}()
	}

	_, err = pidfdGetfd(pidfd, 99999, 0)
	if err == nil {
		return fmt.Errorf("expected pidfd_getfd with invalid source fd to fail")
	}
	return nil
}

func pidfdOpen(pid int, flags uintptr) (int, error) {
	fd, _, errno := syscall.Syscall(pidfdOpenSyscallNr(), uintptr(pid), flags, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

func pidfdGetfd(pidfd int, targetFd int, flags uintptr) (int, error) {
	fd, _, errno := syscall.Syscall(
		pidfdGetfdSyscallNr(),
		uintptr(pidfd),
		uintptr(targetFd),
		flags,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

func pidfdOpenSyscallNr() uintptr {
	// Go's syscall package does not expose pidfd constants on all toolchains.
	if runtime.GOARCH == "amd64" {
		return 434
	}
	if runtime.GOARCH == "arm64" {
		return 434
	}
	panic("pidfd_open syscall number not defined for GOARCH=" + runtime.GOARCH)
}

func pidfdGetfdSyscallNr() uintptr {
	// Go's syscall package does not expose pidfd constants on all toolchains.
	if runtime.GOARCH == "amd64" {
		return 438
	}
	if runtime.GOARCH == "arm64" {
		return 438
	}
	panic("pidfd_getfd syscall number not defined for GOARCH=" + runtime.GOARCH)
}
