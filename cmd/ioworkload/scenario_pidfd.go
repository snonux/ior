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

// pidfdSendSignal opens a pidfd for the current process and issues a
// pidfd_send_signal liveness probe against it. Signal 0 is a special "no signal"
// value: the kernel performs only the permission/existence checks and delivers
// NOTHING, so targeting our own process is completely safe (no signal handler
// runs and the process is not affected). The scenario exercises the enter
// fd_event (pidfd at args[0]) and the exit ret_event (UNCLASSIFIED) end-to-end.
func pidfdSendSignal() error {
	pidfd, err := pidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open self: %w", err)
	}
	defer syscall.Close(pidfd)

	// pidfd_send_signal(pidfd, sig=0, info=NULL, flags=0): liveness probe only.
	if err := pidfdSendSignalRaw(pidfd, 0, 0, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal: %w", err)
	}
	return nil
}

func pidfdOpen(pid int, flags uintptr) (int, error) {
	syscallNr, err := pidfdOpenSyscallNr()
	if err != nil {
		return 0, err
	}
	fd, _, errno := syscall.Syscall(syscallNr, uintptr(pid), flags, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

func pidfdGetfd(pidfd int, targetFd int, flags uintptr) (int, error) {
	syscallNr, err := pidfdGetfdSyscallNr()
	if err != nil {
		return 0, err
	}
	fd, _, errno := syscall.Syscall(
		syscallNr,
		uintptr(pidfd),
		uintptr(targetFd),
		flags,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(fd), nil
}

func pidfdOpenSyscallNr() (uintptr, error) {
	return pidfdOpenSyscallNrForArch(runtime.GOARCH)
}

func pidfdGetfdSyscallNr() (uintptr, error) {
	return pidfdGetfdSyscallNrForArch(runtime.GOARCH)
}

func pidfdSendSignalRaw(pidfd int, sig int, info uintptr, flags uintptr) error {
	syscallNr, err := pidfdSendSignalSyscallNr()
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscallNr,
		uintptr(pidfd),
		uintptr(sig),
		info,
		flags,
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func pidfdSendSignalSyscallNr() (uintptr, error) {
	return pidfdSendSignalSyscallNrForArch(runtime.GOARCH)
}

func pidfdOpenSyscallNrForArch(arch string) (uintptr, error) {
	// Go's syscall package does not expose pidfd constants on all toolchains.
	switch arch {
	case "amd64", "arm64":
		return 434, nil
	default:
		return 0, fmt.Errorf("pidfd_open syscall number not defined for GOARCH=%s", arch)
	}
}

func pidfdGetfdSyscallNrForArch(arch string) (uintptr, error) {
	// Go's syscall package does not expose pidfd constants on all toolchains.
	switch arch {
	case "amd64", "arm64":
		return 438, nil
	default:
		return 0, fmt.Errorf("pidfd_getfd syscall number not defined for GOARCH=%s", arch)
	}
}

func pidfdSendSignalSyscallNrForArch(arch string) (uintptr, error) {
	// Go's syscall package does not expose pidfd constants on all toolchains.
	switch arch {
	case "amd64", "arm64":
		return 424, nil
	default:
		return 0, fmt.Errorf("pidfd_send_signal syscall number not defined for GOARCH=%s", arch)
	}
}
