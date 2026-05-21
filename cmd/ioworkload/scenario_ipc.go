package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func pipeBasic() error {
	var pipefd [2]int
	if err := syscall.Pipe(pipefd[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(pipefd[0])
	defer syscall.Close(pipefd[1])
	return nil
}

func pipe2Basic() error {
	var pipefd [2]int
	flags := syscall.O_CLOEXEC | syscall.O_NONBLOCK
	if err := syscall.Pipe2(pipefd[:], flags); err != nil {
		return fmt.Errorf("pipe2: %w", err)
	}
	defer syscall.Close(pipefd[0])
	defer syscall.Close(pipefd[1])
	return nil
}

func eventfdBasic() error {
	fd, err := createEventfd(syscall.SYS_EVENTFD, 1, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return nil
}

func eventfd2Basic() error {
	flags := uintptr(unix.EFD_CLOEXEC | unix.EFD_NONBLOCK)
	fd, err := createEventfd(syscall.SYS_EVENTFD2, 1, flags)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return nil
}

func createEventfd(number uintptr, initval, flags uintptr) (int, error) {
	fd, _, errno := syscall.RawSyscall(number, initval, flags, 0)
	if errno != 0 {
		return -1, fmt.Errorf("eventfd syscall %d: %w", number, errno)
	}
	return int(fd), nil
}

func fdFromAirEventfdUsers() error {
	memfdName, err := syscall.BytePtrFromString("ior-memfd")
	if err != nil {
		return fmt.Errorf("memfd name: %w", err)
	}
	fd, _, _ := syscall.RawSyscall(unix.SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(memfdName)), uintptr(unix.MFD_CLOEXEC), 0)
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_MEMFD_SECRET, 0, 0, 0)
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC), 0, 0)
	closeIfValid(int(fd))

	var mask unix.Sigset_t
	fd, _, _ = syscall.RawSyscall(unix.SYS_SIGNALFD, ^uintptr(0), uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Sizeof(mask)))
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_SIGNALFD4, ^uintptr(0), uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Sizeof(mask)))
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_TIMERFD_CREATE, uintptr(unix.CLOCK_MONOTONIC), uintptr(unix.TFD_CLOEXEC), 0)
	closeIfValid(int(fd))
	return nil
}

func closeIfValid(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}
