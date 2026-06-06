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

	// Create a timerfd and, while it is still open, arm it with
	// timerfd_settime and read it back with timerfd_gettime. Both of those
	// syscalls take the timerfd as arg0 (kind=fd@arg0), so tracing them
	// exercises the fd_event capture path fixed in commit 6ac9fa4: the enter
	// handlers must resolve arg0 to the registered "timerfd:" descriptor
	// rather than emitting a null event. We close the fd only after both
	// operations so the descriptor stays registered for the duration.
	fd, _, _ = syscall.RawSyscall(unix.SYS_TIMERFD_CREATE, uintptr(unix.CLOCK_MONOTONIC), uintptr(unix.TFD_CLOEXEC), 0)
	if int(fd) >= 0 {
		armAndReadTimerfd(int(fd))
		closeIfValid(int(fd))
	}
	return nil
}

// armAndReadTimerfd arms the given timerfd via timerfd_settime and reads its
// current setting back via timerfd_gettime. The timer is set to a one-second
// relative expiration: far enough in the future that it never actually fires
// during the scenario, so its only observable effect is that the two syscalls
// are issued against an already-open timerfd descriptor.
func armAndReadTimerfd(fd int) {
	newValue := unix.ItimerSpec{
		Value: unix.Timespec{Sec: 1, Nsec: 0},
	}
	syscall.RawSyscall6(unix.SYS_TIMERFD_SETTIME, uintptr(fd), 0,
		uintptr(unsafe.Pointer(&newValue)), 0, 0, 0)

	var curValue unix.ItimerSpec
	syscall.RawSyscall(unix.SYS_TIMERFD_GETTIME, uintptr(fd),
		uintptr(unsafe.Pointer(&curValue)), 0)
}

func closeIfValid(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}
