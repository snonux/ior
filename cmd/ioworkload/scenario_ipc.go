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
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write pipe: %w", err)
	}
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
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write pipe2: %w", err)
	}
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
	flags := uintptr(unix.EFD_SEMAPHORE | unix.EFD_CLOEXEC | unix.EFD_NONBLOCK)
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

// kernelSigsetSize is the kernel's sigset size (_NSIG / 8 on Linux), which
// the legacy signalfd syscall expects as its size argument.
const kernelSigsetSize = uintptr(8)

// fdFromAirEventfdUsers exercises the syscalls that create descriptors "from
// thin air" (no pathname): memfd_create, memfd_secret, userfaultfd, the
// signalfd pair and timerfd. The groups run in this fixed order and every
// descriptor is closed right after use.
func fdFromAirEventfdUsers() error {
	if err := createAnonMemoryFds(); err != nil {
		return err
	}
	exerciseSignalfds()
	exerciseTimerfd()
	return nil
}

// createAnonMemoryFds issues memfd_create, memfd_secret and userfaultfd,
// closing whatever descriptors they return. Their failures are tolerated
// (e.g. memfd_secret is often disabled); only the traced calls matter.
func createAnonMemoryFds() error {
	memfdName, err := syscall.BytePtrFromString("ior-memfd")
	if err != nil {
		return fmt.Errorf("memfd name: %w", err)
	}
	memfdFlags := unix.MFD_CLOEXEC | unix.MFD_ALLOW_SEALING
	fd, _, _ := syscall.RawSyscall(unix.SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(memfdName)), uintptr(memfdFlags), 0)
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_MEMFD_SECRET, uintptr(unix.O_CLOEXEC), 0, 0)
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_USERFAULTFD, uintptr(unix.O_CLOEXEC), 0, 0)
	closeIfValid(int(fd))
	return nil
}

// exerciseSignalfds creates descriptors with signalfd and signalfd4, then
// updates an existing signalfd through both syscalls.
func exerciseSignalfds() {
	var mask unix.Sigset_t
	fd, _, _ := syscall.RawSyscall(unix.SYS_SIGNALFD, ^uintptr(0), uintptr(unsafe.Pointer(&mask)), kernelSigsetSize)
	closeIfValid(int(fd))

	fd, _, _ = syscall.RawSyscall(unix.SYS_SIGNALFD4, ^uintptr(0), uintptr(unsafe.Pointer(&mask)), uintptr(unsafe.Sizeof(mask)))
	closeIfValid(int(fd))

	// signalfd4 updates the signal mask of an existing signalfd when fd is
	// nonnegative. Its flags argument applies only while creating a descriptor;
	// issue both forms so tracing can prove the update keeps the creation flags.
	signalFd, err := unix.Signalfd(-1, &mask, unix.SFD_CLOEXEC)
	if err == nil {
		_, _, _ = syscall.RawSyscall(
			unix.SYS_SIGNALFD,
			uintptr(signalFd),
			uintptr(unsafe.Pointer(&mask)),
			kernelSigsetSize,
		)
		_, _ = unix.Signalfd(signalFd, &mask, unix.SFD_NONBLOCK)
		closeIfValid(signalFd)
	}
}

// exerciseTimerfd creates a timerfd and, while it is still open, arms it with
// timerfd_settime and reads it back with timerfd_gettime. Both of those
// syscalls take the timerfd as arg0 (kind=fd@arg0), so tracing them
// exercises the fd_event capture path fixed in commit 6ac9fa4: the enter
// handlers must resolve arg0 to the registered "timerfd:" descriptor
// rather than emitting a null event. The fd is closed only after both
// operations so the descriptor stays registered for the duration.
func exerciseTimerfd() {
	fd, _, _ := syscall.RawSyscall(unix.SYS_TIMERFD_CREATE, uintptr(unix.CLOCK_MONOTONIC), uintptr(unix.TFD_CLOEXEC), 0)
	if int(fd) >= 0 {
		armAndReadTimerfd(int(fd))
		closeIfValid(int(fd))
	}
}

func fanotifyFlags() error {
	fd, _, errno := syscall.RawSyscall(
		unix.SYS_FANOTIFY_INIT,
		uintptr(unix.FAN_CLOEXEC|unix.FAN_NONBLOCK),
		uintptr(unix.O_RDONLY|unix.O_LARGEFILE),
		0,
	)
	if errno == 0 {
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
	_, _, _ = syscall.RawSyscall6(unix.SYS_TIMERFD_SETTIME, uintptr(fd), 0,
		uintptr(unsafe.Pointer(&newValue)), 0, 0, 0)

	var curValue unix.ItimerSpec
	_, _, _ = syscall.RawSyscall(unix.SYS_TIMERFD_GETTIME, uintptr(fd),
		uintptr(unsafe.Pointer(&curValue)), 0)
}

func closeIfValid(fd int) {
	if fd >= 0 {
		syscall.Close(fd)
	}
}
