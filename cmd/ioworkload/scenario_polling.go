package main

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func pollingEpoll() error {
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("epoll_create1: %w", err)
	}
	defer syscall.Close(epfd) //nolint:errcheck

	var pipefd [2]int
	if err := syscall.Pipe(pipefd[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(pipefd[0]) //nolint:errcheck
	defer syscall.Close(pipefd[1]) //nolint:errcheck

	event := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(pipefd[0])}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, pipefd[0], &event); err != nil {
		return fmt.Errorf("epoll_ctl add: %w", err)
	}

	pwait2Supported := true
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := waitAndDrain(epfd, pipefd, callEpollWait); err != nil {
			return err
		}
		if err := waitAndDrain(epfd, pipefd, callEpollPwait); err != nil {
			return err
		}
		if pwait2Supported {
			if err := waitAndDrain(epfd, pipefd, callEpollPwait2); err != nil {
				if !isUnsupportedEpollPwait2Err(err) {
					return err
				}
				if drainErr := drainWakeByte(pipefd[0]); drainErr != nil {
					return drainErr
				}
				pwait2Supported = false
			}
		}
		if err := waitAndDrainReadiness(pipefd, callPoll); err != nil {
			return err
		}
		if err := waitAndDrainReadiness(pipefd, callPpoll); err != nil {
			return err
		}
		if err := waitAndDrainReadiness(pipefd, callSelect); err != nil {
			return err
		}
		if err := waitAndDrainReadiness(pipefd, callPselect6); err != nil {
			return err
		}
		time.Sleep(2 * time.Millisecond)
	}

	return nil
}

type readinessWaitFn func(pipefd [2]int) (int, error)

func waitAndDrainReadiness(pipefd [2]int, waitFn readinessWaitFn) error {
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write wake byte: %w", err)
	}
	ready, err := waitFn(pipefd)
	if err != nil {
		return err
	}
	if ready < 1 {
		return fmt.Errorf("polling wait returned %d ready events", ready)
	}
	return drainWakeByte(pipefd[0])
}

func waitAndDrain(epfd int, pipefd [2]int, waitFn func(int, []unix.EpollEvent) (int, error)) error {
	if _, err := syscall.Write(pipefd[1], []byte{1}); err != nil {
		return fmt.Errorf("write wake byte: %w", err)
	}
	events := make([]unix.EpollEvent, 4)
	ready, err := waitFn(epfd, events)
	if err != nil {
		return err
	}
	if ready < 1 {
		return fmt.Errorf("epoll wait returned %d ready events", ready)
	}
	return drainWakeByte(pipefd[0])
}

func drainWakeByte(readFD int) error {
	var buf [1]byte
	if _, err := syscall.Read(readFD, buf[:]); err != nil {
		return fmt.Errorf("drain wake byte: %w", err)
	}
	return nil
}

func callEpollWait(epfd int, events []unix.EpollEvent) (int, error) {
	eventPtr := unsafe.Pointer(&events[0])
	r1, _, errno := syscall.RawSyscall6(
		syscall.SYS_EPOLL_WAIT,
		uintptr(epfd),
		uintptr(eventPtr),
		uintptr(len(events)),
		uintptr(100),
		0,
		0,
	)
	runtime.KeepAlive(events)
	if errno != 0 {
		return 0, fmt.Errorf("epoll_wait: %w", errno)
	}
	return int(r1), nil
}

func callEpollPwait(epfd int, events []unix.EpollEvent) (int, error) {
	eventPtr := unsafe.Pointer(&events[0])
	r1, _, errno := syscall.RawSyscall6(
		syscall.SYS_EPOLL_PWAIT,
		uintptr(epfd),
		uintptr(eventPtr),
		uintptr(len(events)),
		uintptr(100),
		0,
		0,
	)
	runtime.KeepAlive(events)
	if errno != 0 {
		return 0, fmt.Errorf("epoll_pwait: %w", errno)
	}
	return int(r1), nil
}

func callEpollPwait2(epfd int, events []unix.EpollEvent) (int, error) {
	eventPtr := unsafe.Pointer(&events[0])
	timeout := unix.Timespec{Sec: 0, Nsec: 100 * 1_000_000}
	r1, _, errno := syscall.RawSyscall6(
		unix.SYS_EPOLL_PWAIT2,
		uintptr(epfd),
		uintptr(eventPtr),
		uintptr(len(events)),
		uintptr(unsafe.Pointer(&timeout)),
		0,
		0,
	)
	runtime.KeepAlive(events)
	runtime.KeepAlive(timeout)
	if errno != 0 {
		return 0, fmt.Errorf("epoll_pwait2: %w", errno)
	}
	return int(r1), nil
}

func callPoll(pipefd [2]int) (int, error) {
	fds := []unix.PollFd{{Fd: int32(pipefd[0]), Events: unix.POLLIN}}
	r1, _, errno := syscall.RawSyscall(
		syscall.SYS_POLL,
		uintptr(unsafe.Pointer(&fds[0])),
		uintptr(len(fds)),
		uintptr(100),
	)
	runtime.KeepAlive(fds)
	if errno != 0 {
		return 0, fmt.Errorf("poll: %w", errno)
	}
	return int(r1), nil
}

func callPpoll(pipefd [2]int) (int, error) {
	fds := []unix.PollFd{{Fd: int32(pipefd[0]), Events: unix.POLLIN}}
	timeout := unix.Timespec{Sec: 0, Nsec: 100 * 1_000_000}
	r1, _, errno := syscall.RawSyscall6(
		unix.SYS_PPOLL,
		uintptr(unsafe.Pointer(&fds[0])),
		uintptr(len(fds)),
		uintptr(unsafe.Pointer(&timeout)),
		0,
		0,
		0,
	)
	runtime.KeepAlive(fds)
	runtime.KeepAlive(timeout)
	if errno != 0 {
		return 0, fmt.Errorf("ppoll: %w", errno)
	}
	return int(r1), nil
}

// fdSetBits is the maximum number of file descriptors an fdSet can represent.
// This matches the Linux FD_SETSIZE constant (1024).
const fdSetBits = 16 * 64

// errFDOutOfRange is returned when a file descriptor is too large for the
// fixed-size fd_set used by select/pselect6 (>= 1024).
var errFDOutOfRange = fmt.Errorf("fd >= %d: too large for select fd_set", fdSetBits)

type fdSet [16]uint64

// set marks fd in the bitset. It returns errFDOutOfRange when fd falls
// outside the fixed 1024-bit array, preventing an index-out-of-bounds panic.
func (s *fdSet) set(fd int) error {
	if fd < 0 || fd >= fdSetBits {
		return errFDOutOfRange
	}
	idx := fd / 64
	bit := uint(fd % 64)
	s[idx] |= 1 << bit
	return nil
}

func callSelect(pipefd [2]int) (int, error) {
	var readSet fdSet
	if err := readSet.set(pipefd[0]); err != nil {
		return 0, fmt.Errorf("select: %w", err)
	}
	timeout := syscall.Timeval{Sec: 0, Usec: 100000}
	r1, _, errno := syscall.RawSyscall6(
		syscall.SYS_SELECT,
		uintptr(pipefd[0]+1),
		uintptr(unsafe.Pointer(&readSet)),
		0,
		0,
		uintptr(unsafe.Pointer(&timeout)),
		0,
	)
	runtime.KeepAlive(readSet)
	runtime.KeepAlive(timeout)
	if errno != 0 {
		return 0, fmt.Errorf("select: %w", errno)
	}
	return int(r1), nil
}

func callPselect6(pipefd [2]int) (int, error) {
	var readSet fdSet
	if err := readSet.set(pipefd[0]); err != nil {
		return 0, fmt.Errorf("pselect6: %w", err)
	}
	timeout := unix.Timespec{Sec: 0, Nsec: 100 * 1_000_000}
	r1, _, errno := syscall.RawSyscall6(
		unix.SYS_PSELECT6,
		uintptr(pipefd[0]+1),
		uintptr(unsafe.Pointer(&readSet)),
		0,
		0,
		uintptr(unsafe.Pointer(&timeout)),
		0,
	)
	runtime.KeepAlive(readSet)
	runtime.KeepAlive(timeout)
	if errno != 0 {
		return 0, fmt.Errorf("pselect6: %w", errno)
	}
	return int(r1), nil
}

func isUnsupportedEpollPwait2Err(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == syscall.ENOSYS || errno == syscall.ENOTSUP
}
