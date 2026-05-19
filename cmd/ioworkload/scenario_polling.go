package main

import (
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

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := waitAndDrain(epfd, pipefd, callEpollWait); err != nil {
			return err
		}
		if err := waitAndDrain(epfd, pipefd, callEpollPwait); err != nil {
			return err
		}
		if err := waitAndDrain(epfd, pipefd, callEpollPwait2); err != nil {
			return err
		}
	}

	return nil
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
	var buf [1]byte
	if _, err := syscall.Read(pipefd[0], buf[:]); err != nil {
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
