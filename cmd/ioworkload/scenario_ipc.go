package main

import (
	"fmt"
	"syscall"

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
