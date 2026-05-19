package main

import (
	"fmt"
	"syscall"
)

func socketBasic() error {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("close socket fd: %w", err)
	}
	return nil
}

func socketpairBasic() error {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("socketpair: %w", err)
	}
	if err := syscall.Close(fds[0]); err != nil {
		return fmt.Errorf("close socketpair fd0: %w", err)
	}
	if err := syscall.Close(fds[1]); err != nil {
		return fmt.Errorf("close socketpair fd1: %w", err)
	}
	return nil
}
