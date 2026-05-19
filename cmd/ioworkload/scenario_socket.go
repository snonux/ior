package main

import (
	"fmt"
	"os"
	"path/filepath"
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

func socketAcceptLifecycle() error {
	dir, err := os.MkdirTemp("", "ioworkload-socket-accept-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	socketPath := filepath.Join(dir, "accept.sock")

	listenerFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("listener socket: %w", err)
	}
	defer syscall.Close(listenerFD) //nolint:errcheck

	if err := syscall.Bind(listenerFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := syscall.Listen(listenerFD, 1); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	clientFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("client socket: %w", err)
	}
	defer syscall.Close(clientFD) //nolint:errcheck

	if err := syscall.Connect(clientFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	acceptedFD, _, err := syscall.Accept4(listenerFD, 0)
	if err != nil {
		return fmt.Errorf("accept4: %w", err)
	}
	defer syscall.Close(acceptedFD) //nolint:errcheck

	if err := syscall.Shutdown(acceptedFD, syscall.SHUT_RDWR); err != nil {
		return fmt.Errorf("shutdown accepted fd: %w", err)
	}
	return nil
}

func socketAcceptLifecyclePlain() error {
	dir, err := os.MkdirTemp("", "ioworkload-socket-accept-plain-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	socketPath := filepath.Join(dir, "accept.sock")

	listenerFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("listener socket: %w", err)
	}
	defer syscall.Close(listenerFD) //nolint:errcheck

	if err := syscall.Bind(listenerFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := syscall.Listen(listenerFD, 1); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	clientFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("client socket: %w", err)
	}
	defer syscall.Close(clientFD) //nolint:errcheck

	if err := syscall.Connect(clientFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	acceptedFDRaw, _, errno := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(listenerFD), 0, 0)
	if errno != 0 {
		return fmt.Errorf("accept: %w", errno)
	}
	acceptedFD := int(acceptedFDRaw)
	defer syscall.Close(acceptedFD) //nolint:errcheck

	if err := syscall.Shutdown(acceptedFD, syscall.SHUT_RDWR); err != nil {
		return fmt.Errorf("shutdown accepted fd: %w", err)
	}
	return nil
}

func socketIntrospection() error {
	dir, cleanup, err := makeTempDir("socket-introspection")
	if err != nil {
		return err
	}
	defer cleanup()

	socketPath := filepath.Join(dir, "introspection.sock")

	listenerFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("listener socket: %w", err)
	}
	defer syscall.Close(listenerFD) //nolint:errcheck

	if err := syscall.Bind(listenerFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := syscall.Listen(listenerFD, 1); err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	clientFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return fmt.Errorf("client socket: %w", err)
	}
	defer syscall.Close(clientFD) //nolint:errcheck

	if err := syscall.Connect(clientFD, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	acceptedFD, _, err := syscall.Accept4(listenerFD, 0)
	if err != nil {
		return fmt.Errorf("accept4: %w", err)
	}
	defer syscall.Close(acceptedFD) //nolint:errcheck

	if _, err := syscall.Getsockname(acceptedFD); err != nil {
		return fmt.Errorf("getsockname: %w", err)
	}
	if _, err := syscall.Getpeername(acceptedFD); err != nil {
		return fmt.Errorf("getpeername: %w", err)
	}
	if err := syscall.SetsockoptInt(acceptedFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 32768); err != nil {
		return fmt.Errorf("setsockopt: %w", err)
	}
	if _, err := syscall.GetsockoptInt(acceptedFD, syscall.SOL_SOCKET, syscall.SO_RCVBUF); err != nil {
		return fmt.Errorf("getsockopt: %w", err)
	}

	return nil
}
