package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

const sysCloseRange = 436

// closeBasic opens multiple files and closes them.
func closeBasic() error {
	dir, cleanup, err := makeTempDir("close-basic")
	if err != nil {
		return err
	}
	defer cleanup()

	var fds []int
	for i := range 3 {
		path := filepath.Join(dir, fmt.Sprintf("closefile-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("open %d: %w", i, err)
		}
		fds = append(fds, fd)
	}
	for _, fd := range fds {
		if err := syscall.Close(fd); err != nil {
			return fmt.Errorf("close fd %d: %w", fd, err)
		}
	}
	return nil
}

// closeRange opens multiple files and closes a range of them via close_range(2).
func closeRange() error {
	dir, cleanup, err := makeTempDir("close-range")
	if err != nil {
		return err
	}
	defer cleanup()

	var fds []int
	for i := range 3 {
		path := filepath.Join(dir, fmt.Sprintf("closerangefile-%d.txt", i))
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
		if err != nil {
			return fmt.Errorf("open %d: %w", i, err)
		}
		fds = append(fds, fd)
	}

	if fds[2]-fds[0] != 2 {
		return fmt.Errorf("fds not contiguous: %v", fds)
	}

	first := uintptr(fds[0])
	last := uintptr(fds[len(fds)-1])
	_, _, errno := syscall.Syscall(sysCloseRange, first, last, 0)
	if errno != 0 {
		return fmt.Errorf("close_range: %w", errno)
	}
	return nil
}

// closeInvalidFd attempts to close a very high fd number that is not open.
// The close fails with EBADF, but ior should capture the enter_close tracepoint
// because arguments are read on syscall entry before the kernel returns an error.
func closeInvalidFd() error {
	err := syscall.Close(99999)
	if err == nil {
		return fmt.Errorf("expected close of invalid fd to fail")
	}
	return nil
}

// closeDoubleClose opens a file, closes it normally, then closes the same fd again.
// The second close fails with EBADF, but ior should capture both enter_close
// tracepoints because arguments are read on syscall entry.
func closeDoubleClose() error {
	dir, cleanup, err := makeTempDir("close-double-close")
	if err != nil {
		return err
	}
	defer cleanup()

	path := filepath.Join(dir, "doubleclosefile.txt")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if err := syscall.Close(fd); err != nil {
		return fmt.Errorf("first close: %w", err)
	}

	err = syscall.Close(fd)
	if err == nil {
		return fmt.Errorf("expected second close of same fd to fail")
	}
	return nil
}

// closeRangeEmpty calls close_range(2) with a range of very high fd numbers
// (9000–9999) where no fds are open. The syscall succeeds (empty range is valid),
// and ior should capture the enter_close_range tracepoint.
func closeRangeEmpty() error {
	_, _, errno := syscall.Syscall(sysCloseRange, 9000, 9999, 0)
	if errno != 0 {
		return fmt.Errorf("close_range: %w", errno)
	}
	return nil
}
